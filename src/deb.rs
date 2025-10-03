use {
    crate::{
        control::MutableControlStanza,
        deployfs::{DeploymentFile, DeploymentTempFile},
        hash::HashingReader,
        parse_size,
        tar::{TarEntry, TarLink, TarReader},
    },
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    core::task::{self, Context, Poll},
    futures_lite::{io::BufReader, AsyncRead, AsyncReadExt, Stream, StreamExt},
    std::{
        io::{self, Result},
        ops::Range,
        path::PathBuf,
        pin::Pin,
        sync::{Arc, Mutex},
        time::{Duration, UNIX_EPOCH},
    },
};

macro_rules! ready_opt {
    ($e:expr $(,)?) => {
        match $e {
            task::Poll::Ready(Ok(t)) => t,
            task::Poll::Ready(Err(err)) => return task::Poll::Ready(Some(Err(err))),
            task::Poll::Pending => return task::Poll::Pending,
        }
    };
}
macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            task::Poll::Ready(Ok(t)) => t,
            task::Poll::Ready(Err(err)) => return task::Poll::Ready(Err(err)),
            task::Poll::Pending => return task::Poll::Pending,
        }
    };
}

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const AR_MAGIC_SIZE: u64 = AR_MAGIC.len() as u64;
const AR_HEADER_SIZE: u64 = 60;

enum State {
    Header,
    Content,
}

#[derive(PartialEq)]
enum EntryKind {
    Control,
    Data,
}

struct DebReaderInner {
    // Current state
    state: State,
    // Content padding
    padding: u8,
    // Size of the current entry
    size: u64,
    // Total bytes read for the current entry
    read: u64,
    // Total bytes read for the whole file
    total: u64,
    // Deb entry header
    hdr: [u8; AR_HEADER_SIZE as usize],
    // Source of the data
    source: Pin<Box<dyn AsyncRead + Send + 'static>>,
}

impl Unpin for DebReaderInner {}

impl DebReaderInner {
    async fn new(mut r: Pin<Box<dyn AsyncRead + Send + 'static>>) -> std::io::Result<Self> {
        let mut hdr = [0u8; AR_MAGIC_SIZE as usize];
        r.read_exact(&mut hdr).await?;
        if &hdr != AR_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid deb header",
            ));
        }
        Ok(Self {
            state: State::Header,
            size: AR_HEADER_SIZE,
            padding: 0,
            read: 0,
            total: AR_MAGIC_SIZE,
            hdr: [0u8; AR_HEADER_SIZE as usize],
            source: r,
        })
    }
    fn reset_for_next_chunk(&mut self, state: State, size: u64) {
        self.state = state;
        self.size = size;
        self.padding = (size & 1) as u8;
        self.read = 0;
    }
    fn size_with_padding(&self) -> u64 {
        self.size + (self.padding as u64)
    }
    fn poll_read_header(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<usize>> {
        let this = self.get_mut();
        let remain = (this.size + this.padding as u64) - this.read;
        if remain == 0 {
            return Poll::Ready(Ok(0));
        }
        let size = this.size as usize;
        let read_so_far = this.read as usize;
        let padding = this.padding;
        // Borrow disjoint fields to satisfy the borrow checker
        let (hdr, source) = (&mut this.hdr, &mut this.source);
        match ready!(source.as_mut().poll_read(ctx, &mut hdr[read_so_far..size])) {
            0 => Poll::Ready(Ok(0)),
            n => {
                this.read += n as u64;
                this.total += n as u64;
                Poll::Ready(Ok(if (n as u64) < remain {
                    n
                } else {
                    n - padding as usize
                }))
            }
        }
    }
}

impl AsyncRead for DebReaderInner {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let remain = (this.size + this.padding as u64) - this.read;
        if remain == 0 {
            return Poll::Ready(Ok(0));
        };
        let size = std::cmp::min(remain, buf.len() as u64);
        match ready!(this
            .source
            .as_mut()
            .poll_read(ctx, &mut buf[0..size as usize]))
        {
            0 => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading package entry",
            ))),
            n => {
                this.read += n as u64;
                this.total += n as u64;
                Poll::Ready(Ok(if (n as u64) < remain {
                    n
                } else {
                    n - this.padding as usize
                }))
            }
        }
    }
}

impl Stream for DebReaderInner {
    type Item = Result<(EntryKind, Range<usize>)>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.state {
                // skip the rest of the unread body if necessary
                State::Content => {
                    if self.read < self.size_with_padding() {
                        let mut buf = [0u8; 8192];
                        while self.read < self.size_with_padding() {
                            if ready_opt!(self.as_mut().poll_read(ctx, &mut buf[..])) == 0 {
                                return Poll::Ready(Some(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF while reading entry content",
                                ))));
                            }
                        }
                    }
                    self.reset_for_next_chunk(State::Header, AR_HEADER_SIZE);
                }
                // read the header
                State::Header => {
                    while self.read < AR_HEADER_SIZE {
                        match ready_opt!(self.as_mut().poll_read_header(ctx)) {
                            0 if self.read == 0 => return Poll::Ready(None),
                            0 => {
                                return Poll::Ready(Some(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF while reading entry header",
                                ))))
                            }
                            _ => continue,
                        }
                    }
                    let size = parse_size(&self.hdr[48..58])?;
                    self.reset_for_next_chunk(State::Content, size);
                    let name = std::str::from_utf8(&self.hdr[0..16]).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid header: {:?}", &self.hdr),
                        )
                    })?;
                    let name = name.find(' ').map(|n| &name[..n]).ok_or(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("error parsing deb entry name {}", name),
                    ))?;
                    if name == "debian-binary" {
                        // a minor optimization to avoid allocating buffer when skipping version
                        if size <= AR_HEADER_SIZE {
                            match ready_opt!(self.as_mut().poll_read_header(ctx)) {
                                0 => {
                                    return Poll::Ready(Some(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "unexpected EOF while reading entry content",
                                    ))))
                                }
                                n if (n as u64) == size => {
                                    self.reset_for_next_chunk(State::Header, AR_HEADER_SIZE);
                                }
                                _ => {} // skip as content
                            }
                        }
                        continue;
                    } else if name.starts_with("control.tar") {
                        let ext_range = "control.tar".len()..name.len();
                        return Poll::Ready(Some(Ok((EntryKind::Control, ext_range))));
                    } else if name.starts_with("data.tar") {
                        let ext_range = "data.tar".len()..name.len();
                        return Poll::Ready(Some(Ok((EntryKind::Data, ext_range))));
                    } else {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected debian package entry {}", name),
                        ))));
                    }
                }
            }
        }
    }
}

/// Asynchronous debian package reader
/// # Example
///
/// ```
/// let mut deb = Deb::new(input).await?;
/// while let Some(entry) = deb.next().await {
///     match entry? {
///         DebEntry::Control(f) => {
///             f.entries()?.map(|file| -> Result<()> Ok(process_control_file(file?)?))
///                 .try_collect()
///                 .await?;
///         }
///         DebEntry::Data(f) => {
///             f.entries()?.map(|file| -> Result<()> Ok(process_data_file(file?)?))
///                 .try_collect()
///                 .await?;
///         }
///         DebEntry::Version(_) => { }
///     }
/// }
/// ```
pub struct DebReader {
    inner: Arc<Mutex<DebReaderInner>>,
}

struct DebEntryReaderInner {
    inner: Arc<Mutex<DebReaderInner>>,
}

impl AsyncRead for DebEntryReaderInner {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut reader = self
            .inner
            .lock()
            .map_err(|err| io::Error::other(format!("unexpected mutex error {}", err)))?;
        Pin::new(&mut *reader).poll_read(ctx, buf)
    }
}

impl DebReader {
    /// Creates a new asynchronous Debian archive reader from the given reader `R`.
    ///
    /// # Arguments
    ///
    /// * `reader` - The input source that implements the asynchronous read trait and provides the Debian archive data.
    ///
    /// # Returns
    ///
    /// * Result<Self> - An instance of `Deb` wrapped in a `Result`, containing
    ///     - `Ok`: A successfully initialized reader
    ///     - `Err`: An error if the reader initialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use deb_repo::deb::Deb;
    /// use anyhow::Result;
    ///
    /// async fn example() -> Result<()> {
    ///     let reader = async_std::fs::File::open("path/to/debian/archive.deb").await?;
    ///     let deb = Deb::new(reader).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(r: Pin<Box<dyn AsyncRead + Send + 'static>>) -> Result<Self> {
        Ok(DebReader {
            inner: Arc::new(Mutex::new(DebReaderInner::new(r).await?)),
        })
    }
    fn entry_reader_for_ext(&self, ext: &str) -> TarReader<Pin<Box<dyn AsyncRead + Send>>> {
        let r = DebEntryReaderInner {
            inner: Arc::clone(&self.inner),
        };
        match ext {
            ".xz" => TarReader::new(Box::pin(XzDecoder::new(BufReader::new(r)))),
            ".gz" => TarReader::new(Box::pin(GzipDecoder::new(BufReader::new(r)))),
            ".bz2" => TarReader::new(Box::pin(BzDecoder::new(BufReader::new(r)))),
            ".lzma" => TarReader::new(Box::pin(LzmaDecoder::new(BufReader::new(r)))),
            ".zstd" | ".zst" => TarReader::new(Box::pin(ZstdDecoder::new(BufReader::new(r)))),
            _ => TarReader::new(Box::pin(r)),
        }
    }
    pub async fn extract_to<FS: crate::DeploymentFileSystem + ?Sized>(
        mut self,
        fs: &FS,
    ) -> Result<MutableControlStanza> {
        let mut installed_files: Vec<String> = vec![];
        let mut ctrl: MutableControlStanza;
        let mut ctrl_files: Vec<(String, FS::TempFile)> = vec![];
        let mut ctrl_files_list = String::new();
        let mut conf_files: Vec<(String, Option<String>)> = vec![];
        let multiarch: Option<&str>;
        let pkg: &str;
        let ctrl_base = PathBuf::from("./var/lib/dpkg/info");
        fs.create_dir_all(&ctrl_base, 0, 0, 0o755).await?;
        {
            let mut control_tarball = self
                .next()
                .await
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "no control.tar entry".to_owned(),
                    )
                })?
                .and_then(|f| match f {
                    DebEntry::Control(f) => Ok(f),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected entry",
                    )),
                })?;
            let mut maybe_ctrl: Option<MutableControlStanza> = None;
            while let Some(entry) = control_tarball.next().await {
                let entry = entry?;
                match entry {
                    TarEntry::File(mut file) => {
                        let mtime = UNIX_EPOCH + Duration::from_secs(file.mtime().into());
                        let uid = file.uid();
                        let gid = file.gid();
                        let mode = file.mode();
                        let size = file.size();
                        let filename = file.path().to_string();
                        if filename.eq("./control") {
                            let mut buf = String::new();
                            file.read_to_string(&mut buf).await?;
                            maybe_ctrl.replace(MutableControlStanza::parse(buf).map_err(
                                |err| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("error parsing control file: {}", err),
                                    )
                                },
                            )?);
                            continue;
                        } else if filename.eq("./conffiles") {
                            let mut buf = String::with_capacity(file.size() as usize);
                            file.read_to_string(&mut buf).await?;
                            conf_files.extend(buf.lines().map(|l| (l.to_owned(), None)));
                            let file = fs
                                .create_temp_file(
                                    buf.as_bytes(),
                                    uid,
                                    gid,
                                    mode,
                                    Some(mtime),
                                    Some(size as usize),
                                )
                                .await?;
                            ctrl_files.push((filename, file));
                        } else {
                            let file = fs
                                .create_temp_file(
                                    file,
                                    uid,
                                    gid,
                                    mode,
                                    Some(mtime),
                                    Some(size as usize),
                                )
                                .await?;
                            ctrl_files.push((filename, file));
                        }
                    }
                    TarEntry::Directory(dir) if dir.path() == "./" => {}
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid entry in control.tar",
                        ));
                    }
                }
            }
            ctrl = maybe_ctrl
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no control file"))?;
            multiarch = ctrl.field("Multi-Arch").and_then(|v| {
                if v.eq_ignore_ascii_case("same") {
                    ctrl.field("Architecture")
                } else {
                    None
                }
            });
            pkg = ctrl.field("Package").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no Package field in package description",
                )
            })?;
            for (name, file) in ctrl_files.into_iter() {
                ctrl_files_list.push_str("\n ");
                ctrl_files_list.push_str(&name);
                let mut target_name = std::ffi::OsString::from(pkg);
                if let Some(arch) = multiarch {
                    target_name.push(":");
                    target_name.push(arch);
                }
                target_name.push(".");
                target_name.push(name.strip_prefix("./").unwrap_or(&name));
                file.persist(ctrl_base.join(target_name)).await?;
            }
        }
        {
            let mut data_tarball = self
                .next()
                .await
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "no data.tar entry".to_owned())
                })?
                .and_then(|f| match f {
                    DebEntry::Data(f) => Ok(f),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected entry",
                    )),
                })?;
            while let Some(entry) = data_tarball.next().await {
                let entry = entry?;
                tracing::debug!("{} {}", pkg, entry.path());
                // tracing::debug!("{} {:?} {:#?}", pkg, path.as_os_str(), entry.header());
                installed_files.push(entry.path().to_owned());
                let mut links: Vec<TarLink> = Vec::new();
                match entry {
                    TarEntry::Directory(dir) => {
                        tracing::debug!("creating directory {}", dir.path());
                        fs.create_dir_all(dir.path(), dir.uid(), dir.gid(), dir.mode())
                            .await?;
                    }
                    TarEntry::File(mut file) => {
                        let mtime = UNIX_EPOCH + Duration::from_secs(file.mtime() as u64);
                        let size = file.size() as usize;
                        let path = PathBuf::from(file.path());
                        let uid = file.uid();
                        let gid = file.gid();
                        let mode = file.mode();
                        tracing::debug!("extracting {}", file.path());
                        match conf_files.iter_mut().find(|(name, _)| name == file.path()) {
                            None => fs
                                .create_file(
                                    &mut file,
                                    &path,
                                    uid,
                                    gid,
                                    mode,
                                    Some(mtime),
                                    Some(size),
                                )
                                .await
                                .map_err(|err| {
                                    io::Error::other(format!(
                                        "error creating file {}: {}",
                                        path.display(),
                                        err
                                    ))
                                })?,
                            Some((_, sum)) => {
                                let mut hasher = HashingReader::<md5::Md5, _>::new(file);
                                let file = fs
                                    .create_file(
                                        &mut hasher,
                                        &path,
                                        uid,
                                        gid,
                                        mode,
                                        Some(mtime),
                                        Some(size),
                                    )
                                    .await
                                    .map_err(|err| {
                                        io::Error::other(format!(
                                            "error creating config file {} {}: {}",
                                            path.display(),
                                            mode,
                                            err
                                        ))
                                    })?;
                                let hash = hasher.into_hash();
                                sum.replace(hash.into());
                                file
                            }
                        }
                        .persist()
                        .await?;
                    }
                    TarEntry::Symlink(link) => {
                        let mtime = UNIX_EPOCH + Duration::from_secs(link.mtime() as u64);
                        let uid = link.uid();
                        let gid = link.gid();
                        fs.symlink(link.link(), link.path(), uid, gid, Some(mtime))
                            .await?;
                    }
                    TarEntry::Link(link) => {
                        links.push(link);
                    }
                }
                for link in links.drain(..) {
                    fs.hardlink(link.link(), link.path()).await?;
                }
            }
        }
        {
            let mut target_name = std::ffi::OsString::from(pkg);
            if let Some(arch) = multiarch {
                target_name.push(":");
                target_name.push(arch);
            }
            target_name.push(".list");
            let mut buf =
                String::with_capacity(installed_files.iter().fold(0, |a, s| a + 1 + s.len()));
            for i in installed_files {
                buf.push_str(&i);
                buf.push('\n');
            }
            let target_name = ctrl_base.join(target_name);
            fs.create_file(
                buf.as_bytes(),
                &target_name,
                0,
                0,
                0o644,
                None,
                Some(buf.len()),
            )
            .await?
            .persist()
            .await?;
        }
        if !conf_files.is_empty() {
            let mut buf = String::new();
            for (name, hash) in conf_files.into_iter() {
                if let Some(hash) = hash {
                    buf.push_str("\n ");
                    buf.push_str(&name);
                    buf.push(' ');
                    buf.push_str(&hash);
                }
            }
            if !buf.is_empty() {
                ctrl.set("Conffiles", buf);
            }
        }
        if !ctrl_files_list.is_empty() {
            ctrl.set("Controlfiles", ctrl_files_list);
        }
        Ok(ctrl)
    }
}

impl Stream for DebReader {
    type Item = Result<DebEntry>;
    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut reader = self
            .inner
            .lock()
            .map_err(|err| io::Error::other(format!("unexpected mutex error {}", err)))?;
        match task::ready!(Pin::new(&mut *reader).poll_next(ctx)) {
            None => Poll::Ready(None),
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            Some(Ok((entry_kind, ext_range))) => Poll::Ready(Some(match entry_kind {
                EntryKind::Control => Ok(DebEntry::Control(self.entry_reader_for_ext(unsafe {
                    std::str::from_utf8_unchecked(&reader.hdr[ext_range])
                }))),
                EntryKind::Data => Ok(DebEntry::Data(self.entry_reader_for_ext(unsafe {
                    std::str::from_utf8_unchecked(&reader.hdr[ext_range])
                }))),
            })),
        }
    }
}

pub enum DebEntry {
    Control(TarReader<Pin<Box<dyn AsyncRead + Send>>>),
    Data(TarReader<Pin<Box<dyn AsyncRead + Send>>>),
}

impl DebEntry {
    pub fn into_inner(self) -> TarReader<Pin<Box<dyn AsyncRead + Send>>> {
        match self {
            DebEntry::Control(tar) | DebEntry::Data(tar) => tar,
        }
    }
    pub async fn next(&mut self) -> Option<Result<TarEntry<Pin<Box<dyn AsyncRead + Send>>>>> {
        match self {
            DebEntry::Control(tar) | DebEntry::Data(tar) => tar.next().await,
        }
    }
}
