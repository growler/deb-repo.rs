pub use async_tar::{
    Archive as Tarball, Entries as TarballEntries, Entry as TarballEntry,
    EntryType as TarballEntryType,
};
use {
    crate::{
        control::MutableControlStanza, deployfs::DeploymentFile, digest::GetDigest, parse_size,
    },
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    core::task::{self, Context, Poll},
    futures::{io::BufReader, AsyncRead, AsyncReadExt, Stream, StreamExt},
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
                            format!("unexpecteddebian package entry {:?}", &name),
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
        let mut reader = self.inner.lock().map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected mutex error {}", err),
            )
        })?;
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
    fn entry_reader_for_ext(
        &self,
        ext: &str,
    ) -> Result<Pin<Box<dyn AsyncRead + Unpin + Send + 'static>>> {
        let r = DebEntryReaderInner {
            inner: Arc::clone(&self.inner),
        };
        Ok(match ext {
            ".xz" => Box::pin(XzDecoder::new(BufReader::new(r))),
            ".gz" => Box::pin(GzipDecoder::new(BufReader::new(r))),
            ".bz2" => Box::pin(BzDecoder::new(BufReader::new(r))),
            ".lzma" => Box::pin(LzmaDecoder::new(BufReader::new(r))),
            ".zstd" => Box::pin(ZstdDecoder::new(BufReader::new(r))),
            _ => Box::pin(r),
        })
    }
    pub async fn extract_to<FS: crate::DeploymentFileSystem>(
        mut self,
        fs: &FS,
    ) -> Result<MutableControlStanza> {
        let mut installed_files: Vec<String> = vec![];
        let mut ctrl: MutableControlStanza;
        let mut ctrl_files: Vec<(String, FS::File)> = vec![];
        let mut ctrl_files_list = String::new();
        let mut conf_files: Vec<(String, Option<String>)> = vec![];
        let multiarch: Option<&str>;
        let pkg: &str;
        let ctrl_base = PathBuf::from("var/lib/dpkg/info");
        fs.create_dir_all(&ctrl_base, 0, 0, 0o755).await?;
        {
            let mut control_entries = self
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
                })?
                .entries()?;
            let mut maybe_ctrl: Option<MutableControlStanza> = None;
            while let Some(entry) = control_entries.next().await {
                let mut entry = entry?;
                match entry.header().entry_type() {
                    TarballEntryType::Regular => {
                        let mtime = UNIX_EPOCH + Duration::from_secs(entry.header().mtime()?);
                        let uid = entry.header().uid()? as u32;
                        let gid = entry.header().gid()? as u32;
                        let mode = entry.header().mode()?;
                        let size = entry.header().size()? as usize;
                        let filename = entry
                            .header()
                            .path()?
                            .file_name()
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("invalid entry in control.tar: {:?}", &entry),
                                )
                            })
                            .and_then(|name| {
                                name.to_str().ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("path is not a valid UTF-8 string: {:?}", name),
                                    )
                                })
                            })?
                            .to_owned();
                        if filename.eq("control") {
                            let mut buf = String::new();
                            entry.read_to_string(&mut buf).await?;
                            maybe_ctrl.replace(MutableControlStanza::parse(buf).map_err(
                                |err| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("error parsing control file: {}", err),
                                    )
                                },
                            )?);
                            continue;
                        } else if filename.eq("conffiles") {
                            let mut buf = String::with_capacity(entry.header().size()? as usize);
                            entry.read_to_string(&mut buf).await?;
                            conf_files.extend(buf.lines().map(|l| (l.to_owned(), None)));
                            let file = fs
                                .create_file(
                                    buf.as_bytes(),
                                    None::<PathBuf>,
                                    uid,
                                    gid,
                                    mode,
                                    Some(mtime),
                                    Some(size),
                                )
                                .await?;
                            ctrl_files.push((filename.into(), file));
                        } else {
                            let file = fs
                                .create_file(
                                    entry,
                                    None::<PathBuf>,
                                    uid,
                                    gid,
                                    mode,
                                    Some(mtime),
                                    Some(size),
                                )
                                .await?;
                            ctrl_files.push((filename.into(), file));
                        }
                    }
                    TarballEntryType::Directory
                        if entry.header().path()?.as_ref().to_str() == Some("./") => {}
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid entry in control.tar: {:?}", &entry),
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
                target_name.push(name);
                file.persist(ctrl_base.join(target_name)).await?;
            }
        }
        {
            let mut data_entries = self
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
                })?
                .entries()?;
            while let Some(entry) = data_entries.next().await {
                let entry = entry?;
                let path = entry.header().path()?.to_path_buf();
                let path_str = path
                    .to_str()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("package file name {:?} is not a valid UTF-8", path),
                        )
                    })
                    .map(|p| if p.starts_with('.') { &p[1..] } else { p })?;
                installed_files.push(path_str.to_owned());
                match entry.header().entry_type() {
                    TarballEntryType::Directory => {
                        fs.create_dir_all(
                            &path,
                            entry.header().uid()? as u32,
                            entry.header().gid()? as u32,
                            entry.header().mode()?,
                        )
                        .await?;
                    }
                    TarballEntryType::Regular => {
                        let mtime = UNIX_EPOCH + Duration::from_secs(entry.header().mtime()?);
                        let uid = entry.header().uid()? as u32;
                        let gid = entry.header().gid()? as u32;
                        let mode = entry.header().mode()?;
                        let size = entry.header().size()? as usize;
                        match conf_files.iter_mut().find(|(name, _)| name == path_str) {
                            None => fs
                                .create_file(
                                    entry,
                                    Some(&path),
                                    uid,
                                    gid,
                                    mode,
                                    Some(mtime),
                                    Some(size),
                                )
                                .await
                                .map_err(|err| {
                                    io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("error creating file {:#?}: {}", &path, err),
                                    )
                                })?,
                            Some((_, sum)) => {
                                let mut hasher =
                                    crate::digest::HashingReader::<md5::Md5, _>::new(entry);
                                let file = fs
                                    .create_file(
                                        &mut hasher,
                                        Some(&path),
                                        uid,
                                        gid,
                                        mode,
                                        Some(mtime),
                                        Some(size),
                                    )
                                    .await
                                    .map_err(|err| {
                                        io::Error::new(
                                            io::ErrorKind::Other,
                                            format!(
                                                "error creating config file {:#?} {}: {}",
                                                path.as_os_str(),
                                                mode,
                                                err
                                            ),
                                        )
                                    })?;
                                let hash = hasher.get_digest();
                                sum.replace(hash.into());
                                file
                            }
                        }
                        .persist(&path)
                        .await?;
                    }
                    TarballEntryType::Link => {
                        fs.hardlink(
                            entry.header().link_name()?.ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("invalid link entry in data.tar: {:?}", &entry),
                                )
                            })?,
                            &path,
                        )
                        .await?;
                    }
                    TarballEntryType::Symlink => {
                        let mtime = UNIX_EPOCH + Duration::from_secs(entry.header().mtime()?);
                        let uid = entry.header().uid()? as u32;
                        let gid = entry.header().gid()? as u32;
                        fs.symlink(
                            entry.header().link_name()?.ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("invalid symlink entry in data.tar: {:?}", &entry),
                                )
                            })?,
                            &path,
                            uid,
                            gid,
                            Some(mtime),
                        )
                        .await?;
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "invalid entry in data.tar: kind {:?} {:?}",
                                entry.header().entry_type().as_byte(),
                                &entry
                            ),
                        ))
                    }
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
                Some(&target_name),
                0,
                0,
                0o644,
                None,
                Some(buf.len()),
            )
            .await?
            .persist(target_name)
            .await?;
        }
        if conf_files.len() > 0 {
            let mut buf = String::new();
            for (name, hash) in conf_files.into_iter() {
                if let Some(hash) = hash {
                    buf.push_str("\n ");
                    buf.push_str(&name);
                    buf.push(' ');
                    buf.push_str(&hash);
                }
            }
            if buf.len() > 0 {
                ctrl.set("Conffiles", buf);
            }
        }
        // ctrl.set(D::DIGEST_FIELD_NAME, Into::<String>::into(self.finalize().await?));
        if ctrl_files_list.len() > 0 {
            ctrl.set("Controlfiles", ctrl_files_list);
        }
        Ok(ctrl)
    }
}

impl Stream for DebReader {
    type Item = Result<DebEntry>;
    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut reader = self.inner.lock().map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected mutex error {}", err),
            )
        })?;
        match task::ready!(Pin::new(&mut *reader).poll_next(ctx)) {
            None => Poll::Ready(None),
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            Some(Ok((entry_kind, ext_range))) => Poll::Ready(Some(match entry_kind {
                EntryKind::Control => {
                    Ok(DebEntry::Control(Tarball::new(self.entry_reader_for_ext(
                        unsafe { std::str::from_utf8_unchecked(&reader.hdr[ext_range]) },
                    )?)))
                }
                EntryKind::Data => Ok(DebEntry::Data(Tarball::new(self.entry_reader_for_ext(
                    unsafe { std::str::from_utf8_unchecked(&reader.hdr[ext_range]) },
                )?))),
            })),
        }
    }
}

// TODO: remove
// pub struct DebEntryReader<'a> {
//     inner: Pin<Box<dyn AsyncRead + Unpin + Send>>,
//     _marker: std::marker::PhantomData<&'a ()>,
// }
//
// impl<'a> AsyncRead for DebEntryReader<'a> {
//     fn poll_read(
//         mut self: Pin<&mut Self>,
//         ctx: &mut Context<'_>,
//         buf: &mut [u8],
//     ) -> Poll<std::io::Result<usize>> {
//         self.inner.as_mut().poll_read(ctx, buf)
//     }
// }

pub enum DebEntry {
    Control(Tarball<Pin<Box<dyn AsyncRead + Unpin + Send + 'static>>>),
    Data(Tarball<Pin<Box<dyn AsyncRead + Unpin + Send + 'static>>>),
}

impl DebEntry {
    pub fn into_inner(self) -> Tarball<Pin<Box<dyn AsyncRead + Unpin + Send + 'static>>> {
        match self {
            DebEntry::Control(tar) | DebEntry::Data(tar) => tar,
        }
    }
    pub fn entries(
        self,
    ) -> Result<TarballEntries<Pin<Box<dyn AsyncRead + Unpin + Send + 'static>>>> {
        match self {
            DebEntry::Control(tar) | DebEntry::Data(tar) => tar.entries(),
        }
    }
}
