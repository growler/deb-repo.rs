use {
    crate::{
        control::MutableControlStanza,
        hash::HashingReader,
        parse_size,
        staging::{Stage, StagingFile},
        tar::{TarEntry, TarLink, TarReader},
        StagingFileSystem,
    },
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    async_lock::Mutex,
    core::task::{self, Context, Poll},
    futures_lite::{io::BufReader, AsyncRead, AsyncReadExt, Stream, StreamExt},
    pin_project_lite::pin_project,
    std::{
        future::Future,
        io::{self, Result},
        ops::Range,
        path::PathBuf,
        pin::{pin, Pin},
        sync::Arc,
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
const DEBIAN_BINARY_VERSION: &str = "2.0\n";

#[derive(Clone, Copy, PartialEq)]
enum State {
    Magic,
    Header,
    Version,
    Content,
}

#[derive(Clone, Copy, PartialEq)]
enum EntryKind {
    Control,
    Data,
}

pin_project! {
    struct DebReaderInner<'a, R> {
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
        #[pin]
        source: R,
        _marker: std::marker::PhantomData<&'a ()>,
    }
}

impl<'a, R> DebReaderInner<'a, R>
where
    R: AsyncRead + Send + 'a,
{
    fn new(r: R) -> Self {
        Self {
            state: State::Magic,
            size: AR_MAGIC_SIZE,
            padding: 0,
            read: 0,
            total: 0,
            hdr: [0u8; AR_HEADER_SIZE as usize],
            source: r,
            _marker: std::marker::PhantomData,
        }
    }
    fn poll_read_header(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<usize>> {
        let this = self.project();
        // padding might be useful to read debian version entry
        let size = *this.size + *this.padding as u64;
        let remain = size - *this.read;
        if remain == 0 {
            return Poll::Ready(Ok(0));
        }
        let read_so_far = *this.read as usize;
        let padding = *this.padding;
        match ready!(pin!(this.source).poll_read(ctx, &mut this.hdr[read_so_far..size as usize])) {
            0 => Poll::Ready(Ok(0)),
            n => {
                *this.read += n as u64;
                *this.total += n as u64;
                Poll::Ready(Ok(if (n as u64) < remain {
                    n
                } else {
                    n - padding as usize
                }))
            }
        }
    }
}

impl<'a, R> AsyncRead for DebReaderInner<'a, R>
where
    R: AsyncRead + Send + 'a,
{
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let remain = (*this.size + *this.padding as u64) - *this.read;
        if remain == 0 {
            return Poll::Ready(Ok(0));
        };
        let size = std::cmp::min(remain, buf.len() as u64);
        match ready!(pin!(this.source).poll_read(ctx, &mut buf[0..size as usize])) {
            0 => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading package entry",
            ))),
            n => {
                *this.read += n as u64;
                *this.total += n as u64;
                Poll::Ready(Ok(if (n as u64) < remain {
                    n
                } else {
                    n - *this.padding as usize
                }))
            }
        }
    }
}

impl<'a, R> Stream for DebReaderInner<'a, R>
where
    R: AsyncRead + Send + 'a,
{
    type Item = Result<(EntryKind, Range<usize>)>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let state = *self.as_mut().project().state;
            match state {
                State::Magic => {
                    // reading magic
                    while ready_opt!(self.as_mut().poll_read_header(ctx)) != 0 {}
                    let this = self.as_mut().project();
                    if this.hdr[..AR_MAGIC_SIZE as usize] != AR_MAGIC[..] {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid debian package magic",
                        ))));
                    }
                    *this.state = State::Header;
                    *this.size = AR_HEADER_SIZE;
                    *this.padding = 0;
                    *this.read = 0;
                }
                State::Content => {
                    // skipping content
                    let mut buf = [0u8; 8192];
                    while ready_opt!(self.as_mut().poll_read(ctx, &mut buf[..])) != 0 {}
                    let this = self.as_mut().project();
                    *this.state = State::Header;
                    *this.size = AR_HEADER_SIZE;
                    *this.padding = 0;
                    *this.read = 0;
                }
                State::Version => {
                    while ready_opt!(self.as_mut().poll_read_header(ctx)) != 0 {}
                    let this = self.as_mut().project();
                    if this.hdr[..DEBIAN_BINARY_VERSION.len()]
                        != DEBIAN_BINARY_VERSION.as_bytes()[..]
                    {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unsupported debian binary package version",
                        ))));
                    }
                    *this.state = State::Header;
                    *this.size = AR_HEADER_SIZE;
                    *this.padding = 0;
                    *this.read = 0;
                }
                State::Header => {
                    // reding header
                    while ready_opt!(self.as_mut().poll_read_header(ctx)) != 0 {}
                    let (size_with_padding, name) = {
                        let this = self.as_mut().project();
                        let size = parse_size(&this.hdr[48..58])?;
                        let size_with_padding = size + (size & 1);
                        let name = std::str::from_utf8(&this.hdr[0..16]).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid header: {:?}", &this.hdr),
                            )
                        })?;
                        let name = name.find(' ').map_or(name, |n| &name[..n]);
                        *this.state = State::Content;
                        *this.size = size;
                        *this.padding = (size & 1) as u8;
                        *this.read = 0;
                        (size_with_padding, name)
                    };
                    if name == "debian-binary" {
                        if size_with_padding > AR_HEADER_SIZE {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid debian binary entry size",
                            ))));
                        } else {
                            let this = self.as_mut().project();
                            *this.state = State::Version;
                            continue;
                        }
                    } else if name.starts_with("control.tar") {
                        let ext_range = "control.tar".len()..name.len();
                        return Poll::Ready(Some(Ok((EntryKind::Control, ext_range))));
                    } else if name.starts_with("data.tar") {
                        let ext_range = "data.tar".len()..name.len();
                        return Poll::Ready(Some(Ok((EntryKind::Data, ext_range))));
                    } else {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected debian package entry \"{}\"", name),
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
pub struct DebReader<'a, R>
where
    R: AsyncRead + Send + 'a,
{
    inner: Arc<Mutex<Pin<Box<DebReaderInner<'a, R>>>>>,
}

struct DebEntryReaderInner<'a, R>
where
    R: AsyncRead + Send + 'a,
{
    inner: Arc<Mutex<Pin<Box<DebReaderInner<'a, R>>>>>,
}

impl<'a, R> AsyncRead for DebEntryReaderInner<'a, R>
where
    R: AsyncRead + Send + 'a,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut();
        let fut = this.inner.lock();
        let mut guard = task::ready!(pin!(fut).poll(ctx));
        guard.as_mut().poll_read(ctx, buf)
    }
}

enum Compression {
    None,
    Gzip,
    Xz,
    Bz2,
    Lzma,
    Zstd,
}

impl Compression {
    fn from_extension(ext: &[u8]) -> Self {
        match ext {
            b".gz" => Compression::Gzip,
            b".xz" => Compression::Xz,
            b".bz2" => Compression::Bz2,
            b".lzma" => Compression::Lzma,
            b".zst" | b".zstd" => Compression::Zstd,
            _ => Compression::None,
        }
    }
}

impl<'a, R> DebReader<'a, R>
where
    R: AsyncRead + Send + 'a,
{
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
    pub fn new(r: R) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::pin(DebReaderInner::new(r)))),
        }
    }
    pub async fn extract_to<'f, FS>(
        mut self,
        fs: &'f FS,
    ) -> Result<MutableControlStanza>
    where
        'a: 'f,
        FS: StagingFileSystem + ?Sized,
    {
        let mut installed_files: Vec<String> = vec![];
        let mut ctrl: MutableControlStanza;
        let mut ctrl_files: Vec<(String, FS::File)> = vec![];
        let mut ctrl_files_list = String::new();
        let mut conf_files: Vec<(String, Option<String>)> = vec![];
        let multiarch: Option<&str>;
        let pkg: &str;
        let ctrl_base = PathBuf::from("./var/lib/dpkg/info");
        fs.create_dir_all(ctrl_base.clone(), 0, 0, 0o755).await?;
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
                                .create_file_from_bytes(
                                    buf.as_bytes(),
                                    uid,
                                    gid,
                                    mode,
                                )
                                .await?;
                            ctrl_files.push((filename, file));
                        } else {
                            let file = fs
                                .create_file(
                                    file,
                                    uid,
                                    gid,
                                    mode,
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
            let mut links: Vec<TarLink> = Vec::new();
            while let Some(entry) = data_tarball.next().await {
                let entry = entry?;
                tracing::debug!("{} {}", pkg, entry.path());
                // tracing::debug!("{} {:?} {:#?}", pkg, path.as_os_str(), entry.header());
                installed_files.push(entry.path().to_owned());
                match entry {
                    TarEntry::Directory(dir) => {
                        tracing::debug!("creating directory {}", dir.path());
                        fs.create_dir_all(dir.path(), dir.uid(), dir.gid(), dir.mode())
                            .await?;
                    }
                    TarEntry::File(mut file) => {
                        let size = file.size() as usize;
                        let path = PathBuf::from(file.path());
                        let uid = file.uid();
                        let gid = file.gid();
                        let mode = file.mode();
                        tracing::debug!("extracting {}", file.path());
                        match conf_files.iter_mut().find(|(name, _)| name == file.path()) {
                            None => fs
                                .create_file(&mut file, uid, gid, mode, Some(size))
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
                                    .create_file(&mut hasher, uid, gid, mode, Some(size))
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
                        .persist(&path)
                        .await?;
                    }
                    TarEntry::Symlink(link) => {
                        let uid = link.uid();
                        let gid = link.gid();
                        fs.symlink(link.link(), link.path(), uid, gid).await?;
                    }
                    TarEntry::Link(link) => {
                        links.push(link);
                    }
                }
            }
            for link in links.drain(..) {
                fs.hardlink(link.link(), link.path()).await?;
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
            fs.create_file_from_bytes(buf.as_bytes(), 0, 0, 0o644)
                .await?
                .persist(&target_name)
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

impl<'a, 'f, R, FS> Stage<'f, FS> for DebReader<'a, R>
where
    R: AsyncRead + Send + 'a,
    FS: StagingFileSystem + ?Sized,
    'a: 'f,
{
    type Output = MutableControlStanza;
    fn stage(self, fs: &'f FS) -> impl Future<Output = io::Result<MutableControlStanza>> + 'f {
        self.extract_to(fs)
    }
}

impl<'a, R> Stream for DebReader<'a, R>
where
    R: AsyncRead + Send + 'a,
{
    type Item = Result<DebEntry<'a>>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = {
            let this = self.as_mut();
            let fut = this.inner.lock();
            let mut inner = task::ready!(pin!(fut).poll(ctx));
            match task::ready!(inner.as_mut().poll_next(ctx)) {
                None => None,
                Some(Err(err)) => Some(Err(err)),
                Some(Ok((entry_kind, ext_range))) => Some(Ok((
                    entry_kind,
                    Compression::from_extension(&inner.hdr[ext_range]),
                ))),
            }
        };
        let (entry_kind, comp) = match polled {
            None => return Poll::Ready(None),
            Some(Err(e)) => return Poll::Ready(Some(Err(e))),
            Some(Ok(v)) => v,
        };
        let this = self.as_ref();
        Poll::Ready(Some(Ok(match entry_kind {
            EntryKind::Control => DebEntry::Control(entry_reader(Arc::clone(&this.inner), comp)),
            EntryKind::Data => DebEntry::Data(entry_reader(Arc::clone(&this.inner), comp)),
        })))
    }
}

pub enum DebEntry<'a> {
    Control(TarReader<'a, Pin<Box<dyn AsyncRead + Send + 'a>>>),
    Data(TarReader<'a, Pin<Box<dyn AsyncRead + Send + 'a>>>),
}

fn entry_reader<'a, R>(
    inner: Arc<Mutex<Pin<Box<DebReaderInner<'a, R>>>>>,
    comp: Compression,
) -> TarReader<'a, Pin<Box<dyn AsyncRead + Send + 'a>>>
where
    R: AsyncRead + Send + 'a,
{
    let r = DebEntryReaderInner { inner };
    match comp {
        Compression::Xz => TarReader::new(Box::pin(XzDecoder::new(BufReader::new(r)))),
        Compression::Gzip => TarReader::new(Box::pin(GzipDecoder::new(BufReader::new(r)))),
        Compression::Bz2 => TarReader::new(Box::pin(BzDecoder::new(BufReader::new(r)))),
        Compression::Lzma => TarReader::new(Box::pin(LzmaDecoder::new(BufReader::new(r)))),
        Compression::Zstd => TarReader::new(Box::pin(ZstdDecoder::new(BufReader::new(r)))),
        Compression::None => TarReader::new(Box::pin(r)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;
    assert_impl_all!(DebReader<'_, smol::fs::File>: Send, Sync);
}
