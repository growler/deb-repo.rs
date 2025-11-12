use {
    crate::{
        StagingFile, StagingFileSystem, comp::{comp_reader, is_comp_ext, is_tar_ext, tar_reader}, hash::{AsyncHashingRead, Hash, HashAlgo, HashingReader}, repo::TransportProvider, staging::{FileList, Stage}, tar
    },
    clap::Args,
    futures_lite::StreamExt,
    rustix::{
        fd::{AsRawFd, OwnedFd},
        fs::{CWD, FileType, Mode, OFlags, fstat, openat},
    },
    serde::{Deserialize, Serialize},
    smol::io::{AsyncRead},
    std::{
        borrow::Cow,
        io,
        num::NonZero,
        path::Path,
        pin::Pin,
        task::{Context, Poll},
    },
};

#[derive(Args)]
pub struct ArtifactArg {
    /// Target file mode (only if artifact is a single file)
    #[arg(long = "mode", value_name = "MODE")]
    pub mode: Option<NonZero<u32>>,
    /// Do not unpack (disables auto-unpacking of tar archives and compressed files)
    #[arg(long = "no-unpack", action)]
    pub do_not_unpack: Option<bool>,
    /// A target architecture for the artifact
    #[arg(long = "only-arch", value_name = "ARCH")]
    pub target_arch: Option<String>,
    /// Artifact URL or path
    #[arg(value_name = "URL")]
    pub url: String,
    /// A target path on the staging filesystem
    #[arg(value_name = "TARGET_PATH")]
    pub target: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Artifact {
    Tar(Tar),
    Dir(Tree),
    File(File),
}

#[derive(Debug, Clone)]
pub enum ArtifactSource<'a> {
    Local(Cow<'a, Path>),
    Remote(Cow<'a, str>),
}

impl<'a> ArtifactSource<'a> {
    pub(crate) fn new<P: AsRef<Path>>(s: &'a str, base: P) -> Self {
        if crate::is_url(s) {
            ArtifactSource::Remote(Cow::Owned(s.to_string()))
        } else {
            let path = Path::new(s);
            if path.is_absolute() {
                ArtifactSource::Local(Cow::Borrowed(path))
            } else {
                ArtifactSource::Local(Cow::Owned(base.as_ref().join(path)))
            }
        }
    }
    pub fn is_remote(&self) -> bool {
        matches!(self, ArtifactSource::Remote(_))
    }
    pub fn remote_uri(&self) -> Option<&str> {
        match self {
            ArtifactSource::Remote(ref uri) => Some(uri.as_ref()),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tar {
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    #[serde(skip, default)]
    uri: String,
    hash: Hash,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}
pub struct TarReader<'a, R: AsyncRead + Send + 'a, FS> {
    target: Option<String>,
    inner: tar::TarReader<'a, R>,
    _marker: std::marker::PhantomData<FS>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tree {
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    #[serde(skip, default)]
    path: String,
    hash: Hash,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}
pub struct TreeReader<FS> {
    target: Option<String>,
    dir: OwnedFd,
    hash: Hash,
    _marker: std::marker::PhantomData<FS>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct File {
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    #[serde(skip, default)]
    uri: String,
    hash: Hash,
    size: u64,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<NonZero<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unpack: Option<bool>,
}
pub struct FileReader<'a, R: AsyncRead + Send + 'a, FS> {
    target: String,
    inner: R,
    mode: Option<NonZero<u32>>,
    size: Option<NonZero<usize>>,
    _marker: std::marker::PhantomData<&'a ()>,
    _marker_fs: std::marker::PhantomData<FS>,
}

pub enum ArtifactReader<'a, R: AsyncRead + Send + 'a, FS> {
    Tar(TarReader<'a, R, FS>),
    Tree(TreeReader<FS>),
    File(FileReader<'a, R, FS>),
}

impl<'a, R, FS> Stage for ArtifactReader<'a, R, FS>
where
    R: AsyncRead + Send + 'a,
    FS: StagingFileSystem,
{
    type Target = FS;
    type Output = ();
    async fn stage(self, fs: &Self::Target) -> io::Result<()> {
        match self {
            ArtifactReader::Tar(tar) => tar.stage(fs).await,
            ArtifactReader::Tree(tree) => tree.stage(fs).await,
            ArtifactReader::File(file) => file.stage(fs).await,
        }
    }
}

impl<'a, R: AsyncRead + Send + 'a, FS> FileReader<'a, R, FS> {
    pub fn new<P: Into<String>>(
        reader: R,
        target: P,
        mode: Option<NonZero<u32>>,
        size: Option<NonZero<usize>>,
    ) -> Self {
        Self {
            target: target.into(),
            inner: reader,
            mode,
            size,
            _marker: std::marker::PhantomData,
            _marker_fs: std::marker::PhantomData,
        }
    }
}

impl Artifact {
    pub(crate) async fn new<B, T>(
        base: B,
        artifact: &ArtifactArg,
        transport: &T,
    ) -> io::Result<Self>
    where
        B: AsRef<Path>,
        T: TransportProvider + ?Sized,
    {
        let uri = &artifact.url;
        let target = artifact.target.clone();
        let source = ArtifactSource::new(uri, base);
        let unpack = artifact.do_not_unpack.map(|b| !b);
        let arch = artifact.target_arch.as_deref();
        match source {
            ArtifactSource::Local(ref path) => {
                let path = path.as_ref();
                if smol::fs::symlink_metadata(path).await?.is_dir() {
                    Ok(Artifact::Dir(
                        Tree::new_local(uri, arch, path, target).await?,
                    ))
                } else if unpack.unwrap_or(true) && is_tar_ext(path.as_os_str().as_encoded_bytes())
                {
                    Ok(Artifact::Tar(
                        Tar::new_local(uri, arch, path, target).await?,
                    ))
                } else {
                    Ok(Artifact::File(
                        File::new_local(uri, arch, path, target, artifact.mode, unpack).await?,
                    ))
                }
            }
            ArtifactSource::Remote(ref uri) => {
                if unpack.unwrap_or(true) && is_tar_ext(uri.as_bytes()) {
                    Ok(Artifact::Tar(
                        Tar::new_remote(uri, arch, target, transport).await?,
                    ))
                } else {
                    Ok(Artifact::File(
                        File::new_remote(uri, arch, target, artifact.mode, unpack, transport)
                            .await?,
                    ))
                }
            }
        }
    }
    pub fn with_remote_reader<R: AsyncRead + Send + 'static, FS: StagingFileSystem>(
        &self,
        r: R,
    ) -> ArtifactReader<'static, Pin<Box<dyn AsyncRead + Send>>, FS> {
        match &self {
            Artifact::Tar(inner) => ArtifactReader::Tar(
                inner
                    .with_remote_reader(r)
                    .expect("failed to create tar reader"),
            ),
            Artifact::File(inner) => ArtifactReader::File(
                inner
                    .with_remote_reader(r)
                    .expect("failed to create file reader"),
            ),
            Artifact::Dir(_) => panic!("directory artifacts do not support remote readers"),
        }
    }
    pub async fn reader<T: TransportProvider + ?Sized, FS: StagingFileSystem>(
        &self,
        source: ArtifactSource<'_>,
        transport: &T,
    ) -> io::Result<ArtifactReader<'static, Pin<Box<dyn AsyncRead + Send>>, FS>> {
        match source {
            ArtifactSource::Local(ref path) => match &self {
                Artifact::Tar(inner) => inner.local_reader(path).await.map(ArtifactReader::Tar),
                Artifact::Dir(inner) => inner.local_reader(path).await.map(ArtifactReader::Tree),
                Artifact::File(inner) => inner.local_reader(path).await.map(ArtifactReader::File),
            },
            ArtifactSource::Remote(ref uri) => match &self {
                Artifact::Dir(_) => Err(io::Error::other(format!(
                    "invalid artifact source for directory artifact: {}",
                    uri
                ))),
                Artifact::Tar(inner) => inner
                    .remote_reader(transport)
                    .await
                    .map(ArtifactReader::Tar),
                Artifact::File(inner) => inner
                    .remote_reader(transport)
                    .await
                    .map(ArtifactReader::File),
            },
        }
    }
    pub fn hash(&self) -> &Hash {
        match &self {
            Artifact::Tar(inner) => &inner.hash,
            Artifact::Dir(inner) => &inner.hash,
            Artifact::File(inner) => &inner.hash,
        }
    }
    pub fn size(&self) -> u64 {
        match &self {
            Artifact::Tar(inner) => inner.size,
            Artifact::Dir(inner) => inner.size,
            Artifact::File(inner) => inner.size,
        }
    }
    pub fn uri(&self) -> &str {
        match &self {
            Artifact::Tar(inner) => &inner.uri,
            Artifact::Dir(inner) => &inner.path,
            Artifact::File(inner) => &inner.uri,
        }
    }
    pub fn arch(&self) -> Option<&str> {
        match &self {
            Artifact::Tar(inner) => inner.arch.as_deref(),
            Artifact::Dir(inner) => inner.arch.as_deref(),
            Artifact::File(inner) => inner.arch.as_deref(),
        }
    }
    pub(crate) fn with_uri(self, uri: String) -> Self {
        match self {
            Artifact::Tar(mut t) => {
                t.uri = uri;
                Artifact::Tar(t)
            }
            Artifact::Dir(mut d) => {
                d.path = uri;
                Artifact::Dir(d)
            }
            Artifact::File(mut f) => {
                f.uri = uri;
                Artifact::File(f)
            }
        }
    }
    pub(crate) fn toml_table(&self) -> toml_edit::Table {
        let mut table = toml_edit::ser::to_document(self)
            .expect("failed to serialize table")
            .into_table();
        if let Artifact::File(File {
            mode: Some(mode), ..
        }) = self
        {
            *table.get_mut("mode").expect("mode field") = format!("0o{:03o}", mode.get())
                .parse::<toml_edit::Item>()
                .expect("parsed item");
        }
        table
    }
}

impl Tar {
    async fn new_remote<T: TransportProvider + ?Sized>(
        uri: &str,
        arch: Option<&str>,
        target: Option<String>,
        transport: &T,
    ) -> io::Result<Self> {
        let mut reader = transport.open_hashed(uri, blake3::Hasher::NAME).await?;
        TarReader {
            inner: tar_reader(uri, &mut reader)?,
            target: target.clone(),
            _marker: std::marker::PhantomData,
        }
        .stage(&FileList::new())
        .await?;
        let hash = reader.as_mut().hash();
        let size = reader.as_mut().size();
        Ok(Tar {
            uri: uri.to_string(),
            arch: arch.map(|s| s.to_string()),
            target,
            hash,
            size,
        })
    }
    async fn new_local(
        uri: &str,
        arch: Option<&str>,
        path: &Path,
        target: Option<String>,
    ) -> io::Result<Self> {
        let mut reader = HashingReader::<blake3::Hasher, _>::new(smol::fs::File::open(path).await?);
        TarReader {
            inner: tar_reader(uri, &mut reader)?,
            target: target.clone(),
            _marker: std::marker::PhantomData,
        }
        .stage(&FileList::new())
        .await?;
        let (hash, size) = reader.into_hash_and_size();
        Ok(Tar {
            uri: uri.to_string(),
            arch: arch.map(|s| s.to_string()),
            target,
            hash,
            size,
        })
    }
    async fn local_reader<FS: StagingFileSystem>(
        &self,
        path: &Path,
    ) -> io::Result<TarReader<'static, Pin<Box<dyn AsyncRead + Send>>, FS>> {
        let inner = tar_reader(
            &self.uri,
            self.hash
                .verifying_reader(self.size, smol::fs::File::open(path).await?),
        )?;
        Ok(TarReader {
            inner,
            target: self.target.clone(),
            _marker: std::marker::PhantomData,
        })
    }
    fn with_remote_reader<R: AsyncRead + Send + 'static, FS: StagingFileSystem>(
        &self,
        r: R,
    ) -> io::Result<TarReader<'static, Pin<Box<dyn AsyncRead + Send>>, FS>> {
        tar_reader(&self.uri, r).map(|inner| TarReader {
            inner,
            target: self.target.clone(),
            _marker: std::marker::PhantomData,
        })
    }
    async fn remote_reader<T, FS>(
        &self,
        transport: &T,
    ) -> io::Result<TarReader<'static, Pin<Box<dyn AsyncRead + Send>>, FS>>
    where
        T: TransportProvider + ?Sized,
        FS: StagingFileSystem,
    {
        self.with_remote_reader(
            transport
                .open_verified(&self.uri, self.size, &self.hash)
                .await?,
        )
    }
}

impl<'a, R, FS> Stage for TarReader<'a, R, FS>
where
    R: AsyncRead + Send + 'a,
    FS: StagingFileSystem,
{
    type Target = FS;
    type Output = ();
    async fn stage(mut self, fs: &Self::Target) -> io::Result<()> {
        let mut links: Vec<tar::TarLink> = Vec::new();
        let target = self.target.as_deref();
        if let Some(parent) = target.and_then(|t| Path::new(t).parent()) {
            fs.create_dir_all(parent, 0, 0, 0o755).await?;
        }
        while let Some(entry) = self.inner.next().await {
            let entry = entry?;
            match entry {
                tar::TarEntry::Directory(dir) => {
                    let path = target.map_or_else(
                        || Cow::Borrowed(Path::new(dir.path())),
                        |p| Cow::Owned(Path::new(p).join(dir.path())),
                    );
                    tracing::trace!("creating directory {}", path.display());
                    fs.create_dir_all(path, dir.uid(), dir.gid(), dir.mode())
                        .await?;
                }
                tar::TarEntry::File(mut file) => {
                    let path = target.map_or_else(
                        || Path::new(file.path()).to_path_buf(),
                        |p| Path::new(p).join(file.path()),
                    );
                    let size = file.size() as usize;
                    let uid = file.uid();
                    let gid = file.gid();
                    let mode = file.mode();
                    tracing::trace!("extracting {}", path.display());
                    fs.create_file(&mut file, uid, gid, mode, Some(size))
                        .await
                        .map_err(|err| {
                            io::Error::other(format!(
                                "error creating file {}: {}",
                                path.display(),
                                err
                            ))
                        })?
                        .persist(&path)
                        .await?;
                }
                tar::TarEntry::Symlink(link) => {
                    let uid = link.uid();
                    let gid = link.gid();
                    let path = target.map_or_else(
                        || Cow::Borrowed(Path::new(link.path())),
                        |p| Cow::Owned(Path::new(p).join(link.path())),
                    );
                    let link = Path::new(link.link());
                    let link = target.map_or_else(
                        || Cow::Borrowed(link),
                        |p| {
                            if link.is_absolute() {
                                Cow::Owned(Path::new(p).join(link))
                            } else {
                                Cow::Borrowed(link)
                            }
                        },
                    );
                    fs.symlink(link, path, uid, gid).await?;
                }
                tar::TarEntry::Link(link) => {
                    links.push(link);
                }
            }
        }
        for link in links.drain(..) {
            let path = target.map_or_else(
                || Cow::Borrowed(Path::new(link.path())),
                |p| Cow::Owned(Path::new(p).join(link.path())),
            );
            let link = target.map_or_else(
                || Cow::Borrowed(Path::new(link.path())),
                |p| Cow::Owned(Path::new(p).join(link.path())),
            );
            fs.hardlink(link, path).await?;
        }
        Ok(())
    }
}

impl Tree {
    async fn new_local<P: AsRef<Path>>(
        uri: &str,
        arch: Option<&str>,
        path: P,
        target: Option<String>,
    ) -> io::Result<Self> {
        let fd = openat(
            CWD,
            path.as_ref(),
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let (merkle, size) = tree::hash_dir(fd).await?;
        Ok(Self {
            path: uri.to_string(),
            arch: arch.map(|s| s.to_string()),
            target,
            hash: merkle,
            size,
        })
    }
    async fn local_reader<P: AsRef<Path>, FS: StagingFileSystem>(
        &self,
        path: P,
    ) -> io::Result<TreeReader<FS>> {
        let fd = openat(
            CWD,
            path.as_ref(),
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        Ok(TreeReader {
            dir: fd,
            target: self.target.clone(),
            hash: self.hash.clone(),
            _marker: std::marker::PhantomData,
        })
    }
}

impl<FS> Stage for TreeReader<FS>
where
    FS: StagingFileSystem,
{
    type Target = FS;
    type Output = ();
    async fn stage(self, fs: &Self::Target) -> io::Result<()> {
        if let Some(parent) = self.target.as_deref().and_then(|t| Path::new(t).parent()) {
            fs.create_dir_all(parent, 0, 0, 0o755).await?;
        }
        let hash = tree::copy_hash_dir(self.dir, fs, self.target.as_deref()).await?;
        if hash != self.hash {
            Err(io::Error::other("hash mismatch after copying local tree"))
        } else {
            Ok(())
        }
    }
}

impl File {
    async fn new_local(
        uri: &str,
        arch: Option<&str>,
        path: &Path,
        target: Option<String>,
        mode: Option<NonZero<u32>>,
        unpack: Option<bool>,
    ) -> io::Result<Self> {
        let target = target.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "target must be specified a file",
            )
        })?;
        let fd = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let stat = fstat(&fd)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(io::Error::other(format!("{} is not a regular file", uri)));
        }
        let st_mode = stat.st_mode & 0o7777;
        if st_mode == 0 {
            return Err(io::Error::other(format!(
                "file {} has invalid permissions set {:0o}",
                uri, st_mode,
            )));
        }
        let mode = mode.or_else(|| Some(NonZero::new(st_mode as u32).unwrap()));
        let (hash, size) = if unpack.unwrap_or(true) && is_comp_ext(uri) {
            let mut reader = HashingReader::<blake3::Hasher, _>::new(smol::fs::File::from(fd));
            smol::io::copy(&mut comp_reader(uri, &mut reader), &mut smol::io::sink()).await?;
            reader.into_hash_and_size()
        } else {
            let hash = smol::unblock(move || {
                let map = unsafe { memmap2::Mmap::map(fd.as_raw_fd()) }?;
                map.advise(memmap2::Advice::Sequential)?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(&map[..]);
                Ok::<_, io::Error>(hasher.into_hash())
            })
            .await?;
            (hash, stat.st_size as u64)
        };
        Ok(Self {
            uri: uri.to_string(),
            arch: arch.map(|s| s.to_string()),
            target,
            hash,
            size,
            mode,
            unpack,
        })
    }
    async fn new_remote<T: TransportProvider + ?Sized>(
        uri: &str,
        arch: Option<&str>,
        target: Option<String>,
        mode: Option<NonZero<u32>>,
        unpack: Option<bool>,
        transport: &T,
    ) -> io::Result<Self> {
        let target = target.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "target must be specified a file",
            )
        })?;
        let mode = mode.or_else(|| Some(NonZero::new(0o644).unwrap()));
        let mut rdr = transport.open_hashed(uri, blake3::Hasher::NAME).await?;
        if unpack.unwrap_or(true) {
            smol::io::copy(&mut comp_reader(uri, &mut rdr), &mut smol::io::sink()).await?;
        } else {
            smol::io::copy(&mut rdr, &mut smol::io::sink()).await?;
        }
        let hash = rdr.as_mut().hash();
        let size = rdr.as_mut().size();
        Ok(Self {
            uri: uri.to_string(),
            arch: arch.map(|s| s.to_string()),
            target,
            hash,
            size,
            mode,
            unpack,
        })
    }
    async fn local_reader<FS: StagingFileSystem>(
        &self,
        path: &Path,
    ) -> io::Result<FileReader<'static, Pin<Box<dyn AsyncRead + Send>>, FS>> {
        let inner: Pin<Box<dyn AsyncRead + Send>> = self
            .hash
            .reader(self.size, smol::fs::File::open(path).await?);
        Ok(FileReader {
            inner,
            target: self.target.clone(),
            mode: self.mode,
            size: Some(NonZero::new(self.size as usize).unwrap()),
            _marker: std::marker::PhantomData,
            _marker_fs: std::marker::PhantomData,
        })
    }
    fn with_remote_reader<R: AsyncRead + Send + 'static, FS: StagingFileSystem>(
        &self,
        r: R,
    ) -> io::Result<FileReader<'static, Pin<Box<dyn AsyncRead + Send>>, FS>> {
        let inner: Pin<Box<dyn AsyncRead + Send>> = self.hash.reader(self.size, r);
        Ok(FileReader {
            inner,
            target: self.target.clone(),
            mode: self.mode,
            size: Some(NonZero::new(self.size as usize).unwrap()),
            _marker: std::marker::PhantomData,
            _marker_fs: std::marker::PhantomData,
        })
    }
    async fn remote_reader<T: TransportProvider + ?Sized, FS: StagingFileSystem>(
        &self,
        transport: &T,
    ) -> io::Result<FileReader<'static, Pin<Box<dyn AsyncRead + Send>>, FS>> {
        self.with_remote_reader(
            transport
                .open_verified(&self.uri, self.size, &self.hash)
                .await?,
        )
    }
}

// rust supports dyn trat upcast only since 1.86.
// TODO:: remove as soon as debian MSRV is 1.86+
pin_project_lite::pin_project! {
    pub(crate) struct EraseHashingRead {
        #[pin]
        inner: Pin<Box<dyn AsyncHashingRead + Send + 'static>>,
    }
}
impl EraseHashingRead {
    fn new(inner: Pin<Box<dyn AsyncHashingRead + Send + 'static>>) -> Self {
        Self { inner }
    }
}
impl AsyncRead for EraseHashingRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<'a, R, FS> Stage for FileReader<'a, R, FS>
where
    R: AsyncRead + Send + 'a,
    FS: StagingFileSystem,
{
    type Target = FS;
    type Output = ();
    async fn stage(self, fs: &Self::Target) -> io::Result<()> {
        if let Some(parent) = Path::new(&self.target).parent() {
            fs.create_dir_all(parent, 0, 0, 0o755).await?;
        }
        fs.create_file(
            self.inner,
            0,
            0,
            self.mode.map_or(0o644, |m| m.get() & 0o7777),
            self.size.map(|s| s.get()),
        )
        .await?
        .persist(&self.target)
        .await
    }
}

fn mode(mode: u32) -> u32 {
    let ft = mode & libc::S_IFMT;
    let perm = mode & 0o7777;
    ft | perm
}

mod tree {
    use {
        super::mode,
        crate::{
            hash::{Hash, HashingReader},
            StagingFile, StagingFileSystem,
        },
        async_channel as chan,
        digest::{FixedOutput, Output},
        futures::stream::{self, StreamExt, TryStreamExt},
        itertools::Itertools,
        rustix::{
            fd::{AsFd, OwnedFd},
            fs::{fstat, openat2, readlinkat, Dir, FileType, Mode, OFlags, ResolveFlags, Stat},
            io::Errno,
        },
        std::{
            ffi::{CString, OsStr, OsString},
            io,
            os::{fd::AsRawFd, unix::ffi::OsStrExt},
            path::{Path, PathBuf},
            str::FromStr,
        },
    };

    enum Object {
        Directory {
            path: PathBuf,
            stat: Stat,
        },
        Symlink {
            path: PathBuf,
            target: CString,
        },
        RegularFile {
            path: PathBuf,
            stat: Stat,
            fd: OwnedFd,
        },
    }

    struct SmallBlockingPool {
        tx: chan::Sender<Box<dyn FnOnce() + Send + 'static>>,
    }
    impl SmallBlockingPool {
        fn new(threads: usize, name: &str) -> Self {
            let (tx, rx) = chan::unbounded::<Box<dyn FnOnce() + Send>>();
            for i in 0..threads {
                let rx = rx.clone();
                let name = format!("{name}-{i}");
                std::thread::Builder::new()
                    .name(name)
                    .spawn(move || {
                        while let Ok(job) = rx.recv_blocking() {
                            job();
                        }
                    })
                    .expect("spawn worker");
            }
            Self { tx }
        }

        async fn spawn<F, R>(&self, f: F) -> R
        where
            F: FnOnce() -> R + Send + 'static,
            R: Send + 'static,
        {
            let (rtx, rrx) = chan::bounded(1);
            let job = Box::new(move || {
                let res = f();
                let _ = rtx.send_blocking(res);
            });

            self.tx.send_blocking(job).expect("pool closed");
            rrx.recv().await.expect("worker dropped")
        }
    }

    type NodeHasher = blake3::Hasher;
    type NodeHash = Output<NodeHasher>;

    pub(super) async fn copy_hash_dir<FS: StagingFileSystem + ?Sized>(
        fd: OwnedFd,
        fs: &FS,
        target_path: Option<&str>,
    ) -> io::Result<Hash> {
        process(fd, &|obj| async {
            match obj {
                Object::Symlink { path, target } => {
                    let link_target = Path::new(OsStr::from_bytes(target.as_bytes()));
                    let path = if let Some(target_path) = target_path {
                        Path::new(target_path).join(path)
                    } else {
                        path
                    };
                    fs.symlink(link_target, &path, 0, 0).await?;
                    Ok(None)
                }
                Object::Directory { stat, path } => {
                    let path = if let Some(target_path) = target_path {
                        Path::new(target_path).join(path)
                    } else {
                        path
                    };
                    fs.create_dir_all(path, 0, 0, stat.st_mode).await?;
                    Ok(None)
                }
                Object::RegularFile { fd, stat, path } => {
                    let path = if let Some(target_path) = target_path {
                        Path::new(target_path).join(path)
                    } else {
                        path
                    };
                    let mut rd = HashingReader::<blake3::Hasher, _>::new(smol::fs::File::from(fd));
                    let file = fs
                        .create_file(&mut rd, 0, 0, stat.st_mode, Some(stat.st_size as usize))
                        .await?;
                    file.persist(path).await?;
                    Ok(Some(rd.into_hash_output()))
                }
            }
        })
        .await
        .map(|(hash, _)| hash)
    }

    pub(super) async fn hash_dir(fd: OwnedFd) -> io::Result<(Hash, u64)> {
        let pool = SmallBlockingPool::new(num_cpus::get().saturating_mul(2), "hash-pool");
        process(fd, &|obj| async {
            match obj {
                Object::Symlink { .. } => Ok(None),
                Object::Directory { .. } => Ok(None),
                Object::RegularFile { fd, stat, path } => {
                    let mut hasher = NodeHasher::new();
                    let hash = if stat.st_size < 16 * 1024 {
                        hasher.update_reader(std::fs::File::from(fd))?;
                        Ok(hasher.finalize_fixed())
                    } else {
                        pool.spawn(move || {
                            let map = unsafe { memmap2::Mmap::map(fd.as_raw_fd()) }?;
                            map.advise(memmap2::Advice::Sequential)?;
                            hasher.update(&map[..]);
                            Ok::<_, io::Error>(hasher.finalize_fixed())
                        })
                        .await
                    }
                    .map_err(|err| {
                        io::Error::other(format!("failed to hash file {}: {}", path.display(), err))
                    })?;
                    Ok(Some(hash))
                }
            }
        })
        .await
    }

    async fn process<F, Fut>(fd: OwnedFd, f: &F) -> io::Result<(Hash, u64)>
    where
        F: Fn(Object) -> Fut,
        Fut: std::future::Future<Output = io::Result<Option<NodeHash>>>,
    {
        let (hash, size) = process_fs_object(
            PathBuf::from_str("").unwrap().as_ref(),
            fd,
            OsStr::from_bytes(b".").to_owned(),
            f,
        )
        .await?;
        Ok((Hash::new_from_hash::<NodeHasher>(hash), size))
    }

    async fn process_fs_object<F, Fut>(
        parent: &Path,
        parent_dfd: impl AsFd,
        name: OsString,
        f: &F,
    ) -> io::Result<(NodeHash, u64)>
    where
        F: Fn(Object) -> Fut,
        Fut: std::future::Future<Output = io::Result<Option<NodeHash>>>,
    {
        let fd = match openat2(
            parent_dfd.as_fd(),
            &name,
            OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        ) {
            Ok(fd) => fd,
            Err(Errno::LOOP) => openat2(
                parent_dfd.as_fd(),
                &name,
                OFlags::CLOEXEC | OFlags::PATH | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )?,
            Err(err) => return Err(err.into()),
        };
        let stat = fstat(&fd)?;
        let path = parent.join(&name);
        let mut hasher = NodeHasher::new();
        hasher.update(&mode(stat.st_mode).to_le_bytes());
        hasher.update(name.as_encoded_bytes());
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => {
                let file_hash = f(Object::RegularFile { path, stat, fd })
                    .await?
                    .expect("file hash");
                hasher.update(&file_hash);
                Ok((hasher.finalize_fixed(), stat.st_size as u64))
            }
            FileType::Symlink => {
                let target = readlinkat(&fd, c"", [])?;
                hasher.update(target.as_bytes());
                f(Object::Symlink { path, target }).await?;
                Ok((hasher.finalize_fixed(), 1))
            }
            FileType::Directory => {
                let (dir_hash, dir_size) = process_dir(path.clone(), fd, f).await?;
                hasher.update(&dir_hash);
                f(Object::Directory { path, stat }).await?;
                Ok((hasher.finalize_fixed(), dir_size))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported file type",
            )),
        }
    }

    async fn process_dir<F, Fut>(path: PathBuf, fd: OwnedFd, f: &F) -> io::Result<(NodeHash, u64)>
    where
        F: Fn(Object) -> Fut,
        Fut: std::future::Future<Output = io::Result<Option<NodeHash>>>,
    {
        let dir = Dir::read_from(&fd)?;
        let mut entries = dir
            .filter_ok(|entry| entry.file_name() != c"." && entry.file_name() != c"..")
            .map_ok(|entry| OsStr::from_bytes(entry.file_name().to_bytes()).to_owned())
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));
        let (hasher, size) = stream::iter(
            entries
                .into_iter()
                .map(|entry| process_fs_object(&path, &fd, entry, f)),
        )
        .buffered(16)
        .try_fold(
            (NodeHasher::new(), 0u64),
            |(mut hasher, size), (hash, s)| async move {
                hasher.update(&hash);
                Ok((hasher, size + s))
            },
        )
        .await?;
        Ok((hasher.finalize_fixed(), size))
    }
}
