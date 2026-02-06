use {
    crate::{
        comp::{comp_reader, is_comp_ext, is_tar_ext, tar_reader},
        content::ContentProvider,
        hash::{AsyncHashingRead, Hash, HashAlgo, Hashable, HashingReader},
        is_url,
        staging::{FileList, Stage, StagingFile, StagingFileSystem},
        tar,
    },
    clap::Args,
    rustix::{
        fd::{AsRawFd, OwnedFd},
        fs::{fstat, openat, FileType, Mode, OFlags, CWD},
    },
    serde::{Deserialize, Serialize},
    smol::{io::AsyncRead, stream::StreamExt},
    std::{
        borrow::Cow,
        future::Future,
        io,
        num::NonZero,
        path::Path,
        pin::{pin, Pin},
    },
};

#[derive(Args)]
pub struct ArtifactArg {
    /// Target file mode (only if artifact is a single file)
    #[arg(long = "mode", value_name = "MODE")]
    pub mode: Option<NonZero<u32>>,
    /// Do not unpack (disables auto-unpacking of tar archives and compressed files)
    #[arg(long = "no-unpack", action)]
    pub do_not_unpack: bool,
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
pub struct TarReader<'a, R: AsyncRead + Send + 'a, FS: ?Sized> {
    target: Option<String>,
    inner: tar::TarReader<'a, R>,
    _marker: std::marker::PhantomData<fn(&FS)>,
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
pub struct TreeReader<FS: ?Sized> {
    target: Option<String>,
    dir: OwnedFd,
    hash: Hash,
    _marker: std::marker::PhantomData<fn(&FS)>,
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
pub struct FileReader<'a, R: AsyncRead + Send + 'a, FS: ?Sized> {
    target: String,
    inner: R,
    mode: Option<NonZero<u32>>,
    uri: String,
    unpack: bool,
    size: Option<NonZero<usize>>,
    _marker: std::marker::PhantomData<&'a ()>,
    _marker_fs: std::marker::PhantomData<fn(&FS)>,
}

impl Artifact {
    pub(crate) async fn new<C>(artifact: &ArtifactArg, cache: &C) -> io::Result<Self>
    where
        C: ContentProvider,
    {
        let uri = artifact.url.clone();
        let target = artifact.target.clone();
        let unpack = if artifact.do_not_unpack {
            Some(false)
        } else {
            None
        };
        let arch = artifact.target_arch.clone();
        if is_url(&uri) {
            let mut artifact = if unpack.unwrap_or(true) && is_tar_ext(uri.as_bytes()) {
                Artifact::Tar(Tar {
                    arch,
                    uri,
                    hash: Hash::default(),
                    size: 0,
                    target,
                })
            } else {
                Artifact::File(File {
                    arch,
                    uri,
                    hash: Hash::default(),
                    size: 0,
                    target: target.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "target must be specified for a file",
                        )
                    })?,
                    mode: artifact.mode,
                    unpack,
                })
            };
            cache.ensure_artifact(&mut artifact).await?;
            Ok(artifact)
        } else {
            let path = cache.resolve_path(&artifact.url).await?;
            let mut artifact = if smol::fs::symlink_metadata(&path).await?.is_dir() {
                Artifact::Dir(Tree {
                    arch,
                    path: uri,
                    hash: Hash::default(),
                    size: 0,
                    target,
                })
            } else if unpack.unwrap_or(true) && is_tar_ext(path.as_os_str().as_encoded_bytes()) {
                Artifact::Tar(Tar {
                    arch,
                    uri,
                    hash: Hash::default(),
                    size: 0,
                    target,
                })
            } else {
                Artifact::File(File {
                    arch,
                    uri,
                    hash: Hash::default(),
                    size: 0,
                    target: target.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "target must be specified for a file",
                        )
                    })?,
                    mode: artifact.mode,
                    unpack,
                })
            };
            cache.ensure_artifact(&mut artifact).await?;
            Ok(artifact)
        }
    }
    pub fn is_remote(&self) -> bool {
        match &self {
            Artifact::Tar(inner) => is_url(&inner.uri),
            Artifact::File(inner) => is_url(&inner.uri),
            Artifact::Dir(_) => false,
        }
    }
    pub fn is_local(&self) -> bool {
        !self.is_remote()
    }
    pub async fn hash_remote<R: AsyncRead + Send + 'static>(
        &mut self,
        r: R,
    ) -> io::Result<(Hash, u64)> {
        match self {
            Artifact::Dir(_) => Err(io::Error::other(
                "directory artifacts do not support remote readers",
            )),
            Artifact::Tar(inner) => inner.hash_remote(r).await,
            Artifact::File(inner) => inner.hash_remote(r).await,
        }
    }
    pub async fn hash_stage_remote<
        R: AsyncRead + Send + 'static,
        FS: StagingFileSystem + ?Sized + 'static,
    >(
        &mut self,
        r: R,
        fs: &FS,
    ) -> io::Result<(Hash, u64)> {
        match self {
            Artifact::Dir(_) => Err(io::Error::other(
                "directory artifacts do not support remote readers",
            )),
            Artifact::Tar(inner) => inner.hash_stage_remote(r, fs).await,
            Artifact::File(inner) => inner.hash_stage_remote(r, fs).await,
        }
    }
    pub fn remote<R: AsyncRead + Send + 'static, FS: StagingFileSystem + ?Sized + 'static>(
        &self,
        r: R,
    ) -> io::Result<Box<dyn Stage<Target = FS, Output = ()> + Send>> {
        match &self {
            Artifact::Dir(_) => Err(io::Error::other(
                "directory artifacts do not support remote readers",
            )),
            Artifact::Tar(inner) => inner.remote(r),
            Artifact::File(inner) => inner.remote(r),
        }
    }
    pub async fn hash_stage_local<P: AsRef<Path>, FS: StagingFileSystem + ?Sized>(
        &mut self,
        path: P,
        fs: &FS,
    ) -> io::Result<(Hash, u64)> {
        match self {
            Artifact::Dir(inner) => inner.hash_stage_local(path, fs).await,
            Artifact::Tar(inner) => inner.hash_stage_local(path, fs).await,
            Artifact::File(inner) => inner.hash_stage_local(path, fs).await,
        }
    }
    pub async fn hash_local<P: AsRef<Path>>(&mut self, path: P) -> io::Result<(Hash, u64)> {
        match self {
            Artifact::Dir(inner) => inner.hash_local(path).await,
            Artifact::Tar(inner) => inner.hash_local(path).await,
            Artifact::File(inner) => inner.hash_local(path).await,
        }
    }
    pub async fn local<P: AsRef<Path>, FS: StagingFileSystem + ?Sized + 'static>(
        &self,
        path: P,
    ) -> io::Result<Box<dyn Stage<Target = FS, Output = ()> + Send>> {
        match self {
            Artifact::Dir(inner) => inner.local(path).await,
            Artifact::Tar(inner) => inner.local(path).await,
            Artifact::File(inner) => inner.local(path).await,
        }
    }
    pub fn hash(&self) -> &Hash {
        match self {
            Artifact::Tar(inner) => &inner.hash,
            Artifact::Dir(inner) => &inner.hash,
            Artifact::File(inner) => &inner.hash,
        }
    }
    pub fn size(&self) -> u64 {
        match self {
            Artifact::Tar(inner) => inner.size,
            Artifact::Dir(inner) => inner.size,
            Artifact::File(inner) => inner.size,
        }
    }
    pub fn uri(&self) -> &str {
        match self {
            Artifact::Tar(inner) => &inner.uri,
            Artifact::Dir(inner) => &inner.path,
            Artifact::File(inner) => &inner.uri,
        }
    }
    pub fn target(&self) -> Option<&str> {
        match self {
            Artifact::Tar(inner) => inner.target.as_deref(),
            Artifact::Dir(inner) => inner.target.as_deref(),
            Artifact::File(inner) => Some(&inner.target),
        }
    }
    pub fn update_spec_hash<H: HashAlgo>(&self, hasher: &mut H) {
        match self {
            Artifact::Tar(inner) => inner.update_spec_hash(hasher),
            Artifact::Dir(inner) => inner.update_spec_hash(hasher),
            Artifact::File(inner) => inner.update_spec_hash(hasher),
        }
    }
    pub fn arch(&self) -> Option<&str> {
        match self {
            Artifact::Tar(inner) => inner.arch.as_deref(),
            Artifact::Dir(inner) => inner.arch.as_deref(),
            Artifact::File(inner) => inner.arch.as_deref(),
        }
    }
    pub(crate) fn with_uri<S: Into<String>>(mut self, uri: S) -> Self {
        match &mut self {
            Artifact::Tar(inner) => inner.uri = uri.into(),
            Artifact::Dir(inner) => inner.path = uri.into(),
            Artifact::File(inner) => inner.uri = uri.into(),
        }
        self
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
    fn update_spec_hash<H: HashAlgo>(&self, hasher: &mut H) {
        "tar".hash_into(hasher);
        if let Some(arch) = self.arch.as_deref() {
            true.hash_into(hasher);
            arch.hash_into(hasher);
        } else {
            false.hash_into(hasher);
        }
        self.uri.hash_into(hasher);
        if let Some(target) = self.target.as_deref() {
            true.hash_into(hasher);
            target.hash_into(hasher);
        } else {
            false.hash_into(hasher);
        }
        self.hash.as_bytes().hash_into(hasher);
    }
    pub async fn local<P: AsRef<Path>, FS: StagingFileSystem + ?Sized + 'static>(
        &self,
        path: P,
    ) -> io::Result<Box<dyn Stage<Target = FS, Output = ()> + Send>> {
        let r = smol::fs::File::open(path.as_ref()).await.map_err(|err| {
            io::Error::other(format!(
                "failed to open local tar file {}: {}",
                path.as_ref().display(),
                err
            ))
        })?;
        Ok(Box::new(tar_reader(&self.uri, r).map(|inner| TarReader {
            inner,
            target: self.target.clone(),
            _marker: std::marker::PhantomData,
        })?)
            as Box<dyn Stage<Target = FS, Output = ()> + Send>)
    }
    async fn hash_stage_local<P: AsRef<Path>, FS: StagingFileSystem + ?Sized>(
        &mut self,
        path: P,
        fs: &FS,
    ) -> io::Result<(Hash, u64)> {
        let file = smol::fs::File::open(path.as_ref()).await.map_err(|err| {
            io::Error::other(format!(
                "failed to open local tar file {}: {}",
                path.as_ref().display(),
                err
            ))
        })?;
        self.hash_stage_remote(file, fs).await
    }
    async fn hash_local<P: AsRef<Path>>(&mut self, path: P) -> io::Result<(Hash, u64)> {
        let file = smol::fs::File::open(path.as_ref()).await.map_err(|err| {
            io::Error::other(format!(
                "failed to open local tar file {}: {}",
                path.as_ref().display(),
                err
            ))
        })?;
        self.hash_remote(file).await
    }
    fn remote<R: AsyncRead + Send + 'static, FS: StagingFileSystem + ?Sized + 'static>(
        &self,
        r: R,
    ) -> io::Result<Box<dyn Stage<Target = FS, Output = ()> + Send>> {
        Ok(Box::new(tar_reader(&self.uri, r).map(|inner| TarReader {
            inner,
            target: self.target.clone(),
            _marker: std::marker::PhantomData,
        })?)
            as Box<dyn Stage<Target = FS, Output = ()> + Send>)
    }
    async fn hash_stage_remote<R: AsyncRead + Send + 'static, FS: StagingFileSystem + ?Sized>(
        &mut self,
        r: R,
        fs: &FS,
    ) -> io::Result<(Hash, u64)> {
        let mut reader = pin!(HashingReader::<blake3::Hasher, _>::new(r));
        TarReader {
            inner: tar_reader(&self.uri, &mut reader)?,
            target: self.target.clone(),
            _marker: std::marker::PhantomData,
        }
        .stage(fs)
        .await?;
        self.size = reader.as_mut().size();
        self.hash = reader.as_mut().hash();
        Ok((self.hash.clone(), self.size))
    }
    async fn hash_remote<R: AsyncRead + Send + 'static>(
        &mut self,
        r: R,
    ) -> io::Result<(Hash, u64)> {
        let mut reader = pin!(HashingReader::<blake3::Hasher, _>::new(r));
        TarReader {
            inner: tar_reader(&self.uri, &mut reader)?,
            target: self.target.clone(),
            _marker: std::marker::PhantomData,
        }
        .stage(&FileList::new())
        .await?;
        self.size = reader.as_mut().size();
        self.hash = reader.as_mut().hash();
        Ok((self.hash.clone(), self.size))
    }
}

impl<'a, R, FS> Stage for TarReader<'a, R, FS>
where
    R: AsyncRead + Send + 'a,
    FS: StagingFileSystem + ?Sized,
{
    type Target = FS;
    type Output = ();
    fn stage<'b>(
        &'b mut self,
        fs: &'b Self::Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'b>> {
        Box::pin(self.extract_to(fs))
    }
}

impl<'a, R, FS> TarReader<'a, R, FS>
where
    R: AsyncRead + Send + 'a,
    FS: StagingFileSystem + ?Sized,
{
    async fn extract_to(&mut self, fs: &FS) -> io::Result<()> {
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
                _ => {
                    return Err(io::Error::other(format!(
                        "unsupported tar entry in artifact {} {:?}",
                        &self.target.as_deref().unwrap_or("<no-target>"),
                        &entry,
                    )));
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
    fn update_spec_hash<H: HashAlgo>(&self, hasher: &mut H) {
        "dir".hash_into(hasher);
        if let Some(arch) = self.arch.as_deref() {
            true.hash_into(hasher);
            arch.hash_into(hasher);
        } else {
            false.hash_into(hasher);
        }
        self.path.hash_into(hasher);
        if let Some(target) = self.target.as_deref() {
            true.hash_into(hasher);
            target.hash_into(hasher);
        } else {
            false.hash_into(hasher);
        }
        self.hash.as_bytes().hash_into(hasher);
    }
    async fn hash_stage_local<P: AsRef<Path>, FS: StagingFileSystem + ?Sized>(
        &mut self,
        path: P,
        fs: &FS,
    ) -> io::Result<(Hash, u64)> {
        let fd = openat(
            CWD,
            path.as_ref(),
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|err| {
            io::Error::other(format!(
                "failed to open local artifact directory {}: {}",
                path.as_ref().display(),
                err
            ))
        })?;
        let (hash, size) =
            tree::copy_hash_dir_inner::<blake3::Hasher, _, _>(&fd, fs, self.target.as_deref())
                .await
                .map(|(hash, size)| (hash.hash(), size))?;
        self.hash = hash.clone();
        self.size = size;
        Ok((hash, size))
    }
    async fn hash_local<P: AsRef<Path>>(&mut self, path: P) -> io::Result<(Hash, u64)> {
        let fd = openat(
            CWD,
            path.as_ref(),
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let (hash, size) = tree::hash_dir_inner::<blake3::Hasher>(fd)
            .await
            .map(|(hash, size)| (hash.hash(), size))?;
        self.hash = hash.clone();
        self.size = size;
        Ok((hash, size))
    }
    async fn local<P: AsRef<Path>, FS: StagingFileSystem + ?Sized + 'static>(
        &self,
        path: P,
    ) -> io::Result<Box<dyn Stage<Target = FS, Output = ()> + Send>> {
        let fd = openat(
            CWD,
            path.as_ref(),
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        Ok(Box::new(TreeReader {
            dir: fd,
            target: self.target.clone(),
            hash: self.hash.clone(),
            _marker: std::marker::PhantomData,
        })
            as Box<dyn Stage<Target = FS, Output = ()> + Send>)
    }
}

pub(crate) async fn hash_directory<P: AsRef<Path>>(path: P, hash: &str) -> io::Result<(Hash, u64)> {
    let fd = openat(
        CWD,
        path.as_ref(),
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|err| {
        io::Error::other(format!(
            "failed to open directory {}: {}",
            path.as_ref().display(),
            err
        ))
    })?;
    tree::hash_dir(fd, hash).await
}

impl<FS> Stage for TreeReader<FS>
where
    FS: StagingFileSystem + ?Sized,
{
    type Target = FS;
    type Output = ();
    fn stage<'b>(
        &'b mut self,
        fs: &'b Self::Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'b>> {
        Box::pin(async move {
            if let Some(parent) = self.target.as_deref().and_then(|t| Path::new(t).parent()) {
                fs.create_dir_all(parent, 0, 0, 0o755).await?;
            }
            let (hash, _) =
                tree::copy_hash_dir(&self.dir, fs, self.target.as_deref(), self.hash.name())
                    .await?;
            if hash != self.hash {
                Err(io::Error::other("hash mismatch after copying local tree"))
            } else {
                Ok(())
            }
        })
    }
}

impl File {
    fn update_spec_hash<H: HashAlgo>(&self, hasher: &mut H) {
        "file".hash_into(hasher);
        if let Some(arch) = self.arch.as_deref() {
            true.hash_into(hasher);
            arch.hash_into(hasher);
        } else {
            false.hash_into(hasher);
        }
        self.uri.hash_into(hasher);
        self.target.hash_into(hasher);
        let mode = self.mode.map_or(0o644, |m| m.get() & 0o7777);
        mode.hash_into(hasher);
        self.unpack.unwrap_or(true).hash_into(hasher);
    }
    async fn local<P: AsRef<Path>, FS: StagingFileSystem + ?Sized + 'static>(
        &self,
        path: P,
    ) -> io::Result<Box<dyn Stage<Target = FS, Output = ()> + Send>> {
        let r = smol::fs::File::open(path.as_ref()).await.map_err(|err| {
            io::Error::other(format!(
                "failed to open local artifact file {}: {}",
                path.as_ref().display(),
                err
            ))
        })?;
        Ok(Box::new(FileReader {
            inner: self.hash.reader(self.size, r),
            target: self.target.clone(),
            mode: self.mode,
            uri: self.uri.clone(),
            unpack: self.unpack.unwrap_or(true),
            size: Some(NonZero::new(self.size as usize).unwrap()),
            _marker: std::marker::PhantomData,
            _marker_fs: std::marker::PhantomData,
        })
            as Box<dyn Stage<Target = FS, Output = ()> + Send>)
    }
    async fn hash_stage_local<P: AsRef<Path>, FS: StagingFileSystem + ?Sized>(
        &mut self,
        path: P,
        fs: &FS,
    ) -> io::Result<(Hash, u64)> {
        let fd = openat(
            CWD,
            path.as_ref(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|err| {
            io::Error::other(format!(
                "failed to open local artifact file {}: {}",
                path.as_ref().display(),
                err
            ))
        })?;
        let stat = fstat(&fd)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(io::Error::other(format!(
                "artefact file {} ({}) is not a regular file",
                &self.uri,
                path.as_ref().display()
            )));
        }
        let st_mode = stat.st_mode & 0o7777;
        if st_mode == 0 {
            return Err(io::Error::other(format!(
                "file {} has invalid permissions set {:0o}",
                &self.uri, st_mode,
            )));
        }
        if self.mode.is_none() && st_mode != 0o644 {
            self.mode = Some(NonZero::new(st_mode as u32).unwrap());
        }
        self.hash_stage_remote(smol::fs::File::from(fd), fs).await
    }
    async fn hash_local<P: AsRef<Path>>(&mut self, path: P) -> io::Result<(Hash, u64)> {
        let fd = openat(
            CWD,
            path.as_ref(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|err| {
            io::Error::other(format!(
                "failed to open local artifact file {}: {}",
                path.as_ref().display(),
                err
            ))
        })?;
        let stat = fstat(&fd)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(io::Error::other(format!(
                "artefact file {} ({}) is not a regular file",
                &self.uri,
                path.as_ref().display()
            )));
        }
        let st_mode = stat.st_mode & 0o7777;
        if st_mode == 0 {
            return Err(io::Error::other(format!(
                "file {} has invalid permissions set {:0o}",
                &self.uri, st_mode,
            )));
        }
        if self.mode.is_none() && st_mode != 0o644 {
            self.mode = Some(NonZero::new(st_mode as u32).unwrap());
        }
        let (hash, size) = if stat.st_size < 65_536 {
            let mut reader = HashingReader::<blake3::Hasher, _>::new(smol::fs::File::from(fd));
            smol::io::copy(&mut reader, smol::io::sink()).await?;
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
        self.hash = hash.clone();
        self.size = size;
        Ok((hash, size))
    }
    async fn hash_stage_remote<R: AsyncRead + Send + 'static, FS: StagingFileSystem + ?Sized>(
        &mut self,
        r: R,
        fs: &FS,
    ) -> io::Result<(Hash, u64)> {
        let st_mode = self.mode.map_or(0o644, |m| m.get() & 0o7777);
        let mut reader = pin!(HashingReader::<blake3::Hasher, _>::new(r));
        if let Some(parent) = Path::new(&self.target).parent() {
            fs.create_dir_all(parent, 0, 0, 0o755).await?;
        }
        if self.unpack.unwrap_or(true) && is_comp_ext(&self.uri) {
            fs.create_file(comp_reader(&self.uri, &mut reader), 0, 0, st_mode, None)
                .await?
        } else {
            fs.create_file(&mut reader, 0, 0, st_mode, None).await?
        }
        .persist(&self.target)
        .await?;
        self.size = reader.as_mut().size();
        self.hash = reader.as_mut().hash();
        Ok((self.hash.clone(), self.size))
    }
    async fn hash_remote<R: AsyncRead + Send + 'static>(
        &mut self,
        r: R,
    ) -> io::Result<(Hash, u64)> {
        let mut reader = pin!(HashingReader::<blake3::Hasher, _>::new(r));
        smol::io::copy(&mut reader, smol::io::sink()).await?;
        self.size = reader.as_mut().size();
        self.hash = reader.as_mut().hash();
        Ok((self.hash.clone(), self.size))
    }
    fn remote<R: AsyncRead + Send + 'static, FS: StagingFileSystem + ?Sized + 'static>(
        &self,
        r: R,
    ) -> io::Result<Box<dyn Stage<Target = FS, Output = ()> + Send>> {
        Ok(Box::new(FileReader {
            inner: self.hash.reader(self.size, r),
            target: self.target.clone(),
            mode: self.mode,
            uri: self.uri.clone(),
            unpack: self.unpack.unwrap_or(true),
            size: Some(NonZero::new(self.size as usize).unwrap()),
            _marker: std::marker::PhantomData,
            _marker_fs: std::marker::PhantomData,
        })
            as Box<dyn Stage<Target = FS, Output = ()> + Send>)
    }
}

impl<'a, R, FS> Stage for FileReader<'a, R, FS>
where
    R: AsyncRead + Send + Unpin + 'a,
    FS: StagingFileSystem + ?Sized,
{
    type Target = FS;
    type Output = ();
    fn stage<'b>(
        &'b mut self,
        fs: &'b Self::Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'b>> {
        Box::pin(async move {
            if let Some(parent) = Path::new(&self.target).parent() {
                fs.create_dir_all(parent, 0, 0, 0o755).await?;
            }
            if self.unpack && is_comp_ext(self.uri.as_bytes()) {
                fs.create_file(
                    comp_reader(&self.uri, &mut self.inner),
                    0,
                    0,
                    self.mode.map_or(0o644, |m| m.get() & 0o7777),
                    None,
                )
                .await?
                .persist(&self.target)
                .await
            } else {
                fs.create_file(
                    &mut self.inner,
                    0,
                    0,
                    self.mode.map_or(0o644, |m| m.get() & 0o7777),
                    self.size.map(|s| s.get()),
                )
                .await?
                .persist(&self.target)
                .await
            }
        })
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
            hash::{Hash, HashAlgo, HashingReader, InnerHash},
            StagingFile, StagingFileSystem,
        },
        async_channel as chan,
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

    pub(super) async fn copy_hash_dir<Fd: AsFd, FS: StagingFileSystem + ?Sized>(
        fd: Fd,
        fs: &FS,
        target_path: Option<&str>,
        hash: &str,
    ) -> io::Result<(Hash, u64)> {
        match hash {
            md5::Md5::NAME => copy_hash_dir_inner::<md5::Md5, _, _>(fd, fs, target_path)
                .await
                .map(|(hash, size)| (hash.hash(), size)),
            sha1::Sha1::NAME => copy_hash_dir_inner::<sha1::Sha1, _, _>(fd, fs, target_path)
                .await
                .map(|(hash, size)| (hash.hash(), size)),
            sha2::Sha256::NAME => {
                copy_hash_dir_inner::<sha2::Sha256, _, _>(fd, fs, target_path)
                    .await
                    .map(|(hash, size)| (hash.hash(), size))
            }
            sha2::Sha512::NAME => {
                copy_hash_dir_inner::<sha2::Sha512, _, _>(fd, fs, target_path)
                    .await
                    .map(|(hash, size)| (hash.hash(), size))
            }
            blake3::Hasher::NAME => {
                copy_hash_dir_inner::<blake3::Hasher, _, _>(fd, fs, target_path)
                    .await
                    .map(|(hash, size)| (hash.hash(), size))
            }
            _ => io::Result::Err(io::Error::other(format!(
                "unsupported hash algorithm for directory artifact: {hash}"
            ))),
        }
    }

    pub(super) async fn copy_hash_dir_inner<
        H: HashAlgo,
        Fd: AsFd,
        FS: StagingFileSystem + ?Sized,
    >(
        fd: Fd,
        fs: &FS,
        target_path: Option<&str>,
    ) -> io::Result<(InnerHash<H>, u64)> {
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
                    let mut rd = HashingReader::<H, _>::new(smol::fs::File::from(fd));
                    let file = fs
                        .create_file(&mut rd, 0, 0, stat.st_mode, Some(stat.st_size as usize))
                        .await?;
                    file.persist(path).await?;
                    let hash: InnerHash<H> = rd.into_hash_output().into();
                    Ok(Some(hash))
                }
            }
        })
        .await
    }

    pub(super) async fn hash_dir(fd: OwnedFd, hash: &str) -> io::Result<(Hash, u64)> {
        match hash {
            md5::Md5::NAME => hash_dir_inner::<md5::Md5>(fd)
                .await
                .map(|(hash, size)| (hash.hash(), size)),
            sha1::Sha1::NAME => hash_dir_inner::<sha1::Sha1>(fd)
                .await
                .map(|(hash, size)| (hash.hash(), size)),
            sha2::Sha256::NAME => hash_dir_inner::<sha2::Sha256>(fd)
                .await
                .map(|(hash, size)| (hash.hash(), size)),
            sha2::Sha512::NAME => hash_dir_inner::<sha2::Sha512>(fd)
                .await
                .map(|(hash, size)| (hash.hash(), size)),
            blake3::Hasher::NAME => hash_dir_inner::<blake3::Hasher>(fd)
                .await
                .map(|(hash, size)| (hash.hash(), size)),
            _ => io::Result::Err(io::Error::other(format!(
                "unsupported hash algorithm for directory artifact: {hash}"
            ))),
        }
    }

    pub(super) async fn hash_dir_inner<H: HashAlgo + 'static>(
        fd: OwnedFd,
    ) -> io::Result<(InnerHash<H>, u64)> {
        let pool = SmallBlockingPool::new(num_cpus::get().saturating_mul(2), "hash-pool");
        process(fd, &|obj| async {
            match obj {
                Object::Symlink { .. } => Ok(None),
                Object::Directory { .. } => Ok(None),
                Object::RegularFile { fd, stat, path } => {
                    let hash = if stat.st_size < 16 * 1024 {
                        let mut reader = HashingReader::<H, _>::new(smol::fs::File::from(fd));
                        smol::io::copy(&mut reader, smol::io::sink()).await?;
                        Ok(reader.into_hash_output().into())
                    } else {
                        let mut hasher = H::default();
                        pool.spawn(move || {
                            let map = unsafe { memmap2::Mmap::map(fd.as_raw_fd()) }?;
                            map.advise(memmap2::Advice::Sequential)?;
                            hasher.update(&map[..]);
                            Ok::<_, io::Error>(hasher.finalize_fixed().into())
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

    async fn process<H, Fd, F, Fut>(fd: Fd, f: &F) -> io::Result<(InnerHash<H>, u64)>
    where
        H: HashAlgo,
        Fd: AsFd,
        F: Fn(Object) -> Fut,
        Fut: std::future::Future<Output = io::Result<Option<InnerHash<H>>>>,
    {
        process_fs_object(
            PathBuf::from_str("").unwrap().as_ref(),
            fd,
            OsStr::from_bytes(b".").to_owned(),
            f,
        )
        .await
    }

    async fn process_fs_object<H, F, Fut>(
        parent: &Path,
        parent_dfd: impl AsFd,
        name: OsString,
        f: &F,
    ) -> io::Result<(InnerHash<H>, u64)>
    where
        H: HashAlgo,
        F: Fn(Object) -> Fut,
        Fut: std::future::Future<Output = io::Result<Option<InnerHash<H>>>>,
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
        let mut hasher = H::default();
        hasher.update(&mode(stat.st_mode).to_le_bytes());
        hasher.update(name.as_encoded_bytes());
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => {
                let file_hash = f(Object::RegularFile { path, stat, fd })
                    .await?
                    .expect("file hash");
                hasher.update(file_hash.as_bytes());
                Ok((hasher.finalize_fixed().into(), stat.st_size as u64))
            }
            FileType::Symlink => {
                let target = readlinkat(&fd, c"", [])?;
                hasher.update(target.as_bytes());
                f(Object::Symlink { path, target }).await?;
                Ok((hasher.finalize_fixed().into(), 1))
            }
            FileType::Directory => {
                f(Object::Directory {
                    path: path.clone(),
                    stat,
                })
                .await?;
                let (dir_hash, dir_size) = process_dir::<H, _, _>(path, fd, f).await?;
                hasher.update(dir_hash.as_bytes());
                Ok((hasher.finalize_fixed().into(), dir_size))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported file type",
            )),
        }
    }

    async fn process_dir<H, F, Fut>(
        path: PathBuf,
        fd: OwnedFd,
        f: &F,
    ) -> io::Result<(InnerHash<H>, u64)>
    where
        H: HashAlgo,
        F: Fn(Object) -> Fut,
        Fut: std::future::Future<Output = io::Result<Option<InnerHash<H>>>>,
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
                .map(|entry| process_fs_object::<H, _, _>(&path, &fd, entry, f)),
        )
        .buffered(16)
        .try_fold(
            (H::default(), 0u64),
            |(mut hasher, size), (hash, s)| async move {
                hasher.update(hash.as_bytes());
                Ok((hasher, size + s))
            },
        )
        .await?;
        Ok((hasher.finalize_fixed().into(), size))
    }
}
