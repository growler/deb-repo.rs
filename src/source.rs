use {
    crate::{
        control::MutableControlStanza, deb::DebReader, hash::FileHash, release::Release,
        TransportProvider,
    },
    chrono::{DateTime, FixedOffset, Local, NaiveDateTime, Utc},
    clap::Args,
    futures::{future::try_join_all, AsyncReadExt},
    iterator_ext::IteratorExt,
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    smol::{fs, io, lock::Semaphore},
    std::{
        path::{Path, PathBuf},
        sync::Arc,
    },
};

pub const DEBIAN_KEYRING: &[u8] = include_bytes!("../keyring/keys.bin");

fn default_components() -> Vec<String> {
    vec!["main".to_string()]
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum SignedBy {
    #[default]
    Builtin,
    Key(String),
    Keyring(PathBuf),
}

impl SignedBy {
    pub const MAX_KEY_SIZE: usize = 64 * 1024; // 64 KiB
    async fn import_into(&self, ctx: &mut gpgme::Context) -> io::Result<()> {
        match self {
            Self::Builtin => {
                ctx.import(DEBIAN_KEYRING)?;
            }
            Self::Key(key) => {
                ctx.import(key.as_bytes())?;
            }
            Self::Keyring(path) => {
                let size = fs::metadata(path).await.and_then(|md| {
                    if md.is_file() {
                        let size = md.len();
                        if size <= Self::MAX_KEY_SIZE as u64 {
                            Ok(size)
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "the key file is too large",
                            ))
                        }
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "the key is not a regular file",
                        ))
                    }
                })?;
                let mut buf = Vec::with_capacity(size as usize);
                fs::File::open(path).await?.read_to_end(&mut buf).await?;
                ctx.import(buf)?;
            }
        }
        Ok(())
    }
}

impl From<&Path> for SignedBy {
    fn from(p: &Path) -> Self {
        SignedBy::Keyring(p.to_path_buf())
    }
}

impl From<&PathBuf> for SignedBy {
    fn from(p: &PathBuf) -> Self {
        Self::from(p.as_path())
    }
}

impl serde::ser::Serialize for SignedBy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SignedBy::Builtin => serializer.serialize_none(),
            SignedBy::Key(s) => serializer.serialize_str(s),
            SignedBy::Keyring(s) => serializer.serialize_str(&s.to_string_lossy()),
        }
    }
}

impl From<&SignedBy> for String {
    fn from(s: &SignedBy) -> Self {
        match s {
            SignedBy::Builtin => "builtin".to_string(),
            SignedBy::Key(s) => s.clone(),
            SignedBy::Keyring(s) => s.to_string_lossy().into_owned(),
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for SignedBy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SignedByVisitor;

        impl<'de> serde::de::Visitor<'de> for SignedByVisitor {
            type Value = SignedBy;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a string containing either a PGP public key block or a path to keyring file"
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let s = v.trim().to_string();
                if s.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
                    Ok(SignedBy::Key(s))
                } else {
                    Ok(SignedBy::Keyring(s.into()))
                }
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                let v = v.trim();
                if v.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
                    Ok(SignedBy::Key(v.to_string()))
                } else {
                    Ok(SignedBy::Keyring(v.into()))
                }
            }
        }

        deserializer.deserialize_string(SignedByVisitor)
    }
}

#[derive(Clone)]
struct ClapSignedByParser;

impl clap::builder::TypedValueParser for ClapSignedByParser {
    type Value = SignedBy;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        if let [b'@', rest @ ..] = value.as_encoded_bytes() {
            let path = Path::new(unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(rest) });
            let key_data = std::fs::read_to_string(path).map_err(|e| {
                let mut err =
                    clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        clap::error::ContextKind::InvalidArg,
                        clap::error::ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    clap::error::ContextKind::InvalidValue,
                    clap::error::ContextValue::String(value.to_string_lossy().into()),
                );
                err.insert(
                    clap::error::ContextKind::Custom,
                    clap::error::ContextValue::String(e.to_string()),
                );
                err
            })?;
            let trimmed = key_data.trim();
            const HDR: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
            const FTR: &str = "-----END PGP PUBLIC KEY BLOCK-----";
            if trimmed.starts_with(HDR) && trimmed.ends_with(FTR) {
                Ok(SignedBy::Key(key_data))
            } else {
                let mut err =
                    clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        clap::error::ContextKind::InvalidArg,
                        clap::error::ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    clap::error::ContextKind::InvalidValue,
                    clap::error::ContextValue::String(value.to_string_lossy().into()),
                );
                err.insert(
                    clap::error::ContextKind::Custom,
                    clap::error::ContextValue::String(
                        "not a valid ASCII-armored OpenPGP public key block".into(),
                    ),
                );
                Err(err)
            }
        } else {
            Ok(SignedBy::Keyring(Path::new(value).into()))
        }
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub enum Snapshot {
    #[default]
    Disable,
    Use(DateTime<Utc>),
}

impl std::fmt::Display for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Snapshot::Disable => write!(f, "no"),
            Snapshot::Use(s) => write!(f, "{}", s.format("%Y%m%dT%H%M%SZ")),
        }
    }
}

impl From<&Snapshot> for String {
    fn from(s: &Snapshot) -> Self {
        match s {
            Snapshot::Disable => "no".to_string(),
            Snapshot::Use(s) => s.format("%Y%m%dT%H%M%SZ").to_string(),
        }
    }
}

impl From<&DateTime<Utc>> for Snapshot {
    fn from(dt: &DateTime<Utc>) -> Self {
        Snapshot::Use(*dt)
    }
}

struct SnapshotFormatSpec {
    pub fmt: &'static str,
    pub with_tz: bool,
}

impl SnapshotFormatSpec {
    pub const fn new(fmt: &'static str) -> Self {
        const fn contains_tz(fmt: &str) -> bool {
            let mut b = fmt.as_bytes();
            loop {
                b = match b {
                    [] => return false,
                    [b'%', b'Z', ..] => return true,
                    [b'%', b'z', ..] => return true,
                    [b'%', b':', b'z', ..] => return true,
                    [b'%', b':', b':', b'z', ..] => return true,
                    [b'%', b':', b':', b':', b'z', ..] => return true,
                    [b'%', b'#', b'z', ..] => return true,
                    [_, rest @ ..] => rest,
                }
            }
        }
        Self {
            fmt,
            with_tz: contains_tz(fmt),
        }
    }
    fn parse(&self, s: &str) -> Option<DateTime<Utc>> {
        if self.with_tz {
            DateTime::<FixedOffset>::parse_from_str(s, self.fmt)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        } else {
            NaiveDateTime::parse_from_str(s, self.fmt)
                .ok()
                .and_then(|ndt| ndt.and_local_timezone(Local).single())
                .map(|dt| dt.with_timezone(&Utc))
        }
    }
}

macro_rules! snapshot_formats {
    ($($fmt:literal),+ $(,)?) => {
        &[
            $( SnapshotFormatSpec::new($fmt) ),+
        ] as &[SnapshotFormatSpec]
    }
}

impl TryFrom<&str> for Snapshot {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("no") {
            Ok(Snapshot::Disable)
        } else {
            snapshot_formats![
                "%Y%m%dT%H%M%S%z",
                "%Y-%m-%d",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S",
                "%Y%m%d",
                "%Y%m%dT%H%M%S",
            ]
            .iter()
            .filter_map(|f| f.parse(s))
            .map(Snapshot::Use)
            .next()
            .ok_or_else(|| format!("invalid snapshot ID '{}' - expected a timestamp", s))
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for Snapshot {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SnapshotVisitor;

        impl<'de> serde::de::Visitor<'de> for SnapshotVisitor {
            type Value = Snapshot;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a \"no\" if snapshot use is disabled or snapshot ID to use"
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let v = v.trim();
                if v.eq_ignore_ascii_case("no") {
                    Ok(Snapshot::Disable)
                } else {
                    v.try_into().map_err(|e: String| E::custom(e))
                }
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                let v = v.trim();
                if v.eq_ignore_ascii_case("no") {
                    Ok(Snapshot::Disable)
                } else {
                    v.try_into().map_err(|e: String| E::custom(e))
                }
            }
        }

        deserializer.deserialize_string(SnapshotVisitor)
    }
}

#[derive(Clone)]
struct ClapSnapshotParser;

impl clap::builder::TypedValueParser for ClapSnapshotParser {
    type Value = Snapshot;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err
        })?;
        value.try_into().map_err(|e: String| {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(value.to_string()),
            );
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String(e),
            );
            err
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SourceHashKind {
    #[default]
    SHA256,
    SHA512,
    MD5sum,
}

impl SourceHashKind {
    pub fn is_sha256(&self) -> bool {
        *self == SourceHashKind::SHA256
    }
    pub fn name(&self) -> &'static str {
        match self {
            SourceHashKind::MD5sum => "MD5",
            SourceHashKind::SHA256 => "SHA256",
            SourceHashKind::SHA512 => "SHA512",
        }
    }
}

impl std::str::FromStr for SourceHashKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "md5" | "md5sum" => Ok(SourceHashKind::MD5sum),
            "sha256" => Ok(SourceHashKind::SHA256),
            "sha512" => Ok(SourceHashKind::SHA512),
            other => Err(format!("unsupported hash: {other}")),
        }
    }
}

#[derive(Clone)]
struct SourceHashKindValueParser;

impl clap::builder::TypedValueParser for SourceHashKindValueParser {
    type Value = SourceHashKind;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let val: SourceHashKind = value
            .to_str()
            .ok_or_else(|| {
                let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        clap::error::ContextKind::InvalidArg,
                        clap::error::ContextValue::String(arg.to_string()),
                    );
                }
                err
            })?
            .parse()
            .map_err(|e: String| {
                let mut err =
                    clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        clap::error::ContextKind::InvalidArg,
                        clap::error::ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    clap::error::ContextKind::InvalidValue,
                    clap::error::ContextValue::String(value.to_string_lossy().into()),
                );
                err.insert(
                    clap::error::ContextKind::Custom,
                    clap::error::ContextValue::String(e),
                );
                err
            })?;

        Ok(val)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RepositoryFile {
    pub(crate) path: String,
    pub(crate) hash: FileHash,
    pub(crate) size: u64,
}
impl RepositoryFile {
    pub fn new(path: String, hash: FileHash, size: u64) -> Self {
        Self { path, hash, size }
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn hash(&self) -> &FileHash {
        &self.hash
    }
}

#[derive(Debug, Args, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
#[group(required = true, multiple = true)]
pub struct Source {
    /// Repository URL
    #[arg(value_name = "URL")]
    pub url: String,

    /// Only include listed architecture
    #[arg(long = "only-arch", value_name = "ARCH", value_delimiter = ',')]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch: Vec<String>,

    /// Allow the repository to be insecure (without checking release signature)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_insecure: Option<bool>,

    /// A path to PGP keyring file or a @path in an ASCII-armored PGP public key block to inline
    #[arg(long = "signed-by", value_name = "@INLINE-KEY|KEYRING", value_parser = ClapSignedByParser)]
    #[serde(default, rename = "signed-by", skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<SignedBy>,

    /// Snapshots service template URL
    #[arg(long = "snapshots", value_name = "URL")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<String>,

    #[arg(long = "snapshot", value_name = "SNAPSHOT", value_parser = ClapSnapshotParser)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,

    /// Suite or codename (i.e. "focal", "buster", "stable", "testing", "unstable", etc.)
    #[arg(short = 's', long = "suite", value_name = "SUITE", num_args = 1, action = clap::ArgAction::Set)]
    pub suites: Vec<String>,

    /// Space separated list of components (i.e. "main", "contrib", "non-free", etc.)
    #[arg(short = 'c', long = "components", value_name = "COMPONENT")]
    #[serde(alias = "comp", default = "default_components")]
    pub components: Vec<String>,

    /// Hash type for veryfing repository files
    #[arg(
        long = "hash",
        value_parser = SourceHashKindValueParser,
        value_name = "md5|sha256|sha512",
        default_value = "sha256"
    )]
    #[serde(default, skip_serializing_if = "SourceHashKind::is_sha256")]
    pub hash: SourceHashKind,

    /// Index files extension (default is .xz, empty for the unpacked)
    #[arg(long = "extension", value_name = ".EXT")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,

    /// Source priority (higher number means higher priority)
    #[arg(long = "priority", value_name = "N")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
}

impl Source {
    const MAX_RELEASE_SIZE: u64 = 2 * 1024 * 1024; // 10 MiB
    const MAX_PACKAGE_SIZE: u64 = 100 * 1024 * 1024; // 10 GiB
    pub fn should_include_arch(&self, arch: &str) -> bool {
        self.arch.is_empty() || self.arch.iter().any(|s| s == arch)
    }
    pub fn allow_insecure(&self) -> bool {
        self.allow_insecure.unwrap_or(false)
    }
    pub fn with_snapshots<S: AsRef<str>>(mut self, snapshots: S) -> Self {
        self.snapshots = Some(snapshots.as_ref().to_string());
        self
    }
    pub async fn fetch_unsigned_release_by_hash<T: TransportProvider>(
        &self,
        transport: &T,
        path: &str,
        size: u64,
        hash: &FileHash,
    ) -> std::io::Result<Release> {
        transport
            .fetch_verify(
                &format!("{}/{}", self.url.trim_end_matches('/'), path,),
                size,
                hash,
            )
            .await
            .and_then(|buf| {
                Release::try_from(buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
    }
    pub async fn fetch_unsigned_release<T: TransportProvider + ?Sized>(
        &self,
        suite: &str,
        transport: &T,
    ) -> std::io::Result<(Release, String, FileHash, u64)> {
        let path = format!("dists/{}/Release", suite);
        transport
            .fetch_hash(
                &format!("{}/{}", self.url.trim_end_matches('/'), &path,),
                self.hash.name(),
                Self::MAX_RELEASE_SIZE,
            )
            .await
            .and_then(|(buf, size, hash)| {
                Ok((
                    Release::try_from(buf)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
                    path,
                    hash,
                    size,
                ))
            })
    }
    async fn verify_signed_release(&self, data: Vec<u8>) -> io::Result<Release> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let tempdir = tempfile::tempdir()?;
        ctx.set_engine_home_dir(tempdir.path().as_os_str().as_encoded_bytes())?;
        ctx.set_flag("auto-key-retrieve", "0")?;

        self.signed_by
            .as_ref()
            .unwrap_or(&SignedBy::Builtin)
            .import_into(&mut ctx)
            .await?;

        let mut plaintext = Vec::new();
        let verify_result = ctx.verify_opaque(data, &mut plaintext)?;
        if let Some(signature) = verify_result.signatures().next() {
            if let Err(err) = signature.status() {
                return Err(err.into());
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no signature found in InRelease",
            ));
        }
        Release::try_from(plaintext)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    pub async fn fetch_signed_release<T: TransportProvider + ?Sized>(
        &self,
        suite: &str,
        transport: &T,
    ) -> std::io::Result<(Release, String, FileHash, u64)> {
        let path = format!("dists/{}/InRelease", suite);
        let (data, size, hash) = transport
            .fetch_hash(
                &format!("{}/{}", self.url.trim_end_matches('/'), &path,),
                self.hash.name(),
                Self::MAX_RELEASE_SIZE,
            )
            .await?;
        Ok((self.verify_signed_release(data).await?, path, hash, size))
    }
    pub async fn fetch_signed_release_by_hash<T: TransportProvider>(
        &self,
        transport: &T,
        path: &str,
        size: u64,
        hash: &FileHash,
    ) -> io::Result<Release> {
        let data = transport
            .fetch_verify(
                &format!("{}/{}", self.url.trim_end_matches('/'), path,),
                size,
                hash,
            )
            .await?;
        self.verify_signed_release(data).await
    }
    pub(crate) async fn file_by_hash<T>(
        &self,
        transport: &T,
        file: &RepositoryFile,
    ) -> io::Result<Box<[u8]>>
    where
        T: TransportProvider + ?Sized,
    {
        transport
            .fetch_verify_unpack(
                &format!("{}/{}", &self.url, &file.path),
                file.size,
                &file.hash,
                Self::MAX_PACKAGE_SIZE,
            )
            .await
            .map(|s| s.into_boxed_slice())
    }
    pub(crate) async fn files<T: TransportProvider + ?Sized>(
        &self,
        arch: &str,
        sem: &Arc<Semaphore>,
        transport: &T,
    ) -> Result<Vec<(RepositoryFile, Vec<RepositoryFile>)>, io::Error> {
        try_join_all(self.suites.iter().map(|s| async move {
            let sem = Arc::clone(sem);
            let _permit = sem.acquire().await;
            let (rel, path, hash, size) = if self.allow_insecure() {
                self.fetch_unsigned_release(s, transport).await?
            } else {
                self.fetch_signed_release(s, transport).await?
            };
            let pkgs_ind = rel
                .files(
                    &self.components,
                    self.hash.name(),
                    arch,
                    self.ext.as_deref(),
                )?
                .map_err(Into::into)
                .map_ok(|(path, hash, size)| {
                    RepositoryFile::new(format!("dists/{}/{}", s, path), hash, size)
                })
                .collect::<io::Result<Vec<_>>>()?;
            Ok::<_, io::Error>((RepositoryFile::new(path, hash, size), pkgs_ind))
        }))
        .await
    }
    pub async fn deb_reader<T: TransportProvider + ?Sized>(
        &self,
        path: &str,
        size: u64,
        hash: &FileHash,
        transport: &T,
    ) -> io::Result<DebReader> {
        transport
            .verifying_deb_reader(
                &format!("{}/{}", self.url.trim_end_matches('/'), path),
                size,
                hash,
            )
            .await
    }
    pub fn as_vendor(&self) -> Option<(Vec<Self>, Vec<String>)> {
        match self.url.to_ascii_lowercase().as_str() {
            "debian" => {
                const DEFAULT_SUITE: &str = "trixie";
                let mut source = self.clone();
                let mut security: Option<Source> = None;
                source.url = "https://ftp.debian.org/debian/".to_string();
                if self.snapshot.is_none() {
                    source.snapshots = Some(
                        "https://snapshot.debian.org/archive/debian/@SNAPSHOTID@/".to_string(),
                    );
                }
                if self.components.is_empty() {
                    source.components = vec!["main".to_string()];
                }
                if self.suites.len() < 2 {
                    let s = if self.suites.is_empty() {
                        DEFAULT_SUITE
                    } else {
                        self.suites[0].as_str()
                    };
                    if s != "sid" && s != "unstable" {
                        source.suites = ["", "-updates", "-backports"]
                            .iter()
                            .map(|f| format!("{}{}", s, f))
                            .collect();
                        security = Some(Source {
                            url: "https://security.debian.org/debian-security/".to_string(),
                            suites: vec![format!("{}-security", s)],
                            snapshots: Some(
                                "https://snapshot.debian.org/archive/debian-security/@SNAPSHOTID@/"
                                    .to_string(),
                            ),
                            ..source.clone()
                        });
                    }
                }
                let mut sources = vec![source];
                sources.extend(security);
                Some((sources, vec!["ca-certificates".to_string()]))
            }
            "ubuntu" => {
                const DEFAULT_SUITE: &str = "noble";
                let mut source = self.clone();
                source.url = "https://archive.ubuntu.com/ubuntu/".to_string();
                if self.snapshot.is_none() {
                    source.snapshots =
                        Some("https://snapshot.ubuntu.com/ubuntu/@SNAPSHOTID@/".to_string());
                }
                if self.components.is_empty() {
                    source.components = vec!["main".to_string(), "universe".to_string()];
                }
                if self.suites.len() < 2 {
                    let s = if self.suites.is_empty() {
                        DEFAULT_SUITE
                    } else {
                        self.suites[0].as_str()
                    };
                    source.suites = ["", "-updates", "-backports", "-security"]
                        .iter()
                        .map(|f| format!("{}{}", s, f))
                        .collect();
                }
                Some((vec![source], vec!["ca-certificates".to_string()]))
            }
            "devuan" => {
                const DEFAULT_SUITE: &str = "daedalus";
                let mut source = self.clone();
                source.url = "http://deb.devuan.org/merged/".to_string();
                source.snapshots = None;
                if self.components.is_empty() {
                    source.components = vec!["main".to_string()];
                }
                if self.suites.len() < 2 {
                    let s = if self.suites.is_empty() {
                        DEFAULT_SUITE
                    } else {
                        self.suites[0].as_str()
                    };
                    if s != "ceres"
                        && s != "unstable"
                        && !s.chars().next().is_some_and(|c| c.is_ascii_digit())
                    {
                        source.suites = ["", "-updates", "-backports", "-security"]
                            .iter()
                            .map(|f| format!("{}{}", s, f))
                            .collect();
                    }
                }
                Some((
                    vec![source],
                    vec!["ca-certificates".to_string(), "devuan-keyring".to_string()],
                ))
            }
            _ => None,
        }
    }
}

impl From<&Source> for MutableControlStanza {
    fn from(src: &Source) -> Self {
        let mut cs = MutableControlStanza::parse("Types: deb\n").unwrap();
        cs.set("URIs", src.url.clone());
        cs.set("Suites", src.suites.join(" "));
        cs.set("Components", src.components.join(" "));
        if !src.arch.is_empty() {
            cs.set("Architectures", src.arch.join(" "));
        }
        if let Some(allow_insecure) = src.allow_insecure {
            cs.set("Allow-Insecure", if allow_insecure { "yes" } else { "no" });
        }
        if let Some(signed_by) = &src.signed_by {
            cs.set("Signed-By", String::from(signed_by));
        }
        if let Some(snapshots) = &src.snapshots {
            cs.set("Snapshots", snapshots.clone());
        }
        if let Some(snapshot) = &src.snapshot {
            cs.set("Snapshot", String::from(snapshot));
        }
        cs
    }
}
