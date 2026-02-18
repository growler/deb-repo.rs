use {
    crate::{control::MutableControlStanza, hash::Hash, indexfile::IndexFile, release::Release},
    chrono::{DateTime, FixedOffset, Local, NaiveDateTime, Utc},
    clap::Args,
    futures::AsyncReadExt,
    serde::{Deserialize, Serialize},
    smol::{fs, io},
    std::path::{Path, PathBuf},
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

        impl serde::de::Visitor<'_> for SignedByVisitor {
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

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotId(pub DateTime<Utc>);

impl SnapshotId {
    pub fn format(&self, fmt: &str) -> String {
        self.0.format(fmt).to_string()
    }
}

impl From<&DateTime<Utc>> for SnapshotId {
    fn from(dt: &DateTime<Utc>) -> Self {
        SnapshotId(*dt)
    }
}

impl From<&DateTime<Utc>> for Snapshot {
    fn from(dt: &DateTime<Utc>) -> Self {
        Snapshot::Use(dt.into())
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.format("%Y%m%dT%H%M%SZ"))
    }
}

impl From<SnapshotId> for Snapshot {
    fn from(dt: SnapshotId) -> Self {
        Snapshot::Use(dt)
    }
}

macro_rules! parse_snapshot {
    ($var:expr, [ $($fmt:literal),+ $(,)? ]) => {
        $(if let Some(parsed) = SnapshotFormatSpec::new($fmt).parse($var) {
            Ok(SnapshotId(parsed))
        } else
        )+
        {
            Err(format!("invalid snapshot ID '{}' - expected a timestamp", $var))
        }
    }
}

impl TryFrom<&str> for SnapshotId {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        parse_snapshot!(
            s.trim(),
            [
                "%Y%m%dT%H%M%SZ",
                "%Y%m%dT%H%M%S%z",
                "%Y-%m-%d",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S",
                "%Y%m%d",
                "%Y%m%dT%H%M%S",
            ]
        )
    }
}

#[derive(Clone)]
pub struct SnapshotIdArgParser;

impl clap::builder::TypedValueParser for SnapshotIdArgParser {
    type Value = SnapshotId;

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
        if value.eq_ignore_ascii_case("now") {
            Ok(SnapshotId(Utc::now()))
        } else {
            value.try_into().map_err(|e: String| {
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
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub enum Snapshot {
    #[default]
    Disable,
    Enable,
    Use(SnapshotId),
}

impl std::fmt::Display for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Snapshot::Disable => write!(f, "disable"),
            Snapshot::Enable => write!(f, "enable"),
            Snapshot::Use(s) => write!(f, "{}", s.format("%Y%m%dT%H%M%SZ")),
        }
    }
}

impl From<&Snapshot> for String {
    fn from(s: &Snapshot) -> Self {
        format!("{}", s)
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

impl TryFrom<&str> for Snapshot {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("disable") {
            Ok(Snapshot::Disable)
        } else if s.eq_ignore_ascii_case("enable") {
            Ok(Snapshot::Enable)
        } else {
            TryFrom::<&str>::try_from(s).map(Snapshot::Use)
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for Snapshot {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SnapshotVisitor;

        impl serde::de::Visitor<'_> for SnapshotVisitor {
            type Value = Snapshot;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a \"no\" if snapshot use is disabled or snapshot ID to use"
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.trim().try_into().map_err(|e: String| E::custom(e))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                v.trim().try_into().map_err(|e: String| E::custom(e))
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
pub enum ArchiveHashKind {
    #[default]
    SHA256,
    SHA512,
    MD5sum,
}

impl ArchiveHashKind {
    pub fn is_sha256(&self) -> bool {
        *self == ArchiveHashKind::SHA256
    }
    pub fn name(&self) -> &'static str {
        match self {
            ArchiveHashKind::MD5sum => "MD5",
            ArchiveHashKind::SHA256 => "SHA256",
            ArchiveHashKind::SHA512 => "SHA512",
        }
    }
}

impl std::str::FromStr for ArchiveHashKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "md5" | "md5sum" => Ok(ArchiveHashKind::MD5sum),
            "sha256" => Ok(ArchiveHashKind::SHA256),
            "sha512" => Ok(ArchiveHashKind::SHA512),
            other => Err(format!("unsupported hash: {other}")),
        }
    }
}

#[derive(Clone)]
struct ArchiveHashKindValueParser;

impl clap::builder::TypedValueParser for ArchiveHashKindValueParser {
    type Value = ArchiveHashKind;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let val: ArchiveHashKind = value
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

#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct RepositoryFile {
    pub(crate) path: String,
    pub(crate) hash: Hash,
    pub(crate) size: u64,
}
impl RepositoryFile {
    pub fn new(path: String, hash: Hash, size: u64) -> Self {
        Self { path, hash, size }
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}

#[derive(Debug, Args, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    /// Repository URL
    #[arg(value_name = "URL")]
    pub url: String,

    #[clap(skip)]
    #[serde(skip)]
    real_url: Option<String>,

    /// Only include the listed architectures
    #[arg(long = "only-arch", value_name = "ARCH", value_delimiter = ',')]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch: Vec<String>,

    /// Allow the repository to be insecure (skip checking release signature)
    #[arg(short = 'K', long = "allow-insecure")]
    #[serde(
        default,
        rename = "allow-insecure",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_insecure: Option<bool>,

    /// A path to PGP keyring file or a @path in an ASCII-armored PGP public key block to inline
    #[arg(long = "signed-by", value_name = "@INLINE-KEY|KEYRING", value_parser = ClapSignedByParser)]
    #[serde(default, rename = "signed-by", skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<SignedBy>,

    /// Snapshots service template URL
    #[arg(long = "snapshots", value_name = "URL")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<String>,

    /// Snapshot ID to use.
    ///
    /// Snapshot ID format is a timestamp in UTC (or with an explicit offset) accepted in any of
    /// these forms:
    ///   %Y%m%dT%H%M%SZ
    ///   %Y%m%dT%H%M%S%z
    ///   %Y-%m-%d
    ///   %Y-%m-%dT%H:%M:%S%z
    ///   %Y-%m-%dT%H:%M:%S
    ///   %Y%m%d
    ///   %Y%m%dT%H%M%S
    #[arg(long = "snapshot", value_name = "SNAPSHOT", value_parser = ClapSnapshotParser)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,

    /// Suite or codename (i.e. "focal", "buster", "stable", "testing", "unstable", etc.)
    #[arg(short = 's', long = "suite", value_name = "SUITE", num_args = 1, action = clap::ArgAction::Set)]
    pub suites: Vec<String>,

    /// Space-separated list of components (i.e. "main", "contrib", "non-free", etc.)
    #[arg(short = 'C', long = "components", value_name = "COMPONENT")]
    #[serde(alias = "comp", default = "default_components")]
    pub components: Vec<String>,

    /// Hash type for verifying repository files
    #[arg(
        hide = true,
        long = "hash",
        value_parser = ArchiveHashKindValueParser,
        value_name = "md5|sha1|sha256|sha512",
        default_value = "sha256",
    )]
    #[serde(default, skip_serializing_if = "ArchiveHashKind::is_sha256")]
    pub hash: ArchiveHashKind,

    /// Archive priority (higher number means higher priority)
    #[arg(long = "priority", value_name = "N")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
}

impl Archive {
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
    pub(crate) fn release_path(&self, suite: &str, skip_verify: bool) -> String {
        if self.allow_insecure() || skip_verify {
            format!("dists/{}/Release", suite)
        } else {
            format!("dists/{}/InRelease", suite)
        }
    }
    pub(crate) async fn release_from_file(
        &self,
        r: IndexFile,
        skip_verify: bool,
    ) -> io::Result<Release> {
        if self.allow_insecure() || skip_verify {
            Release::new(r).map_err(std::io::Error::other)
        } else {
            self.verify_signed_release(&r).await
        }
    }
    async fn verify_signed_release<T: AsRef<str>>(&self, data: T) -> io::Result<Release> {
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
        let verify_result = ctx.verify_opaque(data.as_ref().as_bytes(), &mut plaintext)?;
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
        Release::try_from(plaintext).map_err(std::io::Error::other)
    }
    pub(crate) fn set_base(&mut self) {
        if let Some(snapshots_template) = &self.snapshots {
            if let Some(Snapshot::Use(snap)) = &self.snapshot {
                self.real_url = Some(
                    snapshots_template
                        .trim_end_matches('/')
                        .replace("@SNAPSHOTID@", &snap.format("%Y%m%dT%H%M%SZ").to_string()),
                );
            }
        }
    }
    pub(crate) fn base(&self) -> &str {
        self.real_url.as_deref().unwrap_or(&self.url)
    }
    pub(crate) fn apt_uri(&self) -> String {
        if let Some(snapshots_template) = &self.snapshots {
            if let Some(Snapshot::Use(snap)) = &self.snapshot {
                return snapshots_template
                    .trim_end_matches('/')
                    .replace("@SNAPSHOTID@", &snap.format("%Y%m%dT%H%M%SZ").to_string());
            }
        }
        self.url.trim_end_matches('/').to_string()
    }
    pub fn file_url<P: AsRef<str>>(&self, path: P) -> String {
        if let Some(snapshots_template) = &self.snapshots {
            if let Some(Snapshot::Use(snap)) = &self.snapshot {
                return format!(
                    "{}/{}",
                    snapshots_template
                        .trim_end_matches('/')
                        .replace("@SNAPSHOTID@", &snap.format("%Y%m%dT%H%M%SZ").to_string()),
                    path.as_ref()
                );
            }
        }
        format!("{}/{}", self.url.trim_end_matches('/'), path.as_ref())
    }
    pub fn as_vendor(&self) -> Option<(Vec<Self>, Vec<String>)> {
        match self.url.to_ascii_lowercase().as_str() {
            "debian" => {
                const DEFAULT_SUITE: &str = "trixie";
                let mut archive = self.clone();
                let mut security: Option<Archive> = None;
                archive.url = "https://ftp.debian.org/debian/".to_string();
                if self.snapshot.is_none() {
                    archive.snapshots = Some(
                        "https://snapshot.debian.org/archive/debian/@SNAPSHOTID@/".to_string(),
                    );
                }
                if self.components.is_empty() {
                    archive.components = vec!["main".to_string()];
                }
                if self.suites.len() < 2 {
                    let s = if self.suites.is_empty() {
                        DEFAULT_SUITE
                    } else {
                        self.suites[0].as_str()
                    };
                    if s != "sid" && s != "unstable" {
                        archive.suites = ["", "-updates", "-backports"]
                            .iter()
                            .map(|f| format!("{}{}", s, f))
                            .collect();
                        security = Some(Archive {
                            url: "https://security.debian.org/debian-security/".to_string(),
                            suites: vec![format!("{}-security", s)],
                            snapshots: Some(
                                "https://snapshot.debian.org/archive/debian-security/@SNAPSHOTID@/"
                                    .to_string(),
                            ),
                            ..archive.clone()
                        });
                    }
                }
                let mut archives = vec![archive];
                archives.extend(security);
                Some((archives, vec![]))
            }
            "ubuntu" => {
                const DEFAULT_SUITE: &str = "noble";
                let mut archive = self.clone();
                archive.url = "https://archive.ubuntu.com/ubuntu/".to_string();
                if self.snapshot.is_none() {
                    archive.snapshots =
                        Some("https://snapshot.ubuntu.com/ubuntu/@SNAPSHOTID@/".to_string());
                }
                if self.components.is_empty() {
                    archive.components = vec!["main".to_string(), "universe".to_string()];
                }
                if self.suites.len() < 2 {
                    let s = if self.suites.is_empty() {
                        DEFAULT_SUITE
                    } else {
                        self.suites[0].as_str()
                    };
                    archive.suites = ["", "-updates", "-backports", "-security"]
                        .iter()
                        .map(|f| format!("{}{}", s, f))
                        .collect();
                }
                Some((vec![archive], vec![]))
            }
            "devuan" => {
                const DEFAULT_SUITE: &str = "daedalus";
                let mut archive = self.clone();
                archive.url = "http://deb.devuan.org/merged/".to_string();
                archive.snapshots = None;
                if self.components.is_empty() {
                    archive.components = vec!["main".to_string()];
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
                        archive.suites = ["", "-updates", "-backports", "-security"]
                            .iter()
                            .map(|f| format!("{}{}", s, f))
                            .collect();
                    }
                }
                Some((vec![archive], vec!["devuan-keyring".to_string()]))
            }
            _ => None,
        }
    }
}

impl From<&Archive> for MutableControlStanza {
    fn from(src: &Archive) -> Self {
        let mut cs = MutableControlStanza::parse("Types: deb\n").unwrap();
        cs.set("URIs", src.apt_uri());
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
        cs
    }
}
