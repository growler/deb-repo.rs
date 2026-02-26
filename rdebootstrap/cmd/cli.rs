use {
    clap::Parser,
    debrepo::{
        auth::AuthProvider, cli as deb_cli, content::HostCache, HostFileSystem, HttpTransport,
        LockBase, Manifest, DEFAULT_ARCH,
    },
    std::{
        num::NonZero,
        path::{Path, PathBuf},
    },
};

impl deb_cli::Config for App {
    type FS = HostFileSystem;
    type Cache = HostCache;
    fn log_level(&self) -> i32 {
        if self.quiet {
            -1
        } else {
            self.debug as i32
        }
    }
    fn arch(&self) -> &str {
        &self.arch
    }
    fn manifest(&self) -> &Path {
        &self.manifest
    }
    fn lock_base(&self) -> Option<&LockBase> {
        self.lock.as_ref()
    }
    fn concurrency(&self) -> NonZero<usize> {
        self.concurrency
    }
    fn fetcher(&self) -> std::io::Result<&HostCache> {
        static PROVIDER: once_cell::sync::OnceCell<HostCache> = once_cell::sync::OnceCell::new();
        PROVIDER.get_or_try_init(|| {
            let base = self
                .manifest
                .parent()
                .map(|s| {
                    if s.as_os_str().is_empty() {
                        Path::new(".")
                    } else {
                        s
                    }
                })
                .ok_or_else(|| {
                    std::io::Error::other(format!(
                        "invalid manifest file path: {}",
                        self.manifest.display()
                    ))
                })?;
            let base = std::fs::canonicalize(base).map_err(|err| {
                std::io::Error::other(format!(
                    "failed to find manifest file parent directory {}: {}",
                    self.manifest.parent().unwrap_or(Path::new(".")).display(),
                    err
                ))
            })?;
            if let Some(path) = self.cache_dir.as_deref() {
                std::fs::create_dir_all(path).map_err(|err| {
                    std::io::Error::other(format!(
                        "failed to create cache directory {}: {}",
                        path.display(),
                        err
                    ))
                })?;
            }
            let auth_file = base.join("auth.toml");
            let auth_file = std::fs::canonicalize(&auth_file)
                .ok()
                .and_then(|p| p.into_os_string().into_string().ok());
            Ok(HostCache::new(
                base,
                HttpTransport::new(
                    AuthProvider::new(self.auth.as_deref().or(auth_file.as_deref()))?,
                    self.insecure,
                ),
                self.cache_dir.as_deref(),
            ))
        })
    }
}

#[derive(Parser)]
#[command(
    version,
    next_line_help = false,
    about = "Manifest-driven Debian/Ubuntu bootstrapper",
    long_about = r#"rdebootstrap consumes a declarative manifest (default: Manifest.toml),
resolves Debian packages from configured APT archives, writes a lock file for
reproducible builds, stages extra artifacts, and builds a root filesystem tree
inside an isolated sandbox so maintainer scripts run in a controlled environment.

Typical workflow:
    1) init             - create a manifest with sources and initial packages
    2) include/exclude  - add package requirements and constraints
    3) update           - refresh archive metadata and rewrite Manifest.<arch>.lock
    4) build            - extract and configure packages into a target directory
"#
)]
pub struct App {
    /// Turns off all output except errors
    #[arg(short, long, conflicts_with = "debug", action)]
    pub quiet: bool,

    /// Turns on debugging output (repeat -d for more)
    #[arg(short, long, conflicts_with = "quiet", action = clap::ArgAction::Count)]
    pub debug: u8,

    /// Number of concurrent downloads
    #[arg(
        short = 'n',
        long = "downloads",
        value_name = "NUM",
        default_value = "20"
    )]
    pub concurrency: NonZero<usize>,

    /// Target architecture (e.g. amd64, arm64)
    #[arg(long, value_name = "ARCH", default_value = DEFAULT_ARCH)]
    pub arch: String,

    /// Cache directory to keep downloaded files
    #[arg(
        long = "cache-dir",
        value_name = "DIR",
        conflicts_with = "no_cache",
        display_order = 0
    )]
    pub cache_dir: Option<PathBuf>,

    /// Disable caching downloaded files
    #[arg(
        long = "no-cache",
        conflicts_with = "cache_dir",
        display_order = 0,
        action,
        display_order = 0
    )]
    pub no_cache: bool,

    /// Skip TLS certificate and hostname verification (not recommended)
    #[arg(short = 'k', long = "insecure", action, display_order = 0, action)]
    pub insecure: bool,

    /// Auth source (file:<path>, <path>, or vault:<mount>/<path>); defaults to auth.toml next to the manifest if present
    #[arg(short = 'a', long = "auth", value_name = "AUTH", display_order = 0)]
    pub auth: Option<String>,

    /// Path to the manifest file
    #[arg(global = true, short, long, default_value = Manifest::DEFAULT_FILE, display_order = 0)]
    pub manifest: PathBuf,

    /// Base path for the lock file (end with a separator to treat as a directory)
    #[arg(
        global = true,
        short = 'l',
        long = "lock",
        value_name = "LOCK",
        display_order = 0
    )]
    pub lock: Option<LockBase>,

    #[command(subcommand)]
    pub cmd: Commands,
}

debrepo::cli_commands! {
    pub enum Commands<App> {
        Init(deb_cli::cmd::Init),
        Update(deb_cli::cmd::Update),
        Build(deb_cli::cmd::Build),
        Search(deb_cli::cmd::Search),
        Spec(deb_cli::cmd::Spec),
        Package(deb_cli::cmd::PackageCmd),
        Source(deb_cli::cmd::SourceCmd),
        Archive(deb_cli::cmd::ArchiveCmd),
        Artifact(deb_cli::cmd::ArtifactCmd),
        Local(deb_cli::cmd::LocalCmd),
        Include(deb_cli::cmd::Include),
        Exclude(deb_cli::cmd::Exclude),
        Drop(deb_cli::cmd::Drop),
        Stage(deb_cli::cmd::Stage),
        Unstage(deb_cli::cmd::Unstage),
        Edit(deb_cli::cmd::Edit),
        #[command(hide = true)]
        Add(deb_cli::cmd::Add),
        #[command(hide = true)]
        List(deb_cli::cmd::List),
        #[command(hide = true)]
        Show(deb_cli::cmd::Show),
        #[command(hide = true)]
        Tool(deb_cli::cmd::Tool),
    }
}
