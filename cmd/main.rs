use {
    clap::Parser,
    debrepo::{
        auth::AuthProvider,
        cli::{self, Command},
        content::HostCache,
        exec::maybe_run_helper,
        sandbox::{run_sandbox, HostSandboxExecutor},
        HostFileSystem, HttpTransport, Manifest,
    },
    std::{
        num::NonZero,
        path::{Path, PathBuf},
        process::ExitCode,
    },
    tracing::level_filters::LevelFilter,
    tracing_subscriber::{filter::EnvFilter, fmt},
};

#[derive(Parser)]
#[command(
    version,
    next_line_help = false,
    about = "Bootstrap Debian-based system tree from a manifest file",
    long_about = "Bootstrap a Debian root filesystem from a manifest file.
This tool resolves packages from configured repositories, locks and updates
a snapshot, stages artifacts, and builds a rootfs-like directory tree.
Typical workflow:  
    1) init             - create a manifest with sources and initial packages
    2) include/exclude  - add package requirements and constraints
    3) update           - refresh lock/snapshot and metadata
    4) build            - extract and configure packages into a target directory
Notes:
    -k/--insecure disables TLS verification for archive downloads.
    -K/--no-verify skips Release file signature verification.
"
)]
pub struct App {
    /// Turns off all output except errors
    #[arg(short, long, conflicts_with = "debug", action)]
    quiet: bool,

    /// Turns on debugging output (repeat -d for more)
    #[arg(short, long, conflicts_with = "quiet", action = clap::ArgAction::Count)]
    debug: u8,

    /// Number of concurrent downloads
    #[arg(
        short = 'n',
        long = "downloads",
        value_name = "NUM",
        default_value = "20"
    )]
    concurrency: NonZero<usize>,

    /// Target architecture (e.g. amd64, arm64)
    #[arg(long, value_name = "ARCH", default_value = debrepo::DEFAULT_ARCH)]
    arch: String,

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

    /// Do not verify Release files by default (not recommended)
    #[arg(short = 'K', long = "no-verify", display_order = 0, action)]
    pub insecure_release: bool,

    /// Skip the connection verification (not recommended)
    #[arg(short = 'k', long = "insecure", action, display_order = 0, action)]
    pub insecure: bool,

    /// Auth source (file:<path>, <path>, or vault:<mount>/<path>)
    #[arg(short = 'a', long = "auth", value_name = "AUTH", display_order = 0)]
    auth: Option<String>,

    /// Path to the manifest file
    #[arg(global = true, short, long, default_value = Manifest::DEFAULT_FILE, display_order = 0)]
    manifest: PathBuf,

    #[command(subcommand)]
    cmd: Commands,
}

impl cli::Config for App {
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

debrepo::cli_commands! {
    enum Commands<App> {
        Init(cli::cmd::Init),
        Update(cli::cmd::Update),
        Add(cli::cmd::Add),
        Include(cli::cmd::Include),
        Exclude(cli::cmd::Exclude),
        Drop(cli::cmd::Drop),
        Stage(cli::cmd::Stage),
        Unstage(cli::cmd::Unstage),
        Build(cli::cmd::Build),
        List(cli::cmd::List),
        Search(cli::cmd::Search),
        Show(cli::cmd::Show),
    }
}

fn init_logging(quiet: bool, debug: u8) {
    let default_level = if quiet {
        LevelFilter::ERROR
    } else {
        match debug {
            0 => LevelFilter::INFO,
            1 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    };
    let trace = debug > 1;
    let filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy()
        .add_directive("polling=warn".parse().unwrap())
        .add_directive("isahc::wire=warn".parse().unwrap());

    let base_format = fmt::format()
        .without_time()
        .with_level(trace)
        .with_target(trace);

    fmt()
        .with_env_filter(filter)
        .event_format(base_format)
        .with_thread_ids(trace) // include thread IDs only in debug mode
        .with_thread_names(trace) // include thread names only in debug mode
        .with_file(trace) // include file path only in debug mode
        .with_line_number(trace) // include line number only in debug mode
        .init();
}

fn main() -> ExitCode {
    maybe_run_helper(run_sandbox::<HostSandboxExecutor>);
    let mut app = App::parse();
    init_logging(app.quiet, app.debug);
    if !app.no_cache {
        app.cache_dir = app.cache_dir.clone().or_else(|| {
            if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
                Some(PathBuf::from(xdg))
            } else {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache"))
            }
            .map(|base| base.join("rdebootstrap"))
        });
    } else {
        app.cache_dir = None;
    }
    match app.cmd.exec(&app) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            println!("{}", err);
            ExitCode::FAILURE
        }
    }
}
