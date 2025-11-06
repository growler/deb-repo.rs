use {
    async_lock::OnceCell,
    clap::Parser,
    debrepo::{
        cli::{self, Command},
        sandbox::{maybe_run_sandbox, HostSandboxExecutor},
        HttpCachingTransportProvider, HttpTransportProvider, Manifest, TransportProvider,
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
    about = "Bootstrap Debian-based system tree from a manifest file",
    long_about = "Bootstrap a Debian root filesystem from a manifest file.
This tool resolves packages from configured repositories, locks and updates
a snapshot, stages artifacts, and builds a rootfs-like directory tree.
Typical workflow:  
    1) init             - create a manifest with sources and initial packages
    2) include/exclude  - add packages requirements and constraints 
    3) update           - refresh lock/snapshot and metadata
    4) build            - extract and configure packages into a target directory
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

    /// Path to the manifest file
    #[arg(global = true, short, long, default_value = Manifest::DEFAULT_FILE, display_order = 0)]
    manifest: PathBuf,

    #[command(subcommand)]
    cmd: Commands,
}

impl cli::Config for App {
    fn arch(&self) -> &str {
        &self.arch
    }
    fn manifest(&self) -> &Path {
        &self.manifest
    }
    fn concurrency(&self) -> NonZero<usize> {
        self.concurrency
    }
    fn cache(&self) -> Option<&Path> {
        self.cache_dir.as_deref()
    }
    fn transport(
        &self,
    ) -> impl std::future::Future<Output = std::io::Result<&dyn TransportProvider>> {
        static PROVIDER: OnceCell<Box<dyn TransportProvider>> = OnceCell::new();
        async {
            let provider = PROVIDER
                .get_or_try_init(|| async {
                    if let Some(cache) = &self.cache_dir {
                        HttpCachingTransportProvider::new(self.insecure, cache.clone())
                            .map(|p| Box::new(p) as Box<dyn TransportProvider>)
                    } else {
                        Ok(Box::new(HttpTransportProvider::new(self.insecure))
                            as Box<dyn TransportProvider>)
                    }
                })
                .await
                .map(|t| t.as_ref());
            provider
        }
    }
}

debrepo::commands! {
    enum Commands<App> {
        Init(cli::cmd::Init),
        Update(cli::cmd::Update),
        Build(cli::cmd::Build),
        Include(cli::cmd::Include),
        Exclude(cli::cmd::Exclude),
        Drop(cli::cmd::Drop),
        Stage(cli::cmd::Stage),
        Unstage(cli::cmd::Unstage),
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
    maybe_run_sandbox::<HostSandboxExecutor>();
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
