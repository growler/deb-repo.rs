use {
    anyhow::{anyhow, Result},
    clap::{Parser, Subcommand},
    debrepo::{
        artifact::ArtifactArg,
        builder::Executor,
        cli::Source,
        sandbox::{maybe_run_sandbox, HostSandboxExecutor},
        version::{Constraint, Dependency, Version},
        HttpCachingTransportProvider, HttpTransportProvider, Manifest, SnapshotId,
        TransportProvider,
    },
    futures_lite::AsyncWriteExt,
    itertools::Itertools,
    smol::fs,
    std::{num::NonZero, path::PathBuf, process::ExitCode},
    tracing::level_filters::LevelFilter,
    tracing_subscriber::{filter::EnvFilter, fmt},
};

#[enum_dispatch::enum_dispatch]
pub trait Command {
    fn exec(&self, conf: &App) -> Result<()>;
}

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
    #[arg(short, long)]
    quiet: bool,

    /// Turns on debugging output (repeat -d for more)
    #[arg(short, long, action = clap::ArgAction::Count)]
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

    /// HTTP download cache directory
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

#[enum_dispatch::enum_dispatch(Command)]
#[derive(Subcommand)]
enum Commands {
    /// Initialize a new manifest file
    #[command(name = "init", next_display_order = 200)]
    Init,
    /// Update the lock file
    #[command(name = "update")]
    Update,
    /// Build a root filesystem into a target directory from the manifest
    #[command(name = "build")]
    Build,
    /// Include package requirements into a spec
    #[command(name = "include")]
    Include,
    /// Explicitly exclude packages or versions from a spec
    #[command(name = "exclude")]
    Exclude,
    /// Remove requirements or constraints from a spec
    #[command(name = "drop")]
    Drop,
    /// Add a reference to an external artifact into a spec to stage to the system tree
    #[command(name = "stage")]
    Stage,
    /// Remove a staged artifact from a spec
    #[command(name = "unstage")]
    Unstage,
    /// List resolved packages for a specific spec
    #[command(name = "list")]
    List,
    /// Search packages
    #[command(name = "search")]
    Search,
    /// Show raw package metadata
    #[command(name = "show")]
    Show,
}

#[derive(Parser)]
#[command(
    about = "Create a new manifest file",
    long_about = "Create a new manifest file from a source definition.
If a vendor name is provided as source URL, default sources and packages are derived from it.
Examples:  
    debrepo init --package mc --package libcom-err2 --url debian"
)]
pub struct Init {
    /// Overwrite existing manifest if present
    #[arg(long)]
    pub force: bool,

    /// Package to add (can be used multiple times)
    #[arg(short = 'r', long = "package", value_name = "PACKAGE")]
    requirements: Vec<String>,

    /// Source definition (i.e. --url <URL> ...).
    /// URL might be a vendor name (debian, ubuntu, devuan).
    #[command(flatten)]
    source: Source,
}

impl Command for Init {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let (sources, packages, comment) =
                if let Some((sources, mut packages)) = self.source.as_vendor() {
                    if !self.requirements.is_empty() {
                        packages.extend(self.requirements.iter().cloned());
                        packages = packages.into_iter().unique().collect();
                    }
                    (
                        sources,
                        packages,
                        Some(format!("default manifest file for {}", &self.source.url)),
                    )
                } else {
                    (vec![self.source.clone()], self.requirements.clone(), None)
                };
            let mut mf =
                Manifest::from_sources(&conf.arch, sources.iter().cloned(), comment.as_deref());
            mf.add_requirements(None, packages.iter(), None)?;
            mf.update(true, conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
#[command(
    about = "Remove requirements or constraints from a spec",
    long_about = "Remove requirements and/or constraints from a spec
Use --requirements-only or --constraints-only to limit the operation scope."
)]
struct Drop {
    /// Drop only requirements (do not touch constraints)
    #[arg(
        short = 'R',
        long = "requirements-only",
        conflicts_with = "constraints_only"
    )]
    requirements_only: bool,

    /// Drop only constraints (do not touch requirements)
    #[arg(
        short = 'C',
        long = "constraints-only",
        conflicts_with = "requirements_only"
    )]
    constraints_only: bool,

    /// The spec name to modify
    #[arg(short = 's', long = "spec", value_name = "SPEC")]
    spec: Option<String>,

    /// Package name or package version set
    #[arg(value_name = "CONSTRAINT")]
    cons: Vec<String>,
}

impl Command for Drop {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            if !self.constraints_only {
                mf.remove_requirements(self.spec.as_deref(), self.cons.iter())?;
            }
            if !self.requirements_only {
                mf.remove_constraints(self.spec.as_deref(), self.cons.iter())?;
            }
            mf.update(false, conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Stage {
    /// Spec name to stage the artifact
    #[arg(short = 's', long = "spec", value_name = "SPEC")]
    spec: Option<String>,
    /// A comment for the staged artifact
    #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
    comment: Option<String>,
    #[command(flatten)]
    artifact: ArtifactArg,
}

impl Command for Stage {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            mf.add_artifact(
                self.spec.as_deref(),
                &self.artifact,
                self.comment.as_deref(),
                conf.transport().await?.as_ref(),
            )
            .await?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Unstage {
    /// Spec name to unstage the artifact from
    #[arg(short = 's', long = "spec", value_name = "SPEC")]
    spec: Option<String>,
    /// Artifact URL or path
    #[arg(value_name = "URL")]
    url: String,
}

impl Command for Unstage {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            mf.remove_artifact(self.spec.as_deref(), &self.url)?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Include {
    #[arg(short = 's', long = "spec", value_name = "SPEC")]
    spec: Option<String>,
    #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
    comment: Option<String>,
    #[arg(value_name = "REQUIREMENT", value_parser = debrepo::cli::DependencyParser)]
    reqs: Vec<Dependency<String>>,
}

impl Command for Include {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            mf.add_requirements(
                self.spec.as_deref(),
                self.reqs.iter(),
                self.comment.as_deref(),
            )?;
            mf.update(false, conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Exclude {
    #[arg(short = 's', long = "spec", value_name = "SPEC")]
    spec: Option<String>,
    #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
    comment: Option<String>,
    #[arg(value_name = "CONSTRAINT", value_parser = debrepo::cli::ConstraintParser)]
    reqs: Vec<Constraint<String>>,
}

impl Command for Exclude {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            mf.add_constraints(
                self.spec.as_deref(),
                self.reqs.iter(),
                self.comment.as_deref(),
            )?;
            mf.update(false, conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Update {
    #[arg(short = 'f', long = "force", action)]
    force: bool,
    #[arg(short = 's', long = "snapshot", value_name = "SNAPSHOT_ID", value_parser = debrepo::cli::SnapshotIdArgParser)]
    snapshot: Option<SnapshotId>,
}

impl Command for Update {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            if let Some(snapshot) = &self.snapshot {
                mf.set_snapshot(*snapshot);
            }
            mf.update(
                self.force,
                conf.concurrency,
                conf.transport().await?.as_ref(),
            )
            .await?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Search {
    #[arg(short = 'p', long = "names-only")]
    names_only: bool,
    #[arg(value_name = "PATTERN")]
    pattern: Vec<String>,
}

impl Command for Search {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            mf.update(false, conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            let res = self
                .pattern
                .iter()
                .map(|p| {
                    regex::RegexBuilder::new(p)
                        .unicode(true)
                        .case_insensitive(true)
                        .build()
                        .map_err(|err| anyhow!("invalid regex: {}", err))
                })
                .collect::<Result<Vec<_>>>()?;
            let mut pkgs = mf
                .packages()
                .filter(|p| {
                    res.iter().any(|re| {
                        re.is_match(p.name())
                            || (!self.names_only
                                && re.is_match(p.field("Description").unwrap_or("")))
                    })
                })
                .collect::<Vec<_>>();
            pkgs.sort_by_key(|&pkg| pkg.name());
            let mut out = std::io::stdout().lock();
            pretty_print_packages(&mut out, pkgs, false)?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Show {
    #[arg(value_name = "PACKAGE")]
    package: String,
}

impl Command for Show {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            mf.update(false, conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            let pkg = mf.packages().find(|p| self.package == p.name());
            if let Some(pkg) = pkg {
                let mut out = async_io::Async::new(std::io::stdout().lock())?;
                out.write_all(pkg.src().as_bytes()).await?;
                Ok(())
            } else {
                Err(anyhow!("package {} not found", &self.package))
            }
        })
    }
}

#[derive(Parser)]
struct List {
    #[arg(short = 'e', long = "only-essential", hide = true)]
    only_essential: bool,
    /// The spec name to list installables from
    #[arg(short = 's', long = "spec", value_name = "SPEC")]
    spec: Option<String>,
}

impl Command for List {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            mf.update(false, conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await
                .map_err(|e| anyhow!("failed to update specs: {e}"))?;
            let mut pkgs = mf
                .spec_packages(self.spec.as_deref())?
                .filter(|p| !self.only_essential || p.essential())
                .collect::<Vec<_>>();
            pkgs.sort_by_key(|&pkg| pkg.name());
            let mut out = std::io::stdout().lock();
            pretty_print_packages(&mut out, pkgs, false)?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Build {
    /// The spec name to build
    #[arg(short = 's', long = "spec", value_name = "SPEC")]
    spec: Option<String>,
    /// The target directory
    #[arg(short, long, value_name = "PATH")]
    path: PathBuf,
}

impl Command for Build {
    fn exec(&self, conf: &App) -> Result<()> {
        let mut builder = HostSandboxExecutor::new(&self.path)?;
        smol::block_on(async move {
            let manifest = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            fs::create_dir_all(&self.path).await?;
            let mut fs =
                debrepo::HostFileSystem::new(&self.path, rustix::process::geteuid().is_root())
                    .await?;
            let (essentials, other, scripts) = manifest
                .stage(
                    self.spec.as_deref(),
                    &mut fs,
                    conf.concurrency,
                    conf.transport().await?.as_ref(),
                )
                .await?;
            builder.build(&mut fs, essentials, other, scripts).await?;
            Ok(())
        })
    }
}

struct Package<'a> {
    name: &'a str,
    arch: &'a str,
    ver: Version<&'a str>,
    desc: &'a str,
    prio: debrepo::InstallPriority,
}

impl<'a> From<&'a debrepo::Package<'a>> for Package<'a> {
    fn from(pkg: &'a debrepo::Package<'a>) -> Self {
        Self {
            name: pkg.name(),
            arch: pkg.arch(),
            ver: pkg.raw_version(),
            desc: pkg.field("Description").unwrap_or(""),
            prio: pkg.install_priority(),
        }
    }
}

fn pretty_print_packages<'a, W: std::io::Write>(
    f: &mut W,
    iter: impl IntoIterator<Item = &'a debrepo::Package<'a>>,
    sort: bool,
) -> Result<usize> {
    let mut w0 = 0usize;
    let mut w1 = 0usize;
    let mut w2 = 0usize;
    let mut w3 = 0usize;
    let mut w4 = 0usize;
    let mut packages = iter
        .into_iter()
        .map(Package::try_from)
        .map(|pkg| {
            let pkg = pkg?;
            w0 = std::cmp::max(w0, pkg.arch.len());
            w1 = std::cmp::max(w1, pkg.prio.as_ref().len());
            w2 = std::cmp::max(w2, pkg.name.len());
            w3 = std::cmp::max(w3, pkg.ver.as_ref().len());
            w4 = std::cmp::max(w4, pkg.desc.len());
            Ok(pkg)
        })
        .collect::<Result<Vec<_>>>()?;
    if sort {
        packages.sort_by(|this, that| match this.name.cmp(that.name) {
            std::cmp::Ordering::Equal => this.ver.cmp(&that.ver),
            other => other,
        });
    }
    for p in packages.iter() {
        writeln!(
            f,
            "{:>w0$} {:<w2$} {:>w3$} {:<w4$}",
            p.arch, p.name, p.ver, p.desc
        )?;
    }
    Ok(packages.len())
}

impl App {
    async fn transport(&self) -> Result<Box<dyn TransportProvider>> {
        if let Some(cache) = &self.cache_dir {
            Ok(Box::new(
                HttpCachingTransportProvider::new(self.insecure, cache.clone())
                    .await
                    .map_err(|e| anyhow!("failed to create transport provider: {e}"))?,
            ))
        } else {
            Ok(Box::new(HttpTransportProvider::new(self.insecure)))
        }
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
            .map(|base| base.join("debrepo"))
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
