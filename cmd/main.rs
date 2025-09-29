use {
    anyhow::{anyhow, Result},
    clap::{Parser, Subcommand},
    debrepo::{
        builder::{BuildRunner, Builder, SimpleBuilder},
        cli::Source,
        version::{Constraint, Dependency, Version},
        HttpCachingTransportProvider, HttpTransportProvider, Manifest, TransportProvider,
        DEFAULT_SPEC_NAME,
    },
    futures::AsyncWriteExt,
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

    /// Target architecture
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

    /// Manifest file
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
    /// Fetch artefact
    #[command(name = "fetch", hide = true)]
    Fetch,
    /// Update lock file
    #[command(name = "update")]
    Update,
    /// Extract system to a target directory
    #[command(name = "extract")]
    Extract,
    /// Extract system to a target directory
    #[command(name = "build")]
    Build,
    /// Include a package or packages into the spec
    #[command(name = "include")]
    Include,
    /// Exlicitly exclude a package or packages from the spec
    #[command(name = "exclude")]
    Exclude,
    /// Remove a package or packages from the spec requirements or constraints
    #[command(name = "drop")]
    Drop,
    /// Lists packages
    #[command(name = "list")]
    List,
    /// Lists packages
    #[command(name = "search")]
    Search,
    /// Show package description
    #[command(name = "show")]
    Show,
    /// Updates lock file
    #[command(name = "lock")]
    Lock,
}

#[derive(Parser)]
pub struct Init {
    /// Overwrite existing manifest if present
    #[arg(long)]
    pub force: bool,

    /// Package to add
    #[arg(short = 'r', long = "package", value_name = "PACKAGE")]
    requirements: Vec<String>,

    /// Source definition
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
            let mut mf = Manifest::from_sources(&conf.arch, sources.iter().cloned(), comment);
            mf.add_requirements(&DEFAULT_SPEC_NAME, packages.iter(), None::<&str>)?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Drop {
    /// Specify to drop only requirements
    #[arg(
        short = 'R',
        long = "requirements-only",
        conflicts_with = "constraints_only"
    )]
    requirements_only: bool,
    /// Specify to drop only constraints
    #[arg(
        short = 'C',
        long = "constraints-only",
        conflicts_with = "requirements_only"
    )]
    constraints_only: bool,
    /// The spec name to modify.
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
                mf.drop_requirements(&self.spec, self.cons.iter())?;
            }
            if !self.requirements_only {
                mf.drop_constraints(&self.spec, self.cons.iter())?;
            }
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
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
            mf.add_requirements(&self.spec, self.reqs.iter(), self.comment.as_deref())?;
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
            mf.add_constraints(&self.spec, self.reqs.iter(), self.comment.as_deref())?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await?;
            mf.store(&conf.manifest).await?;
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Update {}

impl Command for Update {
    fn exec(&self, _conf: &App) -> Result<()> {
        Ok(())
    }
}

#[derive(Parser)]
struct Lock {}

impl Command for Lock {
    fn exec(&self, conf: &App) -> Result<()> {
        smol::block_on(async move {
            let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
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
            mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
                .await
                .map_err(|e| anyhow!("failed to update specs: {e}"))?;
            let mut pkgs = mf
                .spec_packages(&self.spec)?
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
        let _user_ns_unshared = match debrepo::exec::UnshareUserNs::unshare() {
            None => false,
            Some(Ok(())) => true,
            Some(Err(err)) => return Err(err.into()),
        };
        smol::block_on(async move {
            let manifest = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            fs::create_dir_all(&self.path).await?;
            let fs =
                debrepo::LocalFileSystem::new(&self.path, rustix::process::geteuid().is_root())
                    .await?;

            {
                let builder = SimpleBuilder::<debrepo::LocalFileSystem>::new();
                builder
                    .build(
                        &manifest,
                        &self.spec,
                        conf.concurrency,
                        conf.transport().await?.as_ref(),
                        &fs,
                    )
                    .await?;
            }
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Extract {
    /// The spec name to extract
    #[arg(short = 's', long = "spec", value_name = "SPEC")]
    spec: Option<String>,
    /// The target directory
    #[arg(short, long, value_name = "PATH")]
    path: PathBuf,
}

impl Command for Extract {
    fn exec(&self, conf: &App) -> Result<()> {
        let _user_ns_unshared = match debrepo::exec::UnshareUserNs::unshare() {
            None => false,
            Some(Ok(())) => true,
            Some(Err(err)) => return Err(err.into()),
        };
        smol::block_on(async move {
            let manifest = Manifest::from_file(&conf.manifest, &conf.arch).await?;
            fs::create_dir_all(&self.path).await?;
            let fs =
                debrepo::LocalFileSystem::new(&self.path, rustix::process::geteuid().is_root())
                    .await?;
            // let fs = std::sync::Arc::new(debrepo::FileList::new());
            {
                let builder = SimpleBuilder::<debrepo::LocalFileSystem>::new();
                builder
                    .build_tree(
                        manifest
                            .installables(&self.spec)?
                            .collect::<std::io::Result<Vec<_>>>()?,
                        conf.concurrency,
                        conf.transport().await?.as_ref(),
                        &fs,
                    )
                    .await?;
            }
            Ok(())
        })
    }
}

#[derive(Parser)]
struct Fetch {
    /// Architecture
    #[arg(short, long, value_name = "ARCH", default_value = debrepo::DEFAULT_ARCH)]
    arch: String,
    /// Origin repository URL
    #[arg(
        short = 'u',
        long = "url",
        value_name = "URL",
        default_value = "https://ftp.debian.org/debian/"
    )]
    origin: String,
    /// Verify
    #[arg(short = 'v', long = "verify")]
    verify: bool,
    /// Target file name
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    out: Option<PathBuf>,
    /// Distribution name
    #[arg(value_name = "DISTR", default_value = "sid")]
    distr: String,
    /// Component
    #[arg(value_name = "COMPONENT", default_value = "main")]
    comp: String,
}

impl Command for Fetch {
    fn exec(&self, _conf: &App) -> Result<()> {
        // let start = std::time::Instant::now();
        // let repo: DebRepo = HttpDebRepo::new(&self.origin, conf.insecure).await?.into();
        // let release = if self.verify {
        //     repo.fetch_verify_release(&self.distr, iter::empty()).await
        // } else {
        //     repo.fetch_release(&self.distr).await
        // }?;
        // let (path, size, hash) = release
        //     .packages_file(&self.comp, &self.arch)
        //     .ok_or_else(|| anyhow!("Packages file for {} {} not found", &self.arch, &self.comp))?;
        // match self.out {
        //     None => {
        //         repo.copy_verify_unpack(async_std::io::stdout(), &path, size, hash)
        //             .await
        //     }
        //     Some(ref out) => {
        //         let out = async_std::fs::File::create(out).await?;
        //         repo.copy_verify_unpack(out, &path, size, hash).await
        //     }
        // }?;
        // println!("fetched in {:?}", start.elapsed());
        Ok(())
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

// async fn copy_repo_package<'a>(
//     universe: &'a Universe,
//     id: debrepo::PackageId,
//     target: &Path,
// ) -> Result<(debrepo::PackageId, impl std::fmt::Display + 'a, u64)> {
//     let pkg = universe
//         .package(id)
//         .ok_or_else(|| anyhow!("package id {:?} not found", id))?;
//     let path: PathBuf = pkg.ensure_field("Filename")?.into();
//     let mut out = PathBuf::from(target);
//     out.push(path.file_name().unwrap());
//     let out = fs::File::create(out).await?;
//     let size = universe.copy_deb_file(out, id).await?;
//     Ok((id, pkg, size))
// }

// async fn extract_repo_package<'a, F: DeploymentFileSystem>(
//     deb: DebReader<'a>,
//     target: F,
// ) -> Result<MutableControlStanza> {
//     let desc = deb.extract_to(&target).await?;
//     Ok(desc)
// }

impl App {
    async fn transport(&self) -> Result<Box<dyn TransportProvider>> {
        if let Some(cache) = &self.cache_dir {
            Ok(Box::new(
                HttpCachingTransportProvider::new(self.insecure, cache.clone())
                    .await
                    .map_err(|e| anyhow!("failed to create transport provider: {e}"))?,
            ))
        } else {
            Ok(Box::new(HttpTransportProvider::new(self.insecure).await))
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
        .add_directive("isahc::wire=warn".parse().unwrap())
        .add_directive("async_std=warn".parse().unwrap());

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

debrepo::helper! {
    fn helper_main "deb-repo-helper" [
        debrepo::exec::UnshareUserNs,
        BuildRunner,
    ]
}

fn main() -> ExitCode {
    helper_main();
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
