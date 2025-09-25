use {
    anyhow::{anyhow, Result}, clap::{Parser, Subcommand}, debrepo::{
        cli::{Source},
        exec::{unshare_root, unshare_user_ns},
        version::{Constraint, Dependency, Version},
        HttpCachingTransportProvider, HttpTransportProvider, Manifest, TransportProvider,
    }, futures::AsyncWriteExt, itertools::Itertools, smol::fs, std::{num::NonZero, path::PathBuf, process::ExitCode}, tracing::level_filters::LevelFilter, tracing_subscriber::{filter::EnvFilter, fmt}
};

#[async_trait::async_trait(?Send)]
#[enum_dispatch::enum_dispatch]
pub trait AsyncCommand {
    fn init(&self, _conf: &App) -> Result<()> {
        Ok(())
    }
    async fn exec(&self, conf: &App) -> Result<()>;
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
    #[arg(
        short = 'K',
        long = "no-verify",
        display_order = 0,
        action
    )]
    pub insecure_release: bool,

    /// Skip the connection verification (not recommended)
    #[arg(
        short = 'k',
        long = "insecure",
        action,
        display_order = 0,
        action
    )]
    pub insecure: bool,

    /// Manifest file
    #[arg(global = true, short, long, default_value = Manifest::DEFAULT_FILE, display_order = 0)]
    manifest: PathBuf,

    #[command(subcommand)]
    cmd: Commands,
}

#[enum_dispatch::enum_dispatch(AsyncCommand)]
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
    /// Include a package or packages into the recipe  
    #[command(name = "include")]
    Include,
    /// Exlicitly exclude a package or packages from the recipe  
    #[command(name = "exclude")]
    Exclude,
    /// Remove a package or packages from the recipe
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

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Init {
    async fn exec(&self, conf: &App) -> Result<()> {
        let (sources, packages, comment) = if let Some((sources, mut packages)) = self.source.as_vendor() {
            if !self.requirements.is_empty() {
               packages.extend(self.requirements.iter().cloned());
                packages = packages.into_iter().unique().collect();
            }
            (sources, packages, Some(format!("default manifest file for {}", &self.source.url)) )
        } else {
            (vec![self.source.clone()], self.requirements.clone(), None)
        };
        let mut mf = Manifest::from_sources(&conf.arch, sources.iter().cloned(), comment);
        mf.add_requirements(None, packages.iter(), None::<&str>)?;
        mf.resolve(conf.concurrency.into(), conf.transport().await?.as_ref()).await?;
        mf.store(&conf.manifest).await?;
        Ok(())
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
    /// The recipe name to modify.
    #[arg(short = 'r', long = "recipe", value_name = "RECIPE")]
    recipe: Option<String>,
    /// Package name or package version set
    #[arg(value_name = "CONSTRAINT")]
    cons: Vec<String>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Drop {
    async fn exec(&self, conf: &App) -> Result<()> {
        let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
        if !self.constraints_only {
            mf.drop_requirements(self.recipe.as_deref(), self.cons.iter())?;
        }
        if !self.requirements_only {
            mf.drop_constraints(self.recipe.as_deref(), self.cons.iter())?;
        }
        mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
            .await?;
        mf.store(&conf.manifest).await?;
        Ok(())
    }
}

#[derive(Parser)]
struct Include {
    #[arg(short = 'r', long = "recipe", value_name = "RECIPE")]
    recipe: Option<String>,
    #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
    comment: Option<String>,
    #[arg(value_name = "REQUIREMENT", value_parser = debrepo::cli::DependencyParser)]
    reqs: Vec<Dependency<String>>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Include {
    async fn exec(&self, conf: &App) -> Result<()> {
        let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
        mf.add_requirements(
            self.recipe.as_deref(),
            self.reqs.iter(),
            self.comment.as_deref(),
        )?;
        mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
            .await?;
        mf.store(&conf.manifest).await?;
        Ok(())
    }
}

#[derive(Parser)]
struct Exclude {
    #[arg(short = 'r', long = "recipe", value_name = "RECIPE")]
    recipe: Option<String>,
    #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
    comment: Option<String>,
    #[arg(value_name = "CONSTRAINT", value_parser = debrepo::cli::ConstraintParser)]
    reqs: Vec<Constraint<String>>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Exclude {
    async fn exec(&self, conf: &App) -> Result<()> {
        let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
        mf.add_constraints(
            self.recipe.as_deref(),
            self.reqs.iter(),
            self.comment.as_deref(),
        )?;
        mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
            .await?;
        mf.store(&conf.manifest).await?;
        Ok(())
    }
}

#[derive(Parser)]
struct Update {}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Update {
    async fn exec(&self, conf: &App) -> Result<()> {
        Ok(())
    }
}

#[derive(Parser)]
struct Lock {}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Lock {
    async fn exec(&self, conf: &App) -> Result<()> {
        let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
        mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
            .await?;
        mf.store(&conf.manifest).await?;
        Ok(())
    }
}

#[derive(Parser)]
struct Search {
    #[arg(short = 'p', long = "names-only")]
    names_only: bool,
    #[arg(value_name = "PATTERN")]
    pattern: Vec<String>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Search {
    async fn exec(&self, conf: &App) -> Result<()> {
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
            .filter_map(|p| {
                res.iter()
                    .any(|re| {
                        re.is_match(p.name())
                            || (!self.names_only
                                && re.is_match(p.field("Description").unwrap_or("")))
                    })
                    .then_some(p)
            })
            .collect::<Vec<_>>();
        pkgs.sort_by_key(|&pkg| pkg.name());
        let mut out = std::io::stdout().lock();
        pretty_print_packages(&mut out, pkgs, false)?;
        Ok(())
    }
}

#[derive(Parser)]
struct Show {
    #[arg(value_name = "PACKAGE")]
    package: String,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Show {
    async fn exec(&self, conf: &App) -> Result<()> {
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
    }
}

#[derive(Parser)]
struct List {
    #[arg(short = 'e', long = "only-essential", hide = true)]
    only_essential: bool,
    /// The recipe name to build (default is the primary nameless recipe)
    #[arg(short = 'r', long = "recipe", value_name = "RECIPE")]
    recipe: Option<String>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for List {
    async fn exec(&self, conf: &App) -> Result<()> {
        let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
        mf.resolve(conf.concurrency, conf.transport().await?.as_ref())
            .await
            .map_err(|e| anyhow!("failed to update recipes: {e}"))?;
        let mut pkgs = mf
            .recipe_packages(self.recipe.as_deref())?
            .filter_map(|p| {
                if self.only_essential {
                    p.essential().then_some(p)
                } else {
                    Some(p)
                }
            })
            .collect::<Vec<_>>();
        pkgs.sort_by_key(|&pkg| pkg.name());
        let mut out = std::io::stdout().lock();
        pretty_print_packages(&mut out, pkgs, false)?;
        mf.store(&conf.manifest).await?;
        Ok(())
    }
}

#[derive(Parser)]
struct Build {
    /// The recipe name to build (default is the primary nameless recipe)
    #[arg(short = 'r', long = "recipe", value_name = "RECIPE")]
    recipe: Option<String>,
    /// The target directory
    #[arg(short, long, value_name = "PATH")]
    path: PathBuf,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Build {
    fn init(&self, _opts: &App) -> Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            unshare_user_ns()?;
        }
        unshare_root()?;
        Ok(())
    }
    async fn exec(&self, conf: &App) -> Result<()> {
        let manifest = Manifest::from_file(&conf.manifest, &conf.arch).await?;
        fs::create_dir_all(&self.path).await?;
        let fs = std::sync::Arc::new(
            debrepo::LocalFileSystem::new(&self.path, nix::unistd::Uid::effective().is_root())
                .await?,
        );
        {
            let builder = debrepo::builder::Builder::new(&fs);
            builder
                .build(
                    &manifest,
                    self.recipe.as_deref(),
                    conf.concurrency,
                    conf.transport().await?.as_ref(),
                )
                .await?;
        }
        Ok(())
    }
}

#[derive(Parser)]
struct Extract {
    /// The recipe name to build (default is the primary nameless recipe)
    #[arg(short = 'r', long = "recipe", value_name = "RECIPE")]
    recipe: Option<String>,
    /// The target directory
    #[arg(short, long, value_name = "PATH")]
    path: PathBuf,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Extract {
    fn init(&self, _opts: &App) -> Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            unshare_user_ns()?;
        }
        unshare_root()?;
        Ok(())
    }
    async fn exec(&self, conf: &App) -> Result<()> {
        let manifest = Manifest::from_file(&conf.manifest, &conf.arch).await?;
        fs::create_dir_all(&self.path).await?;
        let fs = std::sync::Arc::new(
            debrepo::LocalFileSystem::new(&self.path, nix::unistd::Uid::effective().is_root())
                .await?,
        );
        // let fs = std::sync::Arc::new(debrepo::FileList::new());
        {
            let builder = debrepo::builder::Builder::new(&fs);
            builder
                .extract_recipe(
                    &manifest,
                    self.recipe.as_deref(),
                    conf.concurrency,
                    conf.transport().await?.as_ref(),
                )
                .await?;
        }
        // std::sync::Arc::into_inner(fs)
        //     .unwrap()
        //     .keep(&self.path)
        //     .await?;
        // let manifest = Manifest::from_file(&conf.manifest).await?;
        // let repo_builder: Box<dyn DebRepoBuilder> = if let Some(cache) = &conf.cache_dir {
        //     Box::new(HttpCachingRepoBuilder::new(conf.insecure, cache.clone()).await?)
        // } else {
        //     Box::new(HttpRepoBuilder::new(conf.insecure))
        // };
        // let mut universe = manifest
        //     .fetch_universe(&conf.arch, &repo_builder, conf.limit)
        //     .await?;
        // let (reqs, cons) =
        //     manifest.requirements_for(self.recipe.as_ref().map(|s| s.as_ref()).unwrap_or(""))?;
        // let solution = universe.solve(reqs, cons).map_err(|conflict| {
        //     anyhow!(
        //         "failed to solve dependencies: {}",
        //         universe.display_conflict(conflict)
        //     )
        // })?;
        // let essentials = solution
        //     .iter()
        //     .filter_map(|id| {
        //         universe.package(*id).and_then(|pkg| {
        //             if pkg.essential() {
        //                 Some(pkg.name())
        //             } else {
        //                 None
        //             }
        //         })
        //     })
        //     .collect::<Vec<_>>();
        // fs::create_dir_all(&self.path).await?;
        // let fs = debrepo::LocalFileSystem::new(&self.path, nix::unistd::Uid::effective().is_root())
        //     .await?;
        // let mut control_file = stream::iter(solution.iter().cloned())
        //     .map(|id| {
        //         let (deb, package) = (
        //             universe.deb_reader(id),
        //             universe.package(id).unwrap().raw_full_name(),
        //         );
        //         let fs = fs.clone();
        //         async move {
        //             match deb.await {
        //                 Ok(deb) => {
        //                     tracing::info!("unpacking {}...", package);
        //                     let mut stanza = async_std::task::block_on(deb.extract_to(&fs))?;
        //                     stanza.set("Status", "install ok unpacked");
        //                     stanza.sort_fields_deb_order();
        //                     Ok::<_, anyhow::Error>(stanza)
        //                 }
        //                 Err(err) => {
        //                     tracing::error!("failed to unpack {}: {}", package, err);
        //                     Err(err.into())
        //                 }
        //             }
        //         }
        //     })
        //     .buffer_unordered(conf.limit)
        //     .try_collect::<Vec<_>>()
        //     .await?;
        // control_file.sort_by(|a, b| a.field("Package").unwrap().cmp(b.field("Package").unwrap()));
        // fs.create_dir_all("etc/apt", 0, 0, 0o755u32).await?;
        // {
        //     let sources: Vec<u8> = manifest
        //         .sources()
        //         .map(|s| s.into())
        //         .collect::<MutableControlFile>()
        //         .into();
        //     fs.create_file(
        //         sources.as_slice(),
        //         Some("etc/apt/sources.list"),
        //         0,
        //         0,
        //         0o644,
        //         None,
        //         Some(sources.len()),
        //     )
        //     .await?;
        // }
        // fs.create_dir_all("var/lib/dpkg", 0, 0, 0o755u32).await?;
        // {
        //     let size = control_file.iter().map(|i| i.len() + 1).sum();
        //     let mut status = Vec::<u8>::with_capacity(size);
        //     for i in control_file.into_iter() {
        //         status.write_all(format!("{}", &i).as_bytes()).await?;
        //         status.write_all(&[b'\n']).await?;
        //     }
        //     fs.create_file(
        //         status.as_slice(),
        //         Some("var/lib/dpkg/status"),
        //         0,
        //         0,
        //         0o644,
        //         None,
        //         Some(size),
        //     )
        //     .await?;
        // }
        // fs.create_dir_all("usr/sbin", 0, 0, 0o755u32).await?;
        // fs.create_file(
        //     b"#!/bin/sh\nexit 101\n".as_slice(),
        //     Some("usr/sbin/policy-rc.d"),
        //     0,
        //     0,
        //     0o755,
        //     None,
        //     None,
        // )
        // .await?;
        // let env = ["DEBIAN_FRONTEND=noninteractive"];
        // dpkg(
        //     &self.path,
        //     ["--force-depends", "--configure"]
        //         .iter()
        //         .chain(essentials.iter()),
        //     Some(&env),
        // )?;
        // dpkg(&self.path, ["--configure", "-a"], Some(&env))?;
        // fs.remove_file("usr/sbin/policy-rc.d").await?;
        Ok(())
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

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Fetch {
    async fn exec(&self, conf: &App) -> Result<()> {
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

fn main() -> ExitCode {
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
    if let Err(err) = app.cmd.init(&app) {
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    }
    match smol::block_on(app.cmd.exec(&app)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            println!("{}", err);
            ExitCode::FAILURE
        }
    }
}
