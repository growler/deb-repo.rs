use {
    anyhow::{anyhow, Result},
    async_std::{
        fs,
        io::WriteExt,
        path::{Path, PathBuf},
    },
    clap::{Parser, Subcommand},
    debrepo::{
        cli::{Source, Vendor},
        exec::{dpkg, unshare_root, unshare_user_ns},
        Constraint, Dependency, DeploymentFileSystem, HttpCachingTransportProvider,
        HttpTransportProvider, Manifest, MutableControlFile, TransportProvider, Universe, Version,
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    std::{iter, process::ExitCode},
    tracing::level_filters::LevelFilter,
    tracing_subscriber::{filter::EnvFilter, fmt},
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

    /// Manifest file
    #[arg(short, long, default_value = Manifest::DEFAULT_FILE)]
    manifest: PathBuf,

    /// Number of concurrent downloads
    #[arg(
        short = 'n',
        long = "downloads",
        value_name = "NUM",
        default_value = "20"
    )]
    limit: usize,

    /// Target architecture
    #[arg(short, long, value_name = "ARCH", default_value = debrepo::DEFAULT_ARCH)]
    arch: String,

    /// HTTP download cache directory
    #[arg(long = "cache-dir", value_name = "DIR", conflicts_with = "no_cache")]
    pub cache_dir: Option<PathBuf>,

    #[arg(long = "no-cache", conflicts_with = "cache_dir")]
    pub no_cache: bool,

    /// Do not verify Release files by default (not recommended)
    #[arg(short = 'K', long = "no-verify")]
    pub insecure_release: bool,

    /// Skip the connection verification (not recommended)
    #[arg(short = 'k', long = "insecure", action)]
    pub insecure: bool,

    #[command(subcommand)]
    cmd: Commands,
}

#[enum_dispatch::enum_dispatch(AsyncCommand)]
#[derive(Subcommand)]
enum Commands {
    /// Initialize a new manifest file
    #[command(name = "init")]
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
    // #[command(name = "search")]
    // Search {
    //     #[arg(short, long, value_name = "ARCH", default_value = default_arch())]
    //     arch: String,
    //     /// Origin repository URL
    //     #[arg(
    //         short = 'u',
    //         long = "url",
    //         value_name = "URL",
    //         default_value = "https://ftp.debian.org/debian/"
    //     )]
    //     origin: String,
    //     /// Distribution name
    //     #[arg(
    //         short = 'd',
    //         long = "distr",
    //         value_name = "DISTR",
    //         default_value = "sid"
    //     )]
    //     distr: String,
    //     /// Component
    //     #[arg(
    //         short = 'c',
    //         long = "component",
    //         value_name = "COMPONENT",
    //         default_value = "all"
    //     )]
    //     comp: String,
    //     /// name
    //     #[arg(value_name = "NAME")]
    //     name: String,
    // },
}

#[derive(Parser)]
pub struct Init {
    /// Overwrite existing manifest if present
    #[arg(long)]
    pub force: bool,

    #[command(subcommand)]
    cmd: InitCommands,
}

#[derive(Subcommand)]
enum InitCommands {
    /// Initialize manifest for a source definition
    #[command(name = "from-source")]
    InitFromSource(InitFromSource),
    /// Initialize manifest for a known vendor (Debian, Devuan, Ubuntu)
    #[command(name = "from-vendor")]
    InitFromVendor(InitFromVendor),
}

#[derive(Parser, Default)]
pub struct InitFromSource {
    /// Package to add
    #[arg(short = 'r', long = "package", value_name = "PACKAGE")]
    requirements: Vec<String>,
    /// Source definition
    #[command(flatten)]
    source: Source,
}

#[derive(Parser, Default)]
pub struct InitFromVendor {
    /// Vendor
    pub vendor: Vendor,

    /// Suite
    pub suite: Option<String>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Init {
    async fn exec(&self, conf: &App) -> Result<()> {
        let comment = match &self.cmd {
            InitCommands::InitFromSource(_) => None,
            InitCommands::InitFromVendor(cmd) => {
                Some(format!("default manifest file for {}", &cmd.vendor))
            }
        };
        let transport = conf.transport().await?;
        let mut mf = match &self.cmd {
            InitCommands::InitFromSource(cmd) => Manifest::from_sources(
                &conf.arch,
                iter::once(&cmd.source),
                comment,
                conf.limit,
                transport.as_ref(),
            )
            .await
            .map_err(|e| anyhow!("failed to add source: {e}"))?,
            InitCommands::InitFromVendor(cmd) => {
                let sources = cmd
                    .vendor
                    .sources_for(
                        cmd.suite
                            .as_ref()
                            .map(|s| s.as_str())
                            .unwrap_or_else(|| cmd.vendor.defailt_suite()),
                    );
                Manifest::from_sources(&conf.arch, sources.iter(), comment, conf.limit, transport.as_ref())
                    .await
                    .map_err(|e| anyhow!("failed to add sources: {e}"))?
            }
        };
        for req in match &self.cmd {
            InitCommands::InitFromSource(cmd) => cmd
                .requirements
                .iter()
                .map(|s| {
                    s.parse::<Dependency<String>>()
                        .map_err(|e| anyhow!("failed to parse requirement '{s}': {e}"))
                })
                .collect::<Result<Vec<_>>>()?,
            InitCommands::InitFromVendor(cmd) => cmd
                .vendor
                .default_requirements()
                .iter()
                .map(|s| {
                    s.parse::<Dependency<String>>()
                        .map_err(|e| anyhow!("failed to parse requirement '{s}': {e}"))
                })
                .collect::<Result<Vec<_>>>()?,
        } {
            mf.add_requirement("", &req, None::<String>)
                .map_err(|e| anyhow!("invalid manifest: failed to add requirement: {e}"))?;
        }
        mf.update_recipes(conf.limit, transport.as_ref()).await?;
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
    requirements_only: Option<bool>,
    /// Specify to drop only constraints
    #[arg(
        short = 'C',
        long = "constraints-only",
        conflicts_with = "requirements_only"
    )]
    constraints_only: Option<bool>,
    /// The recipe name to modify (by default drop from all recipes).
    /// Use "" to specify the primary recipe.
    #[arg(short = 'r', long = "recipe", value_name = "RECIPE")]
    recipe: Option<String>,
    /// Package name or package version set
    #[arg(value_name = "CONSTRAINT", value_parser = debrepo::cli::ConstraintParser)]
    name: Vec<Constraint<String>>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Drop {
    async fn exec(&self, conf: &App) -> Result<()> {
        let mut mf = Manifest::from_file(&conf.manifest, &conf.arch).await?;
        let recipes = self
            .recipe
            .as_ref()
            .map(|s| vec![s.to_string()])
            .unwrap_or_else(|| mf.recipes().map(|s| s.into()).collect::<Vec<String>>());
        for recipe in recipes.into_iter() {
            self.name.iter().try_for_each(|con| {
                mf.drop_constraint(&recipe, con)
                    .map_err(|e| anyhow!("invalid manifest: failed to drop constraint: {e}"))
                // if self.requirements_only.unwrap_or(false) {
                //     mf.remove_requirement(&recipe, con)
                //         .map_err(|e| anyhow!("invalid manifest: failed to drop requirement: {e}"))
                // } else if self.constraints_only.unwrap_or(false) {
                //     mf.remove_constraint(&recipe, &con)
                //         .map_err(|e| anyhow!("invalid manifest: failed to drop constraint: {e}"))
                // } else {
                //     mf.remove_requirement(&recipe, con)
                //         .or_else(|_| mf.remove_constraint(&recipe, con))
                //         .map_err(|e| {
                //             anyhow!(
                //                 "invalid manifest: failed to drop requirement or constraint: {e}"
                //             )
                //         })
                // }
            })?;
        }
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
        let recipe = self.recipe.clone().unwrap_or_default();
        let mut comment = self.comment.clone();
        self.reqs.iter().try_for_each(|req| {
            mf.add_requirement(&recipe, &req, comment.take())
                .map_err(|e| anyhow!("invalid manifest: failed to add requirement: {e}"))
        })?;
        mf.update_recipes(conf.limit, conf.transport().await?.as_ref())
            .await
            .map_err(|e| anyhow!("failed to update recipes: {e}"))?;
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
        let recipe = self.recipe.clone().unwrap_or_default();
        let mut comment = self.comment.clone();
        self.reqs.iter().try_for_each(|con| {
            mf.add_constraint(&recipe, &con, comment.take())
                .map_err(|e| anyhow!("invalid manifest: failed to add requirement: {e}"))
        })?;
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
        // let manifest =
        //     Manifest::from_reader(async_std::fs::File::open(&conf.manifest).await?).await?;
        // let repo_builder =
        //     HttpCachingRepoBuilder::new(conf.insecure, conf.cache.clone().into()).await?;
        // let mut universe = manifest
        //     .fetch_universe(&conf.arch, &repo_builder, conf.limit)
        //     .await?;
        // match universe.Solve(
        //     manifest.requirements().cloned(),
        //     manifest.constraints().cloned(),
        // ) {
        //     Ok(mut solution) => {
        //         solution.sort_by_key(|&pkg| universe.package(pkg).unwrap().name());
        //         let mut out = std::io::stdout().lock();
        //         pretty_print_packages(
        //             &mut out,
        //             solution
        //                 .into_iter()
        //                 .map(|s| -> Package { universe.package(s).unwrap().into() }),
        //             false,
        //         )?;
        //         Ok(())
        //     }
        //     Err(conflict) => Err(anyhow!(
        //         "failed to solve dependencies: {}",
        //         universe.display_conflict(conflict)
        //     )),
        // }
    }
}

#[derive(Parser)]
struct List {
    /// The recipe name to build (default is the primary nameless recipe)
    #[arg(short = 'r', long = "recipe", value_name = "RECIPE")]
    recipe: Option<String>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for List {
    async fn exec(&self, conf: &App) -> Result<()> {
        let manifest = Manifest::from_file(&conf.manifest, &conf.arch).await?;
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
        // let mut solution = universe.solve(reqs, cons).map_err(|conflict| {
        //     anyhow!(
        //         "failed to solve dependencies: {}",
        //         universe.display_conflict(conflict)
        //     )
        // })?;
        // solution.sort_by_key(|&pkg| universe.package(pkg).unwrap().name());
        // let mut out = std::io::stdout().lock();
        // pretty_print_packages(
        //     &mut out,
        //     solution.iter().map(|s| universe.package(*s).unwrap()),
        //     false,
        // )?;
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
        .map(|pkg| Package::try_from(pkg))
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

// async fn cmd(cli: App) -> Result<ExitCode> {
//     match cli.cmd {
//         Command::Fetch {
//             arch: a,
//             origin,
//             out,
//             distr,
//             comp,
//         } => {
//             let start = std::time::Instant::now();
//             let repo: DebRepo = HttpDebRepo::new(&origin).await?.into();
//             let release = repo.fetch_release(&distr).await?;
//             let (path, size, hash) = release
//                 .packages_file(&comp, &a)
//                 .ok_or_else(|| anyhow!("Packages file for {} {} not found", &a, &comp))?;
//             match out {
//                 None => {
//                     repo.copy_verify_unpack(async_std::io::stdout(), &path, size, hash)
//                         .await
//                 }
//                 Some(out) => {
//                     let out = async_std::fs::File::create(out).await?;
//                     repo.copy_verify_unpack(out, &path, size, hash).await
//                 }
//             }?;
//             println!("fetched in {:?}", start.elapsed());
//             Ok(ExitCode::SUCCESS)
//         }
//         Command::Search {
//             arch,
//             origin,
//             distr,
//             comp,
//             name,
//         } => {
//             let start = std::time::Instant::now();
//             let repo: DebRepo = HttpDebRepo::new(&origin).await?.into();
//             let release = repo
//                 .fetch_verify_release_with_keys(&distr, [debrepo::DEBIAN_KEYRING])
//                 .await?;
//             let components = if &comp == "all" {
//                 release.components().collect::<Vec<&'_ str>>()
//             } else {
//                 comp.split(',').map(|s| s.trim()).collect::<Vec<&'_ str>>()
//             };
//             let packages = join_all(
//                 components
//                     .iter()
//                     .map(|comp| release.fetch_packages(comp, &arch)),
//             )
//             .await
//             .into_iter()
//             .collect::<io::Result<Vec<_>>>()?;
//             let universe = Universe::new(&arch, packages)?;
//             let re = regex::RegexBuilder::new(&name)
//                 .case_insensitive(true)
//                 .build()?;
//             let mut out = std::io::stdout().lock();
//             match pretty_print_packages(
//                 &mut out,
//                 universe
//                     .packages()
//                     .map(|p| -> Package { p.into() })
//                     .filter(|p| re.is_match(p.name) || re.is_match(p.desc)),
//                 true,
//             )? {
//                 0 => {
//                     println!("not found in {:?}", start.elapsed());
//                     Ok(ExitCode::FAILURE)
//                 }
//                 n => {
//                     println!("found {} in {:?}", n, start.elapsed());
//                     Ok(ExitCode::SUCCESS)
//                 }
//             }
//         }
//         Command::Solve {
//             arch,
//             origin,
//             distr,
//             comp,
//             print_graph,
//             fetch,
//             extract,
//             target,
//             limit,
//             reqs,
//         } => {
//             let start = std::time::Instant::now();
//             let requirements = reqs
//                 .iter()
//                 .map(|s| Dependency::try_from(s.as_ref()).map_err(|err| err.into()))
//                 .collect::<Result<Vec<_>>>()?;
//             let repo: DebRepo = HttpDebRepo::new(&origin).await?.into();
//             let release = repo.fetch_release(&distr).await?;
//             let components = if &comp == "all" {
//                 release.components().collect::<Vec<&'_ str>>()
//             } else {
//                 comp.split(',').map(|s| s.trim()).collect::<Vec<&'_ str>>()
//             };
//             let packages = join_all(
//                 components
//                     .iter()
//                     .map(|comp| release.fetch_packages(comp, &arch)),
//             )
//             .await
//             .into_iter()
//             .collect::<io::Result<Vec<_>>>()?;
//             let mut universe = Universe::new(&arch, packages)?;
//             match universe.solve(requirements, std::iter::empty()) {
//                 Ok(mut solution) => {
//                     if extract {
//                         let fs = debrepo::LocalFileSystem::new(
//                             &target,
//                             nix::unistd::Uid::effective().is_root(),
//                         )
//                         .await?;
//                         let mut control_file: Vec<MutableControlStanza> = vec![];
//                         let mut stream = FuturesUnordered::new();
//                         let mut pending = solution.into_iter();
//                         for _ in 0..limit {
//                             if let Some(id) = pending.next() {
//                                 stream.push(extract_repo_package(&universe, id, &fs));
//                             }
//                         }
//                         while let Some(result) = stream.next().await {
//                             match result {
//                                 Ok(mut stanza) => {
//                                     stanza.set("Status", "install ok unpacked");
//                                     stanza.sort_fields_deb_order();
//                                     control_file.push(stanza)
//                                 }
//                                 Err(err) => return Err(err),
//                             }
//                             if let Some(id) = pending.next() {
//                                 stream.push(extract_repo_package(&universe, id, &fs));
//                             }
//                         }
//                         control_file.sort_by(|a, b| {
//                             a.field("Package").unwrap().cmp(b.field("Package").unwrap())
//                         });
//                         {
//                             let mut target = PathBuf::from(&target);
//                             target.push("var/lib/dpkg");
//                             fs::create_dir_all(&target).await?;
//                             target.push("status");
//                             let mut out = fs::File::create(target).await?;
//                             for i in control_file.into_iter() {
//                                 out.write_all(format!("{}", &i).as_bytes()).await?;
//                                 out.write_all(&[b'\n']).await?;
//                             }
//                         };
//
//                         println!("solved and fetched in {:?}", start.elapsed());
//                     } else if fetch {
//                         let mut stream = FuturesUnordered::new();
//                         let mut pending = solution.into_iter();
//                         for _ in 0..limit {
//                             if let Some(id) = pending.next() {
//                                 stream.push(copy_repo_package(&universe, id, &target));
//                             }
//                         }
//                         while let Some(result) = stream.next().await {
//                             match result {
//                                 Ok((_, name, size)) => println!("{} {}", name, size),
//                                 Err(err) => println!("Failed to download: {}", err),
//                             }
//                             if let Some(id) = pending.next() {
//                                 stream.push(copy_repo_package(&universe, id, &target));
//                             }
//                         }
//                         println!("solved and fetched in {:?}", start.elapsed());
//                     } else {
//                         use petgraph::dot::{Config, Dot};
//                         let mut out = std::io::stdout().lock();
//                         if let Some(format) = print_graph {
//                             let graph = universe.dependency_graph(&mut solution);
//                             if format.eq_ignore_ascii_case("dot") {
//                                 println!(
//                                     "{:?}",
//                                     Dot::with_attr_getters(
//                                         &graph,
//                                         &[Config::EdgeNoLabel, Config::NodeNoLabel],
//                                         &|_, _| "".to_owned(),
//                                         &|_, id| format!(
//                                             "label = \"{}\"",
//                                             universe.display_solvable(id.0)
//                                         )
//                                     )
//                                 );
//                             } else {
//                                 let ordered = petgraph::algo::kosaraju_scc(&graph)
//                                     .into_iter()
//                                     .flat_map(|g| g.into_iter());
//                                 for id in ordered {
//                                     println!("{}", universe.display_solvable(id));
//                                     let mut has_deps = false;
//                                     for (i, dep) in graph.neighbors(id).enumerate() {
//                                         if i == 0 {
//                                             print!(" {}", universe.display_solvable(dep));
//                                             has_deps = true;
//                                         } else {
//                                             print!(", {}", universe.display_solvable(dep));
//                                         }
//                                     }
//                                     if has_deps {
//                                         println!("");
//                                     }
//                                 }
//                             }
//                         } else {
//                             pretty_print_packages(
//                                 &mut out,
//                                 universe
//                                     .sorted_solution(&mut solution)
//                                     .into_iter()
//                                     .map(|s| -> Package { universe.package(s).unwrap().into() }),
//                                 false,
//                             )?;
//                             println!("solved in {:?}", start.elapsed());
//                         }
//                     };
//                     Ok(ExitCode::SUCCESS)
//                 }
//                 Err(conflict) => {
//                     println!("{}", universe.display_conflict(conflict));
//                     Ok(ExitCode::FAILURE)
//                 }
//             }
//         }
//     }
// }
//

impl App {
    async fn transport(&self) -> Result<Box<dyn TransportProvider>> {
        if let Some(cache) = &self.cache_dir {
            Ok(Box::new(
                HttpCachingTransportProvider::<sha2::Sha256>::new(self.insecure, cache.clone())
                    .await
                    .map_err(|e| anyhow!("failed to create transport provider: {e}"))?,
            ))
        } else {
            Ok(Box::new(
                HttpTransportProvider::<sha2::Sha256>::new(self.insecure).await,
            ))
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
            } else if let Some(home) = std::env::var_os("HOME") {
                Some(PathBuf::from(home).join(".cache"))
            } else {
                None
            }
            .map(|base| base.join("debrepo"))
        });
    } else {
        app.cache_dir = None;
    }
    match app.cmd.init(&app) {
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::FAILURE;
        }
        Ok(_) => {}
    }
    match async_std::task::block_on(app.cmd.exec(&app)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            println!("{}", err);
            ExitCode::FAILURE
        }
    }
}
