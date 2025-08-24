use {
    crate::common::*,
    anyhow::{anyhow, Result},
    async_std::{
        fs,
        io::WriteExt,
        path::{Path, PathBuf},
    },
    clap::{Parser, Subcommand, Args},
    debrepo::{
        exec::{dpkg, unshare_root, unshare_user_ns},
        DebRepo, Dependency, DeploymentFileSystem, HttpCachingRepoBuilder, HttpDebRepo, Manifest,
        Universe, Version,
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    std::{iter, process::ExitCode, str::FromStr},
    tracing::level_filters::LevelFilter,
    tracing_subscriber::{filter::EnvFilter, fmt, prelude::*},
};
mod common;

fn default_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86" => "i386",
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "powerpc64" => "ppc64el",
        "riscv64" => "riscv64",
        "mips32" | "mips32r6" => "mipsel",
        "mips64" | "mips64r6" => "mips64el",
        "arm" => {
            if cfg!(target_feature = "vfp2") {
                "armhf"
            } else {
                "armel"
            }
        }
        a => a,
    }
}

#[derive(Parser)]
struct App {
    /// Turns off all output except errors
    #[arg(short, long)]
    quiet: bool,

    /// Turns on debugging output (repeat -d for more)
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Manifest file
    #[arg(short, long, default_value = "manifest.yaml")]
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
    #[arg(short, long, value_name = "ARCH", default_value = default_arch())]
    arch: String,

    /// HTTP download cache directory
    #[arg(
        long = "cache-dir",
        value_name = "DIR",
        // Default to "$XDG_CACHE_HOME/debrepo" or "$HOME/.cache/debrepo" if XDG_CACHE_HOME is not set
        default_value_os_t = {
            let base = if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
                PathBuf::from(xdg)
            } else if let Some(home) = std::env::var_os("HOME") {
                PathBuf::from(home).join(".cache")
            } else {
                PathBuf::from(".cache")
            };
            base.join("debrepo")
        }
    )]
    pub cache_dir: PathBuf,

    /// Do not verify Release files (not recommended)
    #[arg(long = "no-verify")]
    pub no_verify: bool,

    /// Keyring for verification (use multiple times to add more)
    #[arg(short = 'k', long = "keyring", value_name = "FILE")]
    pub keyring: Vec<PathBuf>,

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
    /// Add dependency to manifest file
    #[command(name = "add")]
    Add,
    /// Remove dependency from manifest file
    #[command(name = "remove")]
    Remove,
    /// Validate manifest file
    #[command(name = "validate")]
    Validate,
    // #[command(name = "solve")]
    // Solve {
    //     /// Architecture
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
    //     /// Fetch packages
    //     #[arg(short = 'g', long = "print-graph", value_name = "dot|text")]
    //     print_graph: Option<String>,
    //     /// Number of concurrent downloads
    //     #[arg(short = 'l', long = "limit", value_name = "NUM", default_value = "5")]
    //     limit: usize,
    //     /// Fetch packages
    //     #[arg(short = 'f', long = "fetch-packages", action)]
    //     fetch: bool,
    //     /// Extract packages into target directory
    //     #[arg(short = 'e', long = "extract-packages", action)]
    //     extract: bool,
    //     /// Target directory
    //     #[arg(short = 't', long = "target", value_name = "DIR", default_value = ".")]
    //     target: PathBuf,
    //     /// Requirements
    //     #[arg(value_name = "REQUIREMENT")]
    //     reqs: Vec<String>,
    // },
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

#[derive(Args, Default)]
#[group(required = true, multiple = true)]
struct Source {
    /// Repository URL
    #[arg(value_name = "URL", default_value = "https://ftp.debian.org/debian/")]
    url: String,

    /// Distribution name (e.g., bookworm, bookworm-security, sid)
    #[arg(long, default_value = "sid")]
    pub distr: String,

    /// Components (comma-separated), default: all available
    #[arg(long = "comp", value_delimiter = ',')]
    pub comp: Vec<String>,

    /// Only include these architectures (comma-separated)
    #[arg(long = "arch-only", conflicts_with = "arch_exclude", value_delimiter = ',')]
    pub arch_only: Vec<String>,

    /// Exclude this architecture
    #[arg(long = "arch-exclude", conflicts_with = "arch_only")]
    pub arch_exclude: Option<String>,
}

#[derive(Parser, Default)]
pub struct Init {
    /// Overwrite existing manifest if present
    #[arg(long)]
    pub force: bool,

    /// Source definitions (use multiple times to add more)
    #[command(flatten)]
    source: Source,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Init {
    async fn exec(&self, conf: &Config) -> Result<()> {
        Ok(())
    }
}

async fn update_manifest<F>(manifest_path: &Path, modifier: F) -> Result<()>
where
    F: FnOnce(&mut Manifest) -> Result<()>,
{
    let mut manifest = Manifest::read(async_std::fs::File::open(manifest_path).await?).await?;
    modifier(&mut manifest)?;

    let mut temp_path = manifest_path.to_path_buf();
    temp_path.set_extension("tmp");
    let mut temp_file = async_std::fs::File::create(&temp_path).await?;
    manifest
        .write(&mut temp_file)
        .await
        .map_err(|err| anyhow!("failed to write manifest to temporary file: {}", err))?;
    drop(temp_file);
    async_std::fs::rename(&temp_path, manifest_path).await?;
    Ok(())
}

#[derive(Parser)]
struct Remove {
    #[arg(value_name = "DEPENDENCY")]
    name: Vec<String>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Remove {
    async fn exec(&self, conf: &Config) -> Result<()> {
        update_manifest(&conf.manifest, |manifest| {
            for item in self.name.iter() {
                let dep = Dependency::from_str(item.as_ref())?;
                manifest.drop_requirement(dep);
            }
            Ok(())
        })
        .await
    }
}

#[derive(Parser)]
struct Add {
    #[arg(value_name = "DEPENDENCY")]
    name: Vec<String>,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Add {
    async fn exec(&self, conf: &Config) -> Result<()> {
        update_manifest(&conf.manifest, |manifest| {
            for item in self.name.iter() {
                let dep = Dependency::from_str(item.as_ref())?;
                manifest.add_requirement(dep);
            }
            Ok(())
        })
        .await
    }
}

#[derive(Parser)]
struct Update {}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Update {
    async fn exec(&self, conf: &Config) -> Result<()> {
        let manifest = Manifest::read(async_std::fs::File::open(&conf.manifest).await?).await?;
        let repo_builder = HttpCachingRepoBuilder::new(".cache".into()).await?;
        let mut universe = manifest
            .fetch_universe(&conf.arch, &repo_builder, conf.limit)
            .await?;
        let (requirements, constraints) = manifest.into_requirements();
        match universe.solve(requirements, constraints) {
            Ok(mut solution) => {
                solution.sort_by_key(|&pkg| universe.package(pkg).unwrap().name());
                let mut out = std::io::stdout().lock();
                pretty_print_packages(
                    &mut out,
                    solution
                        .into_iter()
                        .map(|s| -> Package { universe.package(s).unwrap().into() }),
                    false,
                )?;
                Ok(())
            }
            Err(conflict) => Err(anyhow!(
                "failed to solve dependencies: {}",
                universe.display_conflict(conflict)
            )),
        }
    }
}

#[derive(Parser)]
struct Extract {
    /// Target path
    #[arg(short, long, value_name = "PATH", default_value = "out")]
    path: PathBuf,
}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Extract {
    async fn exec(&self, conf: &Config) -> Result<()> {
        let manifest = Manifest::read(async_std::fs::File::open(&conf.manifest).await?).await?;
        let repo_builder = HttpCachingRepoBuilder::new(".cache".into()).await?;
        let mut universe = manifest
            .fetch_universe(&conf.arch, &repo_builder, conf.limit)
            .await?;
        let (requirements, constraints) = manifest.into_requirements();
        let solution = universe
            .solve(requirements, constraints)
            .map_err(|conflict| {
                anyhow!(
                    "failed to solve dependencies: {}",
                    universe.display_conflict(conflict)
                )
            })?;
        let essentials = solution
            .iter()
            .filter_map(|id| {
                universe.package(*id).and_then(|pkg| {
                    if pkg.essential() {
                        Some(pkg.name())
                    } else {
                        None
                    }
                })
            })
            .collect::<Vec<_>>();
        fs::create_dir_all(&self.path).await?;
        let fs = debrepo::LocalFileSystem::new(&self.path, nix::unistd::Uid::effective().is_root())
            .await?;
        let mut control_file = stream::iter(solution.iter().cloned())
            .map(|id| {
                let (deb, package) = (
                    universe.deb_reader(id),
                    universe.package(id).unwrap().full_name(),
                );
                let fs = fs.clone();
                async move {
                    match deb.await {
                        Ok(deb) => {
                            tracing::info!("unpacking {}...", package);
                            let mut stanza = async_std::task::block_on(deb.extract_to(&fs))?;
                            stanza.set("Status", "install ok unpacked");
                            stanza.sort_fields_deb_order();
                            Ok::<_, anyhow::Error>(stanza)
                        }
                        Err(err) => {
                            tracing::error!("failed to unpack {}: {}", package, err);
                            Err(err.into())
                        }
                    }
                }
            })
            .buffer_unordered(conf.limit)
            .try_collect::<Vec<_>>()
            .await?;
        control_file.sort_by(|a, b| a.field("Package").unwrap().cmp(b.field("Package").unwrap()));
        fs.create_dir_all("var/lib/dpkg", 0, 0, 0o755u32).await?;
        {
            let size = control_file.iter().map(|i| i.len() + 1).sum();
            let mut status = Vec::<u8>::with_capacity(size);
            for i in control_file.into_iter() {
                status.write_all(format!("{}", &i).as_bytes()).await?;
                status.write_all(&[b'\n']).await?;
            }
            fs.create_file(
                status.as_slice(),
                Some("var/lib/dpkg/status"),
                0,
                0,
                0o644,
                None,
                Some(size),
            )
            .await?;
        };
        let env = ["DEBIAN_FRONTEND=noninteractive"];
        dpkg(
            &self.path,
            ["--force-depends", "--configure"]
                .iter()
                .chain(essentials.iter()),
            Some(&env),
        )?;
        dpkg(&self.path, ["--configure", "-a"], Some(&env))?;
        Ok(())
    }
}

#[derive(Parser)]
struct Validate {}

#[async_trait::async_trait(?Send)]
impl AsyncCommand for Validate {
    async fn exec(&self, conf: &Config) -> Result<()> {
        let manifest = Manifest::read(async_std::fs::File::open(&conf.manifest).await?).await?;
        use async_std::io;
        manifest
            .write(&mut io::stdout())
            .await
            .map_err(|err| anyhow!("failed to write manifest: {}", err))?;
        Ok(())
    }
}

#[derive(Parser)]
struct Fetch {
    /// Architecture
    #[arg(short, long, value_name = "ARCH", default_value = default_arch())]
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
    async fn exec(&self, _conf: &Config) -> Result<()> {
        let start = std::time::Instant::now();
        let repo: DebRepo = HttpDebRepo::new(&self.origin).await?.into();
        let release = if self.verify {
            repo.fetch_verify_release(&self.distr, iter::empty()).await
        } else {
            repo.fetch_release(&self.distr).await
        }?;
        let (path, size, hash) = release
            .packages_file(&self.comp, &self.arch)
            .ok_or_else(|| anyhow!("Packages file for {} {} not found", &self.arch, &self.comp))?;
        match self.out {
            None => {
                repo.copy_verify_unpack(async_std::io::stdout(), &path, size, hash)
                    .await
            }
            Some(ref out) => {
                let out = async_std::fs::File::create(out).await?;
                repo.copy_verify_unpack(out, &path, size, hash).await
            }
        }?;
        println!("fetched in {:?}", start.elapsed());
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
            ver: pkg.version(),
            desc: pkg.field("Description").unwrap_or(""),
            prio: pkg.install_priority(),
        }
    }
}

fn pretty_print_packages<'a, W: std::io::Write>(
    f: &mut W,
    iter: impl IntoIterator<Item = Package<'a>>,
    sort: bool,
) -> std::result::Result<usize, std::io::Error> {
    let mut w0 = 0usize;
    let mut w1 = 0usize;
    let mut w2 = 0usize;
    let mut w3 = 0usize;
    let mut w4 = 0usize;
    let mut packages = iter
        .into_iter()
        .map(|pkg| {
            w0 = std::cmp::max(w0, pkg.arch.len());
            w1 = std::cmp::max(w1, pkg.prio.as_ref().len());
            w2 = std::cmp::max(w2, pkg.name.len());
            w3 = std::cmp::max(w3, pkg.ver.as_ref().len());
            w4 = std::cmp::max(w4, pkg.desc.len());
            pkg
        })
        .collect::<Vec<_>>();
    if sort {
        packages.sort_by(|this, that| match this.name.cmp(that.name) {
            std::cmp::Ordering::Equal => this.ver.cmp(&that.ver),
            other => other,
        });
    }
    for p in packages.iter() {
        writeln!(
            f,
            "{:>w0$} {:<w1$} {:<w2$} {:>w3$} {:<w4$}",
            p.arch,
            p.prio.as_ref(),
            p.name,
            p.ver,
            p.desc
        )?;
    }
    Ok(packages.len())
}

async fn copy_repo_package<'a>(
    universe: &'a Universe,
    id: debrepo::PackageId,
    target: &Path,
) -> Result<(debrepo::PackageId, impl std::fmt::Display + 'a, u64)> {
    let pkg = universe
        .package(id)
        .ok_or_else(|| anyhow!("package id {:?} not found", id))?;
    let path: PathBuf = pkg.ensure_field("Filename")?.into();
    let mut out = PathBuf::from(target);
    out.push(path.file_name().unwrap());
    let out = fs::File::create(out).await?;
    let size = universe.copy_deb_file(out, id).await?;
    Ok((id, pkg, size))
}

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

fn init(_opts: &App) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        unshare_user_ns()?;
    }
    unshare_root()?;
    Ok(())
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
    let app = App::parse();
    init_logging(app.quiet, app.debug);
    match init(&app) {
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::FAILURE;
        }
        Ok(_) => {}
    }
    let conf = Config {
        manifest: app.manifest,
        arch: app.arch,
        limit: app.limit,
    };
    match async_std::task::block_on(app.cmd.exec(&conf)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            println!("{}", err);
            ExitCode::FAILURE
        }
    }
}
