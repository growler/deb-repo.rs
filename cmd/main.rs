mod exec;
use {
    crate::exec::{unshare_root, unshare_user_ns},
    anyhow::{anyhow, Result},
    async_std::{
        fs,
        io::{self, prelude::*},
        path::{Path, PathBuf},
    },
    clap::{Parser, Subcommand},
    debrepo::{
        DebRepo, Dependency, DeploymentFileSystem, HttpDebRepo, MutableControlStanza, Universe,
        Version,
    },
    futures::{
        future::join_all,
        stream::{FuturesUnordered, StreamExt},
    },
    std::process::ExitCode,
};

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

#[derive(Parser, Debug)]
struct App {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    #[command(name = "fetch")]
    Fetch {
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
        /// Target file name
        #[arg(short = 'o', long = "output", value_name = "FILE")]
        out: Option<PathBuf>,
        /// Distribution name
        #[arg(value_name = "DISTR", default_value = "sid")]
        distr: String,
        /// Component
        #[arg(value_name = "COMPONENT", default_value = "main")]
        comp: String,
    },
    #[command(name = "solve")]
    Solve {
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
        /// Distribution name
        #[arg(
            short = 'd',
            long = "distr",
            value_name = "DISTR",
            default_value = "sid"
        )]
        distr: String,
        /// Component
        #[arg(
            short = 'c',
            long = "component",
            value_name = "COMPONENT",
            default_value = "all"
        )]
        comp: String,
        /// Fetch packages
        #[arg(short = 'g', long = "print-graph", value_name = "dot|text")]
        print_graph: Option<String>,
        /// Number of concurrent downloads
        #[arg(short = 'l', long = "limit", value_name = "NUM", default_value = "5")]
        limit: usize,
        /// Fetch packages
        #[arg(short = 'f', long = "fetch-packages", action)]
        fetch: bool,
        /// Extract packages into target directory
        #[arg(short = 'e', long = "extract-packages", action)]
        extract: bool,
        /// Target directory
        #[arg(short = 't', long = "target", value_name = "DIR", default_value = ".")]
        target: PathBuf,
        /// Requirements
        #[arg(value_name = "REQUIREMENT")]
        reqs: Vec<String>,
    },
    #[command(name = "search")]
    Search {
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
        /// Distribution name
        #[arg(
            short = 'd',
            long = "distr",
            value_name = "DISTR",
            default_value = "sid"
        )]
        distr: String,
        /// Component
        #[arg(
            short = 'c',
            long = "component",
            value_name = "COMPONENT",
            default_value = "all"
        )]
        comp: String,
        /// name
        #[arg(value_name = "NAME")]
        name: String,
    },
}

struct Package<'a> {
    name: &'a str,
    arch: &'a str,
    ver: Version<&'a str>,
    desc: &'a str,
}

impl<'a> From<&'a debrepo::Package<'a>> for Package<'a> {
    fn from(pkg: &'a debrepo::Package<'a>) -> Self {
        Self {
            name: pkg.name(),
            arch: pkg.arch(),
            ver: pkg.version(),
            desc: pkg.field("Description").unwrap_or(""),
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
    let mut packages = iter
        .into_iter()
        .map(|pkg| {
            w0 = std::cmp::max(w0, pkg.arch.len());
            w1 = std::cmp::max(w1, pkg.name.len());
            w2 = std::cmp::max(w2, pkg.ver.as_ref().len());
            w3 = std::cmp::max(w3, pkg.desc.len());
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
            "{:>w0$} {:<w1$} {:>w2$} {:<w3$}",
            p.arch, p.name, p.ver, p.desc
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

async fn extract_repo_package<'a, F: DeploymentFileSystem>(
    universe: &'a Universe,
    id: debrepo::PackageId,
    target: F,
) -> Result<MutableControlStanza> {
    let reader = universe.deb_reader(id).await?;
    let desc = reader.extract_to(&target).await?;
    Ok(desc)
}

async fn cmd(cli: App) -> Result<ExitCode> {
    match cli.cmd {
        Command::Fetch {
            arch: a,
            origin,
            out,
            distr,
            comp,
        } => {
            let start = std::time::Instant::now();
            let repo: DebRepo = HttpDebRepo::new(&origin).await?.into();
            let release = repo.fetch_release(&distr).await?;
            let (path, size, hash) = release
                .packages_file(&comp, &a)
                .ok_or_else(|| anyhow!("Packages file for {} {} not found", &a, &comp))?;
            match out {
                None => {
                    repo.copy_verify_unpack(async_std::io::stdout(), &path, size, hash)
                        .await
                }
                Some(out) => {
                    let out = async_std::fs::File::create(out).await?;
                    repo.copy_verify_unpack(out, &path, size, hash).await
                }
            }?;
            println!("fetched in {:?}", start.elapsed());
            Ok(ExitCode::SUCCESS)
        }
        Command::Search {
            arch,
            origin,
            distr,
            comp,
            name,
        } => {
            let start = std::time::Instant::now();
            let repo: DebRepo = HttpDebRepo::new(&origin).await?.into();
            let release = repo
                .fetch_verify_release_with_keys(&distr, [debrepo::DEBIAN_KEYRING])
                .await?;
            let components = if &comp == "all" {
                release.components().collect::<Vec<&'_ str>>()
            } else {
                comp.split(',').map(|s| s.trim()).collect::<Vec<&'_ str>>()
            };
            let packages = join_all(
                components
                    .iter()
                    .map(|comp| release.fetch_packages(comp, &arch)),
            )
            .await
            .into_iter()
            .collect::<io::Result<Vec<_>>>()?;
            let universe = Universe::new(&arch, packages)?;
            let re = regex::RegexBuilder::new(&name)
                .case_insensitive(true)
                .build()?;
            let mut out = std::io::stdout().lock();
            match pretty_print_packages(
                &mut out,
                universe
                    .packages()
                    .map(|p| -> Package { p.into() })
                    .filter(|p| re.is_match(p.name) || re.is_match(p.desc)),
                true,
            )? {
                0 => {
                    println!("not found in {:?}", start.elapsed());
                    Ok(ExitCode::FAILURE)
                }
                n => {
                    println!("found {} in {:?}", n, start.elapsed());
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
        Command::Solve {
            arch,
            origin,
            distr,
            comp,
            print_graph,
            fetch,
            extract,
            target,
            limit,
            reqs,
        } => {
            let start = std::time::Instant::now();
            let requirements = reqs
                .iter()
                .map(|s| Dependency::try_from(s.as_ref()).map_err(|err| err.into()))
                .collect::<Result<Vec<_>>>()?;
            let repo: DebRepo = HttpDebRepo::new(&origin).await?.into();
            let release = repo.fetch_release(&distr).await?;
            let components = if &comp == "all" {
                release.components().collect::<Vec<&'_ str>>()
            } else {
                comp.split(',').map(|s| s.trim()).collect::<Vec<&'_ str>>()
            };
            let packages = join_all(
                components
                    .iter()
                    .map(|comp| release.fetch_packages(comp, &arch)),
            )
            .await
            .into_iter()
            .collect::<io::Result<Vec<_>>>()?;
            let mut universe = Universe::new(&arch, packages)?;
            match universe.solve(requirements, std::iter::empty()) {
                Ok(mut solution) => {
                    if extract {
                        let fs = debrepo::LocalFileSystem::new(
                            &target,
                            nix::unistd::Uid::effective().is_root(),
                        )
                        .await?;
                        let mut control_file: Vec<MutableControlStanza> = vec![];
                        let mut stream = FuturesUnordered::new();
                        let mut pending = solution.into_iter();
                        for _ in 0..limit {
                            if let Some(id) = pending.next() {
                                stream.push(extract_repo_package(&universe, id, &fs));
                            }
                        }
                        while let Some(result) = stream.next().await {
                            match result {
                                Ok(mut stanza) => {
                                    stanza.set("Status", "install ok unpacked");
                                    stanza.sort_fields_deb_order();
                                    control_file.push(stanza)
                                }
                                Err(err) => return Err(err),
                            }
                            if let Some(id) = pending.next() {
                                stream.push(extract_repo_package(&universe, id, &fs));
                            }
                        }
                        control_file.sort_by(|a, b| {
                            a.field("Package").unwrap().cmp(b.field("Package").unwrap())
                        });
                        {
                            let mut target = PathBuf::from(&target);
                            target.push("var/lib/dpkg");
                            fs::create_dir_all(&target).await?;
                            target.push("status");
                            let mut out = fs::File::create(target).await?;
                            for i in control_file.into_iter() {
                                out.write_all(format!("{}", &i).as_bytes()).await?;
                                out.write_all(&[b'\n']).await?;
                            }
                        };

                        println!("solved and fetched in {:?}", start.elapsed());
                    } else if fetch {
                        let mut stream = FuturesUnordered::new();
                        let mut pending = solution.into_iter();
                        for _ in 0..limit {
                            if let Some(id) = pending.next() {
                                stream.push(copy_repo_package(&universe, id, &target));
                            }
                        }
                        while let Some(result) = stream.next().await {
                            match result {
                                Ok((_, name, size)) => println!("{} {}", name, size),
                                Err(err) => println!("Failed to download: {}", err),
                            }
                            if let Some(id) = pending.next() {
                                stream.push(copy_repo_package(&universe, id, &target));
                            }
                        }
                        println!("solved and fetched in {:?}", start.elapsed());
                    } else {
                        use petgraph::dot::{Config, Dot};
                        let mut out = std::io::stdout().lock();
                        if let Some(format) = print_graph {
                            let graph = universe.dependency_graph(&mut solution);
                            if format.eq_ignore_ascii_case("dot") {
                                println!(
                                    "{:?}",
                                    Dot::with_attr_getters(
                                        &graph,
                                        &[Config::EdgeNoLabel, Config::NodeNoLabel],
                                        &|_, _| "".to_owned(),
                                        &|_, id| format!(
                                            "label = \"{}\"",
                                            universe.display_solvable(id.0)
                                        )
                                    )
                                );
                            } else {
                                let ordered = petgraph::algo::kosaraju_scc(&graph)
                                    .into_iter()
                                    .flat_map(|g| g.into_iter());
                                for id in ordered {
                                    println!("{}", universe.display_solvable(id));
                                    let mut has_deps = false;
                                    for (i, dep) in graph.neighbors(id).enumerate() {
                                        if i == 0 {
                                            print!(" {}", universe.display_solvable(dep));
                                            has_deps = true;
                                        } else {
                                            print!(", {}", universe.display_solvable(dep));
                                        }
                                    }
                                    if has_deps {
                                        println!("");
                                    }
                                }
                            }
                        } else {
                            pretty_print_packages(
                                &mut out,
                                universe
                                    .sorted_solution(&mut solution)
                                    .into_iter()
                                    .map(|s| -> Package { universe.package(s).unwrap().into() }),
                                false,
                            )?;
                            println!("solved in {:?}", start.elapsed());
                        }
                    };
                    Ok(ExitCode::SUCCESS)
                }
                Err(conflict) => {
                    println!("{}", universe.display_conflict(conflict));
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn init(_opts: &App) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        unshare_user_ns()?;
    }
    unshare_root()?;
    Ok(())
}

fn main() -> ExitCode {
    let cli = App::parse();
    match init(&cli) {
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::FAILURE;
        }
        Ok(_) => {}
    }
    match async_std::task::block_on(cmd(cli)) {
        Ok(code) => code,
        Err(err) => {
            println!("{}", err);
            ExitCode::FAILURE
        }
    }
}
