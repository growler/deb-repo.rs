use {
    anyhow::{anyhow, Result},
    async_std::io::WriteExt,
    clap::{Parser, Subcommand},
    debrepo::{DebRepo, Dependency, HttpDebRepo, Packages, Universe, Version},
    std::{path::PathBuf, pin::Pin, process::ExitCode},
};

fn arch<'a>(a: &'a str) -> &'a str {
    match a {
        "x86" => "i386",
        "x86_64" => "amd64",
        "arm" => "armel",
        "aarch64" => "arm64",
        "mips64" => "mips64el",
        "powerpc64" => "ppc64el",
        "riscv64" => "riscv64",
        a => a,
    }
}

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    #[command(name = "fetch")]
    Fetch {
        /// Architecture
        #[arg(short, long, value_name = "ARCH", default_value = arch(std::env::consts::ARCH))]
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
        #[arg(short, long, value_name = "ARCH", default_value = arch(std::env::consts::ARCH))]
        arch: String,
        /// Packages file
        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "Packages"
        )]
        input: PathBuf,
        /// Requirements
        #[arg(value_name = "REQUIREMENT")]
        reqs: Vec<String>,
    },
    #[command(name = "search")]
    Search {
        /// Packages file
        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "Packages"
        )]
        input: PathBuf,
        /// name
        #[arg(value_name = "NAME")]
        name: String,
    },
    #[command(name = "filter", hide = true)]
    Filter {
        /// Packages file
        #[arg(
            short = 'i',
            long = "input",
            value_name = "FILE",
            default_value = "Packages"
        )]
        input: PathBuf,
        /// Target file name
        #[arg(short = 'o', long = "output", value_name = "FILE")]
        out: Option<PathBuf>,
        /// ids
        #[arg(value_name = "ID")]
        ids: Vec<usize>,
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
    packages.sort_by(|this, that| match this.name.cmp(that.name) {
        std::cmp::Ordering::Equal => this.ver.cmp(&that.ver),
        other => other,
    });
    for p in packages.iter() {
        writeln!(
            f,
            "{:>w0$} {:<w1$} {:>w2$} {:<w3$}",
            p.arch, p.name, p.ver, p.desc
        )?;
    }
    Ok(packages.len())
}

async fn cmd(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Commands::Fetch {
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
                .packages_file(&comp, arch(&a))
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
        Commands::Search { input, name } => {
            let start = std::time::Instant::now();
            let packages = Packages::read(&mut async_std::fs::File::open(&input).await?).await?;
            let re = regex::RegexBuilder::new(&name)
                .case_insensitive(true)
                .build()?;
            let mut out = std::io::stdout().lock();
            match pretty_print_packages(
                &mut out,
                packages
                    .packages()
                    .map(|p| -> Package { p.into() })
                    .filter(|p| re.is_match(p.name) || re.is_match(p.desc)),
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
        Commands::Solve { arch, input, reqs } => {
            let start = std::time::Instant::now();
            let requirements: Result<Vec<_>> = reqs
                .iter()
                .map(|s| Dependency::try_from(s.as_ref()).map_err(|err| err.into()))
                .collect();
            let packages = Packages::read(&mut async_std::fs::File::open(&input).await?).await?;
            let mut universe = Universe::new(&arch, [packages])?;
            let problem = universe.problem(requirements?, std::iter::empty());
            match universe.solve(problem) {
                Ok(solution) => {
                    let mut out = std::io::stdout().lock();
                    pretty_print_packages(
                        &mut out,
                        solution
                            .into_iter()
                            .map(|s| -> Package { universe.package(s).into() }),
                    )?;
                    println!("solved in {:?}", start.elapsed());
                    Ok(ExitCode::SUCCESS)
                }
                Err(unsolvable) => match unsolvable {
                    resolvo::UnsolvableOrCancelled::Unsolvable(conflict) => {
                        println!("{}", universe.display_conflict(conflict));
                        Ok(ExitCode::FAILURE)
                    }
                    resolvo::UnsolvableOrCancelled::Cancelled(_) => unreachable!(),
                },
            }
        }
        Commands::Filter {
            input,
            out,
            mut ids,
        } => {
            let packages = Packages::read(&mut async_std::fs::File::open(&input).await?).await?;
            let mut out: Pin<Box<dyn async_std::io::Write + Send + Unpin>> = match out {
                None => Box::pin(async_std::io::stdout()),
                Some(out) => Box::pin(async_std::fs::File::create(out).await?),
            };
            ids.sort();
            for id in ids {
                out.write(packages.get(id).unwrap().src().as_bytes())
                    .await?;
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[async_std::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cmd(cli).await {
        Ok(code) => code,
        Err(err) => {
            println!("{}", err);
            ExitCode::FAILURE
        }
    }
}
