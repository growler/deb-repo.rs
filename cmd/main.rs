use {
    anyhow::{anyhow, Result},
    clap::{Parser, Subcommand},
    debrepo::{DebRepo, Dependency, HttpDebRepo, Packages, Universe},
    std::{path::PathBuf, process::ExitCode},
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
            let repo = HttpDebRepo::new(&origin).await?;
            let release = repo.fetch_release(&distr).await?;
            let file = release
                .packages_file_for(&comp, arch(&a), Some(".xz"))
                .ok_or_else(|| anyhow!("Packages file for {} {} not found", &a, &comp))?;
            match out {
                None => {
                    repo.copy_verify_unpack(
                        &format!("dists/{}/{}", &distr, file.path()),
                        file.digest().clone(),
                        file.size(),
                        async_std::io::stdout(),
                    )
                    .await
                }
                Some(out) => {
                    let out = async_std::fs::File::create(out).await?;
                    repo.copy_verify_unpack(
                        &format!("dists/{}/{}", &distr, file.path()),
                        file.digest().clone(),
                        file.size(),
                        out,
                    )
                    .await
                }
            }?;
            println!("fetched in {:?}", start.elapsed());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Search { input, name } => {
            let packages = Packages::read(&mut async_std::fs::File::open(&input).await?).await?;
            let re = regex::RegexBuilder::new(&name).case_insensitive(true).build()?;
            for p in packages.packages() {
                let desc = p.field("Description").unwrap_or("");
                if re.is_match(p.name())
                    || re.is_match(desc)
                {
                    println!("{} {}", p.full_name(), desc);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Solve { arch, input, reqs } => {
            let start = std::time::Instant::now();
            let requirements: Result<Vec<_>> = reqs
                .iter()
                .map(|s| Dependency::try_from(s.as_ref()).map_err(|err| err.into()))
                .collect();
            let packages = Packages::read(&mut async_std::fs::File::open(&input).await?).await?;
            let universe = Universe::new(&arch, [packages])?;
            let mut solver = resolvo::Solver::new(universe);
            let problem = solver.provider().problem(requirements?, std::iter::empty());
            match solver.solve(problem) {
                Ok(solution) => {
                    let mut solution: Vec<_> = solution
                        .into_iter()
                        .map(|s| solver.provider().package(s))
                        .collect();
                    solution.sort_by(|&this, &that| match this.name().cmp(&that.name()) {
                        std::cmp::Ordering::Equal => this.version().cmp(&that.version()),
                        ord => ord,
                    });
                    for item in solution {
                        println!("{}", item.full_name());
                    }
                    println!("solved in {:?}", start.elapsed());
                    Ok(ExitCode::SUCCESS)
                }
                Err(unsolvable) => match unsolvable {
                    resolvo::UnsolvableOrCancelled::Unsolvable(conflict) => {
                        println!("{}", conflict.display_user_friendly(&solver));
                        Ok(ExitCode::FAILURE)
                    }
                    resolvo::UnsolvableOrCancelled::Cancelled(_) => unreachable!(),
                },
            }
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
