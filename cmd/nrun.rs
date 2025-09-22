use {
    anyhow::{anyhow, Result},
    clap::Parser,
    nix::{
        mount::{mount, umount2, MntFlags, MsFlags},
        sched::{clone, unshare, CloneFlags},
        sys::{
            stat::Mode,
            wait::{waitpid, WaitStatus},
        },
        unistd::{chdir, execve, fork, mkdir, pipe, pivot_root, read, ForkResult, Pid},
    },
    std::{
        convert::Infallible,
        ffi::CString,
        os::fd::{AsFd, AsRawFd},
        path::PathBuf,
        process::ExitCode,
    },
};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short = 'U', long = "map-user", action)]
    map_user: bool,
    #[arg(value_name = "DIR")]
    dir: PathBuf,
    #[arg(value_name = "CMD")]
    cmd: String,
    #[arg(value_name = "ARGS")]
    args: Vec<String>,
}

trait ErrnoContext<T> {
    fn context(
        self,
        context: &'static str,
    ) -> std::result::Result<T, (&'static str, nix::errno::Errno)>;
}
impl<T> ErrnoContext<T> for nix::Result<T> {
    fn context(
        self,
        context: &'static str,
    ) -> std::result::Result<T, (&'static str, nix::errno::Errno)> {
        match self {
            Ok(t) => Ok(t),
            Err(err) => Err((context, err)),
        }
    }
}

#[derive(Debug)]
struct Args {
    dir: CString,
    dir_proc: CString,
    cmd: CString,
    args: Vec<CString>,
    env: Vec<CString>,
}

fn exec_cmd(args: &Args) -> std::result::Result<Infallible, (&'static str, nix::errno::Errno)> {
    let dir = args.dir.as_c_str();
    mount(
        Some("none"),
        "/",
        None::<&str>,
        MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("making / private")?;
    mount(
        Some(dir),
        dir,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("bind-mounting root")?;
    mount(
        Some("proc"),
        args.dir_proc.as_c_str(),
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_RELATIME,
        None::<&str>,
    )
    .context("mounting new proc")?;
    chdir(dir).context("changing working directory")?;
    pivot_root(".", ".").context("pivoting root")?;
    umount2(".", MntFlags::MNT_DETACH).context("unmounting old root")?;
    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_RELATIME,
        Some("size=1024M"),
    )
    .context("mounting /dev")?;
    mkdir("/dev/pts", Mode::from_bits(0o755u32).unwrap()).context("mkdir /dev/pts")?;
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_RELATIME,
        Some("gid=5,mode=620,ptmxmode=000"),
    )
    .context("mounting /dev/pts")?;
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME,
        Some(""),
    )
    .context("mounting /run")?;
    execve(&args.cmd, &args.args, &args.env).context("executing command")
}

async fn run(cmd: Cli) -> Result<ExitCode> {
    let args = Args {
        dir: CString::new(cmd.dir.as_os_str().as_encoded_bytes())?,
        dir_proc: CString::new(cmd.dir.join("proc").as_os_str().as_encoded_bytes())?,
        cmd: CString::new(cmd.cmd.as_bytes())?,
        args: std::iter::once(&cmd.cmd)
            .chain(cmd.args.iter())
            .map(|s| CString::new(s.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()?,
        env: ["PATH=/sbin:/bin:/usr/sbin:/usr/bin"]
            .iter()
            .map(|s| CString::new(s.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()?,
    };
    println!("{:?}", &args);

    let mut stack = vec![0u8; 16384];
    let pid = unsafe {
        clone(
            Box::new(&|| -> isize {
                match exec_cmd(&args) {
                    Ok(_) => unreachable!(),
                    Err((msg, err)) => {
                        eprintln!("error while {}: {}", msg, err.desc());
                        -1
                    }
                }
            }),
            &mut stack,
            CloneFlags::CLONE_PTRACE
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWNET
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWNS,
            Some(nix::sys::signal::Signal::SIGCHLD as i32),
        )
    }?;
    loop {
        if let WaitStatus::Exited(_, code) = waitpid(pid, None)? {
            if code == 0 {
                break;
            } else {
                return Err(nix::errno::Errno::from_raw(code).into());
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

struct SubIdEntry {
    name: String,
    start: u64,
    count: u64,
}

impl SubIdEntry {
    fn read_entries<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Vec<SubIdEntry>> {
        use std::io::BufRead;
        std::io::BufReader::new(std::fs::File::open(path.as_ref())?)
            .lines()
            .filter_map(|line| {
                line.map(|line| {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        let mut parts = line.split(':');
                        if let Some(name) = parts.next() {
                            let name = name.to_owned();
                            if let Some(start) = parts.next() {
                                if let Ok(start) = start.parse::<u64>() {
                                    if let Some(count) = parts.next() {
                                        if let Ok(count) = count.parse::<u64>() {
                                            return Some(Ok(SubIdEntry { name, start, count }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    None
                })
                .unwrap_or_else(|err| Some(Err(err)))
            })
            .collect::<std::io::Result<Vec<_>>>()
    }
}

fn set_user_ns() -> Result<bool> {
    let _subuids = SubIdEntry::read_entries("/etc/subuid")?;
    let _subgids = SubIdEntry::read_entries("/etc/subgid")?;
    //let _uid = unsafe { libc::geteuid() };
    //let _gid = unsafe { libc::getegid() };
    let (read_fd, write_fd) = pipe()?;
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            drop(read_fd);
            unshare(CloneFlags::CLONE_NEWUSER)?;
            drop(write_fd);
            match waitpid(child, None)? {
                WaitStatus::Exited(_, code) if code == 0 => Ok(true),
                status => Err(anyhow!("failed to set user namespace: {:?}", &status)),
            }
        }
        ForkResult::Child => {
            drop(write_fd);
            let mut buf = [0u8; 1];
            _ = read(read_fd.as_fd().as_raw_fd(), &mut buf);
            drop(read_fd);
            std::process::Command::new("newuidmap")
                .arg(format!("{}", Pid::parent()))
                .args(["1", "100000", "65535", "0", "1000", "1"])
                .status()?;
            std::process::Command::new("newgidmap")
                .arg(format!("{}", Pid::parent()))
                .args(["1", "100000", "65535", "0", "100", "1"])
                .status()?;
            Ok(false)
        }
    }
}

fn main() -> ExitCode {
    //tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    if cli.map_user {
        match set_user_ns() {
            Err(err) => {
                eprintln!("{}", err);
                return ExitCode::FAILURE;
            }
            Ok(is_parent) if is_parent => {}
            Ok(_) => return ExitCode::SUCCESS,
        }
    }

    match smol::block_on(run(cli)) {
        Ok(code) => code,
        Err(_) => ExitCode::FAILURE,
    }
}
