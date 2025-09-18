use {
    nix::{
        mount::{mount, umount2, MntFlags, MsFlags},
        sched::{clone, unshare, CloneFlags},
        sys::{
            stat::Mode,
            wait::{waitpid, WaitStatus},
        },
        unistd::{chdir, execve, fork, mkdir, pipe, pivot_root, read, ForkResult, Gid, Pid, Uid},
    },
    std::path::Path,
    std::{
        convert::Infallible,
        ffi::{CStr, CString, NulError},
        fmt, io,
        os::{fd::AsFd, unix::process::CommandExt},
        process::ExitCode,
    },
};

pub type Result<T> = std::result::Result<T, ExecError>;

pub struct ExecError {
    errno: nix::errno::Errno,
    context: &'static str,
}
impl std::error::Error for ExecError {}
impl fmt::Debug for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("error")?;
        if !self.context.is_empty() {
            f.write_str(" ")?;
            f.write_str(self.context)?;
        }
        f.write_str(": ")?;
        f.write_str(self.errno.desc())
    }
}
trait ErrnoContext<T> {
    fn context(self, context: &'static str) -> Result<T>;
}
impl<T> ErrnoContext<T> for nix::Result<T> {
    fn context(self, context: &'static str) -> Result<T> {
        match self {
            Ok(ok) => Ok(ok),
            Err(errno) => Err(ExecError { errno, context }),
        }
    }
}

impl From<nix::errno::Errno> for ExecError {
    fn from(errno: nix::errno::Errno) -> ExecError {
        Self { errno, context: "" }
    }
}

impl From<NulError> for ExecError {
    fn from(_err: NulError) -> ExecError {
        Self {
            errno: nix::errno::Errno::EINVAL,
            context: "invalid string supplied as argument",
        }
    }
}

pub fn unshare_root() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS).context("unsharing namespace")?;
    mount(
        Some("none"),
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("re-mounting root as private")
}

struct SubIdEntry {
    name: String,
    start: u64,
    count: u64,
}

impl SubIdEntry {
    fn read_entries<P: AsRef<std::path::Path>>(
        path: P,
    ) -> io::Result<impl Iterator<Item = io::Result<SubIdEntry>>> {
        use std::io::BufRead;
        Ok(std::io::BufReader::new(std::fs::File::open(path.as_ref())?)
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
            }))
    }
}

pub fn unshare_user_ns() -> io::Result<()> {
    let uid = Uid::effective();
    let gid = Gid::effective();
    let user = nix::unistd::User::from_uid(uid)?.ok_or_else(|| {
        io::Error::other(
            format!("user record not found for uid {}", uid),
        )
    })?;
    let subuid = SubIdEntry::read_entries("/etc/subuid")?
        .find(|item| match item {
            Ok(item) => item.name == user.name,
            _ => true,
        })
        .unwrap_or_else(|| {
            Err(io::Error::other(
                format!("/etc/subuid entry not found for user {}", &user.name),
            ))
        })?;
    let subgid = SubIdEntry::read_entries("/etc/subgid")?
        .find(|item| match item {
            Ok(item) => item.name == user.name,
            _ => true,
        })
        .unwrap_or_else(|| {
            Err(io::Error::other(
                format!("/etc/subgid entry not found for user {}", &user.name),
            ))
        })?;
    let mut newuid = std::process::Command::new("newuidmap");
    newuid.arg(Pid::this().to_string()).args([
        "0",
        &uid.to_string(),
        "1",
        "1",
        &subuid.start.to_string(),
        &subuid.count.to_string(),
    ]);
    let mut newgid = std::process::Command::new("newgidmap");
    newgid.arg(Pid::this().to_string()).args([
        "0",
        &gid.to_string(),
        "1",
        "1",
        &subgid.start.to_string(),
        &subgid.count.to_string(),
    ]);
    let (read_fd, write_fd) = pipe()?;
    match unsafe { fork()? } {
        ForkResult::Child => {
            drop(write_fd);
            let mut buf = [0u8; 1];
            _ = read(read_fd.as_fd(), &mut buf);
            drop(read_fd);
            match newuid.status() {
                Ok(code) if code.success() => {}
                _ => std::process::exit(1),
            };
            _ = newgid.exec();
            std::process::exit(1); // unreachable
        }
        ForkResult::Parent { child } => {
            drop(read_fd);
            unshare(CloneFlags::CLONE_NEWUSER)?;
            drop(write_fd);
            match waitpid(child, None)? {
                WaitStatus::Exited(_, 0) => Ok(()),
                WaitStatus::Exited(_, code) => Err(io::Error::other(
                    format!("failed to set uid/gid map (code {})", code),
                )),
                status => Err(io::Error::other(
                    format!("failed to set uid/gid map ({:?})", status),
                )),
            }
        }
    }
}

fn exec_cmd<As: AsRef<CStr>, Es: AsRef<CStr>>(
    root: &CStr,
    proc: &CStr,
    cwd: Option<&CStr>,
    cmd: &CStr,
    args: &[As],
    env: &[Es],
) -> Result<Infallible> {
    mount(
        Some("none"),
        "/",
        None::<&str>,
        MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("making / private")?;
    mount(
        Some(root),
        root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("bind-mounting root")?;
    mount(
        Some("proc"),
        proc,
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_RELATIME,
        None::<&str>,
    )
    .context("mounting new proc")?;
    chdir(root).context("changing working directory")?;
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
    mkdir("/run/lock", Mode::from_bits(0o1777u32).unwrap()).context("mkdir /tmp")?;
    if let Some(cwd) = cwd {
        chdir(cwd).context("changing working directory")?;
    }
    execve(cmd, args, env).context("executing command")
}

/// Execute a command inside a freshly created set of Linux namespaces with a pivoted root.
///
/// This function spawns a child process using `clone(2)` and sets up isolation via
/// the following namespace flags:
/// - `CLONE_NEWUTS`
/// - `CLONE_NEWPID`
/// - `CLONE_NEWNET`
/// - `CLONE_NEWIPC`
/// - `CLONE_NEWNS`
/// - `CLONE_PTRACE`
///
/// In the child process it:
/// - Switches the root to `root` (pivot/chroot semantics handled internally by the callee).
/// - Optionally changes the working directory to `dir` (relative to the new root).
/// - Executes `cmd` with the provided `args` and `env`.
///
/// Conventions and behavior:
/// - `cmd` and `dir` are interpreted relative to the new root.
/// - `argv[0]` is set automatically from `cmd`; do not include it in `args`.
/// - If `env` is `None` or empty, a default `PATH` is provided:
///   `PATH=/sbin:/bin:/usr/sbin:/usr/bin`.
/// - If `env` is provided but does not include a `PATH=...` entry, the default PATH is appended.
/// - All provided strings (paths, args, env entries) must not contain interior NUL bytes.
///
/// Blocking and result:
/// - This function blocks until the child process exits.
/// - Returns `Ok(ExitCode::SUCCESS)` if the child exits with status code `0`.
/// - If the child exits with a non-zero status, returns an error that maps the exit code to
///   a `nix::errno::Errno`.
///
/// Errors:
/// - Creation of C-compatible strings fails (e.g., interior NUL bytes).
/// - Any underlying syscall can fail (e.g., `clone`, `waitpid`, namespace operations, `execve`).
/// - Insufficient privileges for namespace operations (commonly requires `CAP_SYS_ADMIN`) or
///   pivoting the root will result in errors (e.g., `EPERM`).
///
/// Notes:
/// - Inside the new PID namespace, the executed command will observe itself as PID 1.
/// - Ensure that `root` contains any required filesystem structure for the command to run
///   (e.g., the executable at `cmd`, needed libraries, and any directories you plan to `chdir` into).
///
/// Parameters:
/// - `root`: Filesystem path that becomes the new root of the child process.
/// - `cmd`: Executable path relative to `root` that will be invoked.
/// - `args`: Additional arguments (excluding `argv[0]`).
/// - `dir`: Optional working directory (relative to the new root) to `chdir` into before exec.
/// - `env`: Optional environment entries of the form `KEY=VALUE`. If `PATH` is missing, a default is added.
pub fn exec<Rp, Dp, Cp, A, E>(
    root: Rp,
    cmd: Cp,
    args: A,
    dir: Option<Dp>,
    env: Option<E>,
) -> Result<ExitCode>
where
    Rp: AsRef<Path>,
    Dp: AsRef<Path>,
    Cp: AsRef<Path>,
    A: IntoIterator,
    A::Item: AsRef<str>,
    E: IntoIterator,
    E::Item: AsRef<str>,
{
    let proc = CString::new(root.as_ref().join("proc").as_os_str().as_encoded_bytes())?;
    let root = CString::new(root.as_ref().as_os_str().as_encoded_bytes())?;
    let dir = dir
        .as_ref()
        .map(|d| CString::new(d.as_ref().as_os_str().as_encoded_bytes()))
        .transpose()?;
    let cmd = CString::new(cmd.as_ref().as_os_str().as_encoded_bytes())?;
    let args = std::iter::once(Ok::<_, ExecError>(cmd.clone()))
        .chain(
            args.into_iter()
                .map(|s| CString::new(s.as_ref().as_bytes()).map_err(Into::into)),
        )
        .collect::<std::result::Result<Vec<_>, _>>()?;

    const PATH_ENV: &str = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";

    let env: Vec<CString> = match env {
        Some(e) => {
            let mut v = e
                .into_iter()
                .map(|s| CString::new(s.as_ref().as_bytes()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let has_path = v.iter().any(|s| s.as_bytes().starts_with(b"PATH="));
            if !has_path {
                v.push(CString::new(PATH_ENV)?);
            }
            v
        }
        _ => vec![CString::new(PATH_ENV)?],
    };

    let mut stack = vec![0u8; 32768];
    let pid = unsafe {
        clone(
            Box::new(&|| -> isize {
                match exec_cmd(
                    &root,
                    &proc,
                    dir.as_deref(),
                    &cmd,
                    &args,
                    &env,
                ) {
                    Ok(_) => unreachable!(),
                    Err(err) => {
                        eprintln!("error while {}: {}", err.context, err.errno.desc());
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

pub fn dpkg<Rp, A, E>(root: Rp, args: A, env: Option<E>) -> Result<ExitCode>
where
    Rp: AsRef<Path>,
    A: IntoIterator,
    A::Item: AsRef<str>,
    E: IntoIterator,
    E::Item: AsRef<str>,
{
    exec(root, "/usr/bin/dpkg", args, None::<&str>, env)
}
