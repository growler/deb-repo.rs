use {
    crate::{
        builder::{BuildJob, Executor},
        HostFileSystem,
    },
    clone3::Clone3,
    rustix::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        fs::{mkdirat, openat, readlinkat, symlinkat, Mode, OFlags, Uid, CWD},
        io::{dup, fcntl_getfd, fcntl_setfd, Errno, FdFlags},
        mount::{
            fsconfig_create, fsconfig_set_string, fsmount, fsopen, mount_change, move_mount,
            open_tree, unmount, FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags,
            MoveMountFlags, OpenTreeFlags, UnmountFlags,
        },
        path::Arg,
        pipe,
        process::{
            fchdir, getegid, geteuid, getpid, pidfd_open, pivot_root, waitid, PidfdFlags, WaitId,
            WaitIdOptions,
        },
        thread::Pid,
    },
    serde::{Deserialize, Serialize},
    std::{
        borrow::Cow,
        ffi::{CStr, OsStr, OsString},
        io::{self, Write},
        iter::once,
        os::unix::ffi::OsStrExt,
        path::{Path, PathBuf},
        process::Command,
        sync::OnceLock,
    },
};

#[derive(Serialize, Deserialize)]
pub struct HostSandboxExecutor {
    root: PathBuf,
    env: Vec<(OsString, OsString)>,
}

impl HostSandboxExecutor {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            env: Vec::new(),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Executor for HostSandboxExecutor {
    type Filesystem = HostFileSystem;
    async fn execute(&mut self, job: BuildJob<Self>) -> io::Result<()> {
        Sandbox::execute_with(self, job).await
    }
    fn env<K, V>(&mut self, k: K, v: V) -> io::Result<()>
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env.push((k.as_ref().into(), v.as_ref().into()));
        Ok(())
    }
    fn envs<I, K, V>(&mut self, iter: I) -> io::Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env.extend(
            iter.into_iter()
                .map(|(k, v)| (k.as_ref().into(), v.as_ref().into())),
        );
        Ok(())
    }
    fn exec_cmd<I, A, C>(&self, cmd: C, args: I) -> io::Result<()>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
        C: AsRef<OsStr>,
    {
        Command::new(cmd)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .args(args)
            .status()?
            .success()
            .then_some(())
            .ok_or_else(|| io::Error::other("command failed"))
    }
}

impl SandboxExecutor for HostSandboxExecutor {
    fn spawn<E>(&mut self, job: BuildJob<Self>, spawner: E) -> io::Result<OwnedFd>
    where
        E: FnOnce(&Self, BuildJob<Self>) -> io::Result<OwnedFd>,
    {
        spawner(&self, job)
    }
    fn setup_rootfs(&mut self) -> io::Result<OwnedFd> {
        let dfd = openat(
            CWD,
            &self.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mfd = open_tree(
            &dfd,
            "",
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::AT_EMPTY_PATH,
        )?;
        move_mount(
            &mfd,
            "",
            &dfd,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        )?;
        Ok(openat(
            CWD,
            &self.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    }
}

pub trait SandboxExecutor
where
    Self: Executor + Serialize + for<'de> Deserialize<'de>,
{
    fn spawn<E>(&mut self, job: BuildJob<Self>, spawner: E) -> io::Result<OwnedFd>
    where
        E: FnOnce(&Self, BuildJob<Self>) -> io::Result<OwnedFd>;
    fn setup_rootfs(&mut self) -> io::Result<OwnedFd>;
}

pub struct Sandbox<'a, E: SandboxExecutor> {
    runner: &'a mut E,
}

impl<'a, E: SandboxExecutor> Sandbox<'a, E> {
    pub fn new(runner: &'a mut E) -> Self {
        Self { runner }
    }
    pub async fn execute_with(runner: &'a mut E, job: BuildJob<E>) -> io::Result<()> {
        Self::new(runner).execute(job.with_executor::<Self>()).await
    }
}

#[derive(Serialize)]
struct OutJob<'a, E, J>
where
    E: Serialize,
    J: Serialize,
{
    executor: &'a E,
    job: &'a J,
}
impl<'a, E, J> OutJob<'a, E, J>
where
    E: Serialize,
    J: Serialize,
{
    fn write_to(&self, mut w: std::fs::File) -> io::Result<()> {
        bincode::serde::encode_into_std_write(self, &mut w, bincode::config::standard()).map_err(
            |err| {
                io::Error::other(format!(
                    "failed to send parameters to helper process: {}",
                    err
                ))
            },
        )?;
        w.flush()
    }
}

#[derive(Deserialize)]
struct InJob<E, J> {
    executor: E,
    job: J,
}
impl<E, J> InJob<E, J>
where
    E: for<'de> Deserialize<'de>,
    J: for<'de> Deserialize<'de>,
{
    fn read_from(mut r: std::fs::File) -> io::Result<Self> {
        bincode::serde::decode_from_std_read(&mut r, bincode::config::standard()).map_err(|err| {
            io::Error::other(format!(
                "failed to get parameters from calling process: {}",
                err
            ))
        })
    }
}

#[async_trait::async_trait(?Send)]
impl<'a, E: SandboxExecutor> Executor for Sandbox<'a, E> {
    type Filesystem = E::Filesystem;
    async fn prepare_tree(&mut self, _fs: &Self::Filesystem) -> io::Result<()> {
        unimplemented!()
    }
    async fn process_changes(&mut self, _fs: &Self::Filesystem) -> io::Result<()> {
        unimplemented!()
    }
    fn env<K, V>(&mut self, _k: K, _v: V) -> io::Result<()>
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        unimplemented!()
    }
    fn envs<I, K, V>(&mut self, _iter: I) -> io::Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        unimplemented!()
    }
    fn exec_cmd<I, A, C>(&self, _cmd: C, _args: I) -> io::Result<()>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
        C: AsRef<OsStr>,
    {
        unimplemented!()
    }
    async fn execute(&mut self, job: BuildJob<Self>) -> io::Result<()>
    where
        Self: Sized,
    {
        let pid = self.runner.spawn(job.with_executor::<E>(), |runner, job| {
            let (rfd, wfd) = pipe::pipe()?;
            let mut flags = fcntl_getfd(&rfd)?;
            flags.remove(FdFlags::CLOEXEC);
            fcntl_setfd(&rfd, flags)?;
            let pid_fd = spawn_sandbox(once(rfd.as_raw_fd().to_string()), true)?;
            let wr: std::fs::File = wfd.into();
            OutJob {
                executor: runner,
                job: &job,
            }
            .write_to(wr)?;
            Ok(pid_fd)
        })?;
        SandboxStatus(pid).status().await.and_then(|status| {
            if status.is_success() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "sandbox exited with code {}",
                    status.code()
                )))
            }
        })
    }
}
fn run_sandbox<E: SandboxExecutor>(rd: std::fs::File) -> io::Result<()> {
    unshare_root()?;
    let mut job = InJob::<E, BuildJob<E>>::read_from(rd)?;
    let root_dfd = job.executor.setup_rootfs()?;
    fchdir(&root_dfd)?;
    mkdirat_if_not_exist(&root_dfd, "dev", Mode::from_raw_mode(0o755))?;
    mkdirat_if_not_exist(&root_dfd, "proc", Mode::from_raw_mode(0o755))?;
    mkdirat_if_not_exist(&root_dfd, "run", Mode::from_raw_mode(0o755))?;
    mount_dev(&root_dfd)?;
    mount_pts(&root_dfd)?;
    mount_proc(&root_dfd)?;
    mount_run(&root_dfd)?;
    pivot_root(".", ".")?;
    unmount(".", UnmountFlags::DETACH)?;
    job.job.run(job.executor)
}
pub fn maybe_run_sandbox<E: SandboxExecutor>() {
    let link = match readlinkat(CWD, "/proc/self/exe", vec![0u8; libc::PATH_MAX as usize]) {
        Ok(link) => link,
        Err(_) => return,
    };
    let mut name = match Path::new(OsStr::from_bytes(link.as_bytes())).file_name() {
        Some(name) => name.to_os_string(),
        None => return,
    };
    name.push("-sandbox");
    let name = init_sandbox_name(name);
    let mut args = std::env::args_os();
    let arg0 = args.next();
    if arg0.is_none() || arg0.as_ref().unwrap() != &name {
        return;
    }
    match args
        .next()
        .ok_or_else(|| io::Error::other("sandbox: expects an fd param"))
        .and_then(|s| {
            s.into_string().map_err(|err| {
                io::Error::other(format!(
                    "sandbox: invalid fd param: {}",
                    err.to_string_lossy()
                ))
            })
        })
        .and_then(|s| {
            s.parse::<i32>()
                .map_err(|err| io::Error::other(format!("helper: failed to parse fd: {}", err)))
        })
        .and_then(|fd| Ok(unsafe { OwnedFd::from_raw_fd(fd) }.into()))
        .and_then(|fd| run_sandbox::<E>(fd))
    {
        Ok(()) => std::process::exit(0),
        Err(err) => {
            {
                eprintln!("helper: {}", err);
            };
            std::process::exit(127);
        }
    }
}

fn mkdirat_if_not_exist<P: Arg, Fd: AsFd>(dirfd: Fd, path: P, mode: Mode) -> io::Result<()> {
    mkdirat(&dirfd, path, mode).map_or_else(
        |op| match op {
            Errno::EXIST => Ok(()),
            err => Err(io::Error::from(err)),
        },
        |_| Ok(()),
    )
}

fn unshare_root() -> io::Result<()> {
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(Into::into)
}
fn mount_dev(dfd: &OwnedFd) -> io::Result<()> {
    let fsfd = fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_set_string(&fsfd, "size", "1024M")?;
    fsconfig_set_string(&fsfd, "mode", "0755")?;
    fsconfig_create(&fsfd)?;
    let mountfd = fsmount(
        &fsfd,
        FsMountFlags::empty(),
        MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )?;
    move_mount(
        mountfd,
        "",
        dfd,
        "dev",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    let dev_dfd = openat(
        dfd,
        "dev",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    mkdirat(&dev_dfd, "pts", Mode::from_raw_mode(0o755))?;
    static LINKS: [(&str, &str); 6] = [
        ("pts/ptmx", "ptmx"),
        ("pts/0", "console"),
        ("/proc/kcore", "core"),
        ("/proc/self/fd/0", "stdin"),
        ("/proc/self/fd/1", "stdout"),
        ("/proc/self/fd/2", "stderr"),
    ];
    for (target, path) in LINKS {
        symlinkat(target, &dev_dfd, path)?;
    }
    static DEVICES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];
    let host_dfd = openat(
        CWD,
        "/dev",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    for name in DEVICES {
        let target_fd = openat(
            &dev_dfd,
            name,
            OFlags::CREATE | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::from_raw_mode(0o700),
        )?;
        let mnt_fd = open_tree(&host_dfd, name, OpenTreeFlags::OPEN_TREE_CLONE)?;
        move_mount(
            &mnt_fd,
            "",
            &target_fd,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        )?;
    }
    Ok(())
}
fn mount_pts(dfd: &OwnedFd) -> io::Result<()> {
    let fsfd = fsopen("devpts", FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_set_string(&fsfd, "gid", "5")?;
    fsconfig_set_string(&fsfd, "mode", "620")?;
    fsconfig_set_string(&fsfd, "ptmxmode", "0666")?;
    fsconfig_create(&fsfd)?;
    let mountfd = fsmount(
        &fsfd,
        FsMountFlags::empty(),
        MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NOEXEC
            | MountAttrFlags::MOUNT_ATTR_RELATIME,
    )?;
    move_mount(
        mountfd,
        "",
        dfd,
        "dev/pts",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}
fn mount_proc(dfd: &OwnedFd) -> io::Result<()> {
    let fsfd = fsopen("proc", FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_create(&fsfd)?;
    let mountfd = fsmount(
        &fsfd,
        FsMountFlags::empty(),
        MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NOEXEC
            | MountAttrFlags::MOUNT_ATTR_RELATIME,
    )?;
    move_mount(
        mountfd,
        "",
        dfd,
        "proc",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}
fn mount_run(dfd: &OwnedFd) -> io::Result<()> {
    let fsfd = fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_create(&fsfd)?;
    let mountfd = fsmount(
        &fsfd,
        FsMountFlags::empty(),
        MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NOEXEC
            | MountAttrFlags::MOUNT_ATTR_RELATIME,
    )?;
    move_mount(
        mountfd,
        "",
        dfd,
        "run",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    let run_fd = openat(
        dfd,
        "run",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    mkdirat(&run_fd, "lock", Mode::from_raw_mode(0o1777))?;
    Ok(())
}

struct SandboxExitStatus(i32);

impl SandboxExitStatus {
    pub fn is_success(&self) -> bool {
        self.0 == 0
    }
    pub fn code(&self) -> i32 {
        self.0
    }
}

impl From<SandboxExitStatus> for i32 {
    fn from(status: SandboxExitStatus) -> Self {
        status.code()
    }
}

impl std::fmt::Display for SandboxExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

struct SandboxStatus(OwnedFd);

impl SandboxStatus {
    async fn status(&self) -> io::Result<SandboxExitStatus> {
        let pidfd = dup(self.0.as_fd())?;
        let file = std::fs::File::from(pidfd);
        let afd = smol::Async::new(file)?;
        loop {
            afd.readable()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            match waitid(WaitId::PidFd(self.0.as_fd()), WaitIdOptions::EXITED) {
                Ok(Some(status)) => {
                    if let Some(code) = status.exit_status() {
                        break Ok(SandboxExitStatus(code));
                    }
                    if let Some(sig) = status.terminating_signal() {
                        break Err(io::Error::other(format!(
                            "sandbox killed by signal {}",
                            sig
                        )));
                    }
                    break Err(io::Error::other("sandbox terminated (unknown status)"));
                }
                Ok(None) => {
                    continue;
                }
                Err(Errno::INTR) => continue,
                Err(err) => {
                    break Err(io::Error::other(format!(
                        "error waiting for sandbox: {}",
                        err
                    )))
                }
            }
        }
    }
}

fn spawn_sandbox<A>(args: A, needs_unshare: bool) -> io::Result<OwnedFd>
where
    A: IntoIterator,
    A::Item: Arg,
{
    let uid_map = (needs_unshare && !geteuid().is_root())
        .then(|| UidMap::new())
        .transpose()?;

    let name = SANDBOX_COMMAND_NAME
        .get()
        .expect("sandbox command name is not initialized");

    let args: Vec<Cow<'_, CStr>> = once(Arg::into_c_str(name))
        .chain(args.into_iter().map(|s| s.into_c_str()))
        .collect::<Result<Vec<_>, Errno>>()?;

    let argv: Vec<*mut libc::c_char> = args
        .iter()
        .map(|s| s.as_ptr() as *mut libc::c_char)
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();

    let ppidfd = pidfd_open(getpid(), PidfdFlags::empty()).map_err(io::Error::from)?;
    let mut ppidfd_flags = fcntl_getfd(&ppidfd)?;
    ppidfd_flags.insert(FdFlags::CLOEXEC);
    fcntl_setfd(&ppidfd, ppidfd_flags)?;

    let ppidfd_raw = ppidfd.as_raw_fd();
    let mut pfd = libc::pollfd {
        fd: ppidfd_raw,
        events: libc::POLLIN,
        revents: 0,
    };

    let fd = openat(
        CWD,
        "/proc/self/exe",
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let fd_raw = fd.as_raw_fd();
    let mut pidfd = -1;

    let mut sem: Option<(OwnedFd, OwnedFd)> = None;
    let mut sem_rd = -1;

    let mut clone = Clone3::default();
    clone
        .flag_pidfd(&mut pidfd)
        .exit_signal(rustix::process::Signal::CHILD.as_raw() as u64);
    if needs_unshare {
        clone
            .flag_newnet()
            .flag_newipc()
            .flag_newpid()
            .flag_newuts()
            .flag_newns();
        if uid_map.is_some() {
            clone.flag_newuser();
            let (rfd, wfd) = pipe::pipe()?;
            let mut flags = fcntl_getfd(&rfd)?;
            flags.remove(FdFlags::CLOEXEC);
            fcntl_setfd(&rfd, flags)?;
            sem_rd = rfd.as_raw_fd();
            sem = Some((rfd, wfd));
        }
    }

    match unsafe { clone.call()? } {
        0 => unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                libc::_exit(127);
            }
            loop {
                let n = libc::poll(&mut pfd as *mut libc::pollfd, 1, 0);
                if n == 0 {
                    break;
                } else if n > 0 {
                    libc::_exit(127);
                } else {
                    let e = *libc::__errno_location();
                    if e == libc::EINTR {
                        continue;
                    } else {
                        libc::_exit(127);
                    }
                }
            }
            if sem_rd >= 0 {
                let mut b = 0u8;
                if libc::read(sem_rd, &mut b as *mut u8 as *mut libc::c_void, 1) != 1 {
                    static ERR_MSG: &[u8] = b"read failed\n";
                    let _ = libc::write(
                        libc::STDERR_FILENO,
                        ERR_MSG.as_ptr() as *const _,
                        ERR_MSG.len(),
                    );
                    libc::_exit(127);
                }
                libc::close(sem_rd);
            }
            extern "C" {
                static mut environ: *mut *mut libc::c_char;
            }
            let envp: *const *mut libc::c_char = environ as *const *mut libc::c_char;
            libc::execveat(
                fd_raw,
                c"".as_ptr(),
                argv.as_ptr(),
                envp,
                libc::AT_EMPTY_PATH,
            );
            static ERR_MSG: &[u8] = b"execveat failed\n";
            let err = *libc::__errno_location();
            let _ = libc::write(
                libc::STDERR_FILENO,
                ERR_MSG.as_ptr() as *const _,
                ERR_MSG.len(),
            );
            let code = match err {
                libc::EACCES | libc::EPERM => 126,
                _ => 127,
            };
            libc::_exit(code);
        },
        child => {
            if let Some((rfd, wfd)) = sem {
                drop(rfd);
                uid_map.unwrap().map_uid(&Pid::from_raw(child).unwrap())?;
                let mut f: std::fs::File = wfd.into();
                f.write(&[1u8])?;
            }
            Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
        }
    }
}

static SANDBOX_COMMAND_NAME: OnceLock<OsString> = OnceLock::new();

fn init_sandbox_name(name: OsString) -> &'static OsStr {
    SANDBOX_COMMAND_NAME
        .set(name)
        .expect("sandbox name already initialized");
    SANDBOX_COMMAND_NAME.get().unwrap()
}

fn initial_buf_size(sysconf_name: libc::c_int, fallback: usize) -> usize {
    unsafe {
        let n = libc::sysconf(sysconf_name);
        if n > 0 {
            n as usize
        } else {
            fallback
        }
    }
}

fn get_user_name(uid: Uid) -> Option<String> {
    let buf_len = initial_buf_size(libc::_SC_GETPW_R_SIZE_MAX, 2048);

    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; buf_len];

    let rc = unsafe {
        libc::getpwuid_r(
            uid.as_raw(),
            &mut pwd as *mut libc::passwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result as *mut *mut libc::passwd,
        )
    };
    if rc == 0 {
        if result.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned();
        Some(name)
    } else {
        None
    }
}

struct UidMap {
    uid: u32,
    subuid_start: u32,
    subuid_count: u32,
    gid: u32,
    subgid_start: u32,
    subgid_count: u32,
}

impl UidMap {
    fn new() -> io::Result<Self> {
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let user_name = get_user_name(geteuid()).ok_or_else(|| io::Error::other("no such user"))?;
        let subuid = SubIdEntry::read_entries("/etc/subuid")?
            .find_map(|item| match item {
                Ok(item) => (item.name == user_name).then_some(item),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("no subuid entry"))?;
        let subgid = SubIdEntry::read_entries("/etc/subgid")?
            .find_map(|item| match item {
                Ok(item) => (item.name == user_name).then_some(item),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("no subgid entry"))?;
        Ok(Self {
            uid,
            subuid_start: subuid.start,
            subuid_count: subuid.count,
            gid,
            subgid_start: subgid.start,
            subgid_count: subgid.count,
        })
    }
    fn map_uid(&self, pid: &Pid) -> io::Result<()> {
        match Command::new("newuidmap")
            .arg(pid.to_string())
            .arg("0")
            .arg(self.uid.to_string())
            .arg("1")
            .arg("1")
            .arg(self.subuid_start.to_string())
            .arg(self.subuid_count.to_string())
            .status()
        {
            Ok(status) if status.success() => (),
            Ok(_) => return Err(io::Error::other("failed to run newuidmap")),
            Err(err) => return Err(err),
        };
        match Command::new("newgidmap")
            .arg(pid.to_string())
            .arg("0")
            .arg(self.gid.to_string())
            .arg("1")
            .arg("1")
            .arg(self.subgid_start.to_string())
            .arg(self.subgid_count.to_string())
            .status()
        {
            Ok(status) if status.success() => Ok(()),
            Ok(_) => Err(io::Error::other("failed to run newgidmap")),
            Err(err) => Err(err),
        }
    }
}

struct SubIdEntry {
    name: String,
    start: u32,
    count: u32,
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
                                if let Ok(start) = start.parse::<u32>() {
                                    if let Some(count) = parts.next() {
                                        if let Ok(count) = count.parse::<u32>() {
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
