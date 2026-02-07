use {
    rustix::{
        fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        fs::{mkdirat, openat, readlinkat, symlinkat, Mode, OFlags, Uid, CWD},
        io::{dup, dup2, fcntl_getfd, fcntl_setfd, Errno, FdFlags},
        mount::{
            fsconfig_create, fsconfig_set_string, fsmount, fsopen, mount_change, move_mount,
            open_tree, unmount, FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags,
            MoveMountFlags, OpenTreeFlags, UnmountFlags,
        },
        path::Arg,
        pipe::pipe,
        process::{
            fchdir, getegid, geteuid, getpid, pidfd_open, pivot_root, waitid, PidfdFlags, WaitId,
            WaitIdOptions,
        },
        thread::{unshare_unsafe, UnshareFlags},
    },
    std::{
        borrow::Cow,
        convert::Infallible,
        env::ArgsOs,
        ffi::{CStr, OsStr, OsString},
        io::{self},
        iter::once,
        os::unix::{ffi::OsStrExt, process::CommandExt},
        path::Path,
        process::Command,
        sync::OnceLock,
    },
};

pub fn unshare_root() -> io::Result<()> {
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(Into::into)
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

pub(crate) fn setup_root(root: impl AsFd) -> io::Result<()> {
    let root_dfd = root.as_fd();
    fchdir(root_dfd)?;
    mkdirat_if_not_exist(root_dfd, "dev", Mode::from_raw_mode(0o755))?;
    mkdirat_if_not_exist(root_dfd, "proc", Mode::from_raw_mode(0o755))?;
    mkdirat_if_not_exist(root_dfd, "sys", Mode::from_raw_mode(0o755))?;
    mkdirat_if_not_exist(root_dfd, "run", Mode::from_raw_mode(0o755))?;
    mount_dev(root_dfd)?;
    mount_pts(root_dfd)?;
    mount_proc(root_dfd)?;
    mount_run(root_dfd)?;
    pivot_root(".", ".")?;
    unmount(".", UnmountFlags::DETACH)?;
    Ok(())
}

fn mount_dev(dfd: impl AsFd) -> io::Result<()> {
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
        dfd.as_fd(),
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
    static LINKS: [(&str, &str); 7] = [
        ("pts/ptmx", "ptmx"),
        ("pts/0", "console"),
        ("/proc/kcore", "core"),
        ("/proc/self/fd", "fd"),
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
fn mount_pts(dfd: impl AsFd) -> io::Result<()> {
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
        dfd.as_fd(),
        "dev/pts",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}
fn mount_proc(dfd: impl AsFd) -> io::Result<()> {
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
        dfd.as_fd(),
        "proc",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}
fn mount_sys(dfd: impl AsFd) -> io::Result<()> {
    let fsfd = fsopen("sysfs", FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_create(&fsfd)?;
    let mntfd = fsmount(
        &fsfd,
        FsMountFlags::empty(),
        MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NOEXEC
            | MountAttrFlags::MOUNT_ATTR_RELATIME,
    )?;
    move_mount(
        mntfd,
        "",
        dfd.as_fd(),
        "sys",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}
fn mount_run(dfd: impl AsFd) -> io::Result<()> {
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
        dfd.as_fd(),
        "run",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    let run_fd = openat(
        dfd.as_fd(),
        "run",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    mkdirat(&run_fd, "lock", Mode::from_raw_mode(0o1777))?;
    Ok(())
}

pub(crate) struct HelperExitStatus(i32);

impl HelperExitStatus {
    pub fn is_success(&self) -> bool {
        self.0 == 0
    }
    pub fn code(&self) -> i32 {
        self.0
    }
}

impl From<HelperExitStatus> for i32 {
    fn from(status: HelperExitStatus) -> Self {
        status.code()
    }
}

impl std::fmt::Display for HelperExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

pub(crate) struct HelperStatus(OwnedFd);

impl From<OwnedFd> for HelperStatus {
    fn from(fd: OwnedFd) -> Self {
        Self(fd)
    }
}

impl HelperStatus {
    pub async fn status(&self) -> io::Result<HelperExitStatus> {
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
                        break Ok(HelperExitStatus(code));
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
    pub fn status_sync(&self) -> io::Result<HelperExitStatus> {
        loop {
            match waitid(WaitId::PidFd(self.0.as_fd()), WaitIdOptions::EXITED) {
                Ok(Some(status)) => {
                    if let Some(code) = status.exit_status() {
                        break Ok(HelperExitStatus(code));
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

pub(crate) fn spawn_helper<I>(name: &str, args: I, unshare: bool) -> io::Result<OwnedFd>
where
    I: IntoIterator,
    I::Item: Arg,
{
    let mut argv0 = HELPER_COMMAND_NAME
        .get()
        .expect("sandbox command name is not initialized")
        .clone();
    argv0.push(name);

    let args = once(Arg::into_c_str(&argv0))
        .chain(args.into_iter().map(Arg::into_c_str))
        .collect::<Result<Vec<_>, Errno>>()?;

    let argv = args
        .iter()
        .map(|a| a.as_ptr() as *mut libc::c_char)
        .chain(once(std::ptr::null_mut()))
        .collect::<Vec<_>>();

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

    let clone_args = libc::clone_args {
        flags: (if unshare {
            libc::CLONE_NEWNET
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWNS
        } else {
            0
        } | libc::CLONE_PIDFD) as u64,
        pidfd: std::ptr::addr_of_mut!(pidfd) as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: rustix::process::Signal::CHILD.as_raw() as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };

    match unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &clone_args,
            std::mem::size_of::<libc::clone_args>(),
        )
    } {
        -1 => Err(io::Error::last_os_error()),
        0 => unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                libc::_exit(127);
            }
            loop {
                match libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) {
                    0 => break,
                    n if n > 0 => libc::_exit(127),
                    _ => {
                        let e = *libc::__errno_location();
                        if e == libc::EINTR {
                            continue;
                        } else {
                            libc::_exit(127);
                        }
                    }
                }
            }
            extern "C" {
                static mut environ: *const *mut libc::c_char;
            }
            libc::execveat(
                fd_raw,
                c"".as_ptr(),
                argv.as_ptr(),
                environ,
                libc::AT_EMPTY_PATH,
            );
            static ERR_MSG: &str = concat!(stringify!($name), " failed\n");
            let _ = libc::write(
                libc::STDERR_FILENO,
                ERR_MSG.as_ptr() as *const _,
                ERR_MSG.len(),
            );
            libc::_exit(match *libc::__errno_location() {
                libc::EACCES | libc::EPERM => 126,
                _ => 127,
            });
        },
        _ => Ok(unsafe { OwnedFd::from_raw_fd(pidfd) }),
    }
}

pub fn maybe_run_helper<F>(f: F)
where
    F: FnOnce(ArgsOs) -> io::Result<()>,
{
    let link = match readlinkat(CWD, "/proc/self/exe", vec![0u8; libc::PATH_MAX as usize]) {
        Ok(link) => link,
        Err(_) => return,
    };
    let mut name = match Path::new(OsStr::from_bytes(link.as_bytes())).file_name() {
        Some(name) => name.to_os_string(),
        None => return,
    };
    name.push("-");
    let name = init_helper_name(name);
    let mut args = std::env::args_os();
    let arg0 = args.next();
    if arg0.is_none() {
        return;
    }
    let arg0 = arg0.as_ref().unwrap().as_bytes();
    if !arg0.starts_with(name.as_bytes()) {
        return;
    }
    match match &arg0[name.len()..] {
        b"uidmap" => unshare_user_ns_helper(args),
        b"runner" => f(args),
        _ => Err(io::Error::other("unknown helper command")),
    } {
        Ok(()) => std::process::exit(0),
        Err(err) => {
            {
                eprintln!("helper: {}", err);
            };
            std::process::exit(127);
        }
    }
}

static HELPER_COMMAND_NAME: OnceLock<OsString> = OnceLock::new();

fn init_helper_name(name: OsString) -> &'static OsStr {
    HELPER_COMMAND_NAME
        .set(name)
        .expect("sandbox name already initialized");
    HELPER_COMMAND_NAME.get().unwrap()
}

fn set_cloexec(fd: impl AsFd, cloexec: bool) -> io::Result<()> {
    let mut flags = fcntl_getfd(&fd)?;
    if cloexec {
        flags.insert(FdFlags::CLOEXEC);
    } else {
        flags.remove(FdFlags::CLOEXEC);
    }
    fcntl_setfd(&fd, flags).map_err(Into::into)
}

struct EnvironIter<'a> {
    env: *mut *mut libc::c_char,
    phantom: std::marker::PhantomData<&'a str>,
}
impl EnvironIter<'_> {
    fn new() -> Self {
        extern "C" {
            static mut environ: *mut *mut libc::c_char;
        }
        Self {
            env: unsafe { environ },
            phantom: std::marker::PhantomData,
        }
    }
}
impl<'a> Iterator for EnvironIter<'a> {
    type Item = Cow<'a, CStr>;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if (*self.env).is_null() {
                None
            } else {
                let item = CStr::from_ptr(*self.env);
                self.env = self.env.add(1);
                Some(item.into())
            }
        }
    }
}

pub fn exec<A>(args: A) -> io::Result<Infallible>
where
    A: IntoIterator,
    A::Item: Arg,
{
    let args = args
        .into_iter()
        .map(|s| s.into_c_str())
        .collect::<Result<Vec<_>, Errno>>()?;
    let argv = args
        .iter()
        .map(|arg| arg.as_ptr() as *const libc::c_char)
        .chain(once(std::ptr::null()))
        .collect::<Vec<_>>();
    let environ = EnvironIter::<'_>::new().collect::<Vec<_>>();
    let envp = environ
        .iter()
        .map(|e| e.as_ptr() as *const libc::c_char)
        .chain(once(std::ptr::null()))
        .collect::<Vec<_>>();
    unsafe { libc::execvpe(argv[0], argv.as_ptr(), envp.as_ptr()) };
    // execve failed
    Err(io::Error::last_os_error())
}

pub fn unshare_user_ns<I>(env: I) -> io::Result<Infallible>
where
    I: IntoIterator,
    I::Item: Arg,
{
    let proc_fd = openat(
        CWD,
        "/proc/self",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    let exec_fd = openat(
        &proc_fd,
        "exe",
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let exec_fd_raw = exec_fd.as_raw_fd();
    let (rd, mut wd) = pipe()?;
    set_cloexec(&mut wd, true)?;
    let status = HelperStatus(spawn_helper(
        "uidmap",
        [rd.as_raw_fd().to_string(), proc_fd.as_raw_fd().to_string()],
        false,
    )?);
    drop(rd);
    drop(proc_fd);
    unsafe { unshare_unsafe(UnshareFlags::NEWUSER) }?;
    rustix::io::write(&wd, &[0u8; 1])?;
    drop(wd);
    status.status_sync().and_then(|status| {
        status.is_success().then_some(()).ok_or_else(|| {
            io::Error::other(format!(
                "failed to setup uid/gid map: exited with code {}",
                status
            ))
        })
    })?;
    let args = std::env::args_os()
        .map(|s| s.into_c_str())
        .collect::<Result<Vec<_>, Errno>>()?;
    let argv = args
        .iter()
        .map(|arg| arg.as_ptr() as *mut libc::c_char)
        .chain(once(std::ptr::null_mut()))
        .collect::<Vec<_>>();
    let environ = EnvironIter::<'_>::new()
        .map(Ok)
        .chain(env.into_iter().map(|a| a.into_c_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let envp = environ
        .iter()
        .map(|e| e.as_ptr() as *mut libc::c_char)
        .chain(once(std::ptr::null_mut()))
        .collect::<Vec<_>>();
    unsafe {
        libc::execveat(
            exec_fd_raw,
            c"".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    // execveat failed
    Err(io::Error::last_os_error())
}

trait FdArg {
    fn fd_arg(&mut self) -> io::Result<OwnedFd>;
}

impl FdArg for std::env::ArgsOs {
    fn fd_arg(&mut self) -> io::Result<OwnedFd> {
        self.next()
            .ok_or_else(|| io::Error::other("missing fd argument"))
            .and_then(|s| {
                s.into_string().map_err(|err| {
                    io::Error::other(format!("invalid fd argument: {}", err.to_string_lossy()))
                })
            })
            .and_then(|s| {
                s.parse::<i32>()
                    .map_err(|err| io::Error::other(format!("failed to parse fd: {}", err)))
            })
            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

pub(crate) fn unshare_user_ns_helper(mut args: std::env::ArgsOs) -> io::Result<()> {
    rustix::io::read(args.fd_arg()?, &mut [0u8; 0])?;
    let dfd = args.fd_arg()?;
    openat(
        &dfd,
        "uid_map",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| io::Error::other(format!("failed to open <0>/uid_map: {}", err)))?;
    let uid_map = UidMap::new()?;
    uid_map.map_uid(&dfd)?;
    Ok(())
}

pub fn get_user_name(uid: Uid) -> Option<String> {
    let buf_len = unsafe {
        let n = libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX);
        if n > 0 {
            n as usize
        } else {
            2048
        }
    };

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
    fn map_uid(&self, dfd: impl AsFd) -> io::Result<()> {
        fn cmd(name: &str, dfd: i32, uid: u32, map_start: u32, map_count: u32) -> Command {
            let mut cmd = Command::new(name);
            cmd.arg("fd:0")
                .arg("0")
                .arg(uid.to_string())
                .arg("1")
                .arg("1")
                .arg(map_start.to_string())
                .arg(map_count.to_string());
            unsafe {
                cmd.pre_exec(move || {
                    let dfd = OwnedFd::from_raw_fd(dfd);
                    let mut fd = OwnedFd::from_raw_fd(0);
                    dup2(dfd, &mut fd)?;
                    let _ = fd.into_raw_fd();
                    Ok(())
                })
            };
            cmd
        }
        match cmd(
            "newuidmap",
            dfd.as_fd().as_raw_fd(),
            self.uid,
            self.subuid_start,
            self.subuid_count,
        )
        .status()
        {
            Ok(status) if status.success() => (),
            Ok(_) => return Err(io::Error::other("failed to run newuidmap")),
            Err(err) => return Err(err),
        };
        match cmd(
            "newgidmap",
            dfd.as_fd().as_raw_fd(),
            self.gid,
            self.subgid_start,
            self.subgid_count,
        )
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
