use {
    crate::builder::{BuildRunner, Builder},
    clone3::Clone3,
    rustix::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        fs::{openat, readlinkat, Gid, Mode, OFlags, Uid, CWD},
        io::{dup, read, write, fcntl_getfd, fcntl_setfd, Errno, FdFlags},
        path::Arg,
        pipe,
        process::{getpid, geteuid, getegid, pidfd_open, waitid, PidfdFlags, WaitId, WaitIdOptions}, thread::{unshare_unsafe, UnshareFlags},
    },
    std::{
        process::Command,
        borrow::Cow,
        env::ArgsOs,
        ffi::{CStr, CString, OsStr},
        io::{self, Write},
        iter::once,
        os::unix::ffi::OsStrExt,
        path::Path,
        sync::OnceLock,
    },
};


pub struct HelperExitStatus(i32);

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

pub struct Helper(OwnedFd);

impl Helper {
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
                        break Err(io::Error::other(format!("helper killed by signal {}", sig)));
                    }
                    break Err(io::Error::other("helper terminated (unknown status)"));
                }
                Ok(None) => {
                    continue;
                }
                Err(Errno::INTR) => continue,
                Err(err) => {
                    break Err(io::Error::other(format!(
                        "error waiting for helper: {}",
                        err
                    )))
                }
            }
        }
    }
    pub fn sync_status(&self) -> io::Result<HelperExitStatus> {
        loop {
            match waitid(WaitId::PidFd(self.0.as_fd()), WaitIdOptions::EXITED) {
                Ok(Some(status)) => {
                    if let Some(code) = status.exit_status() {
                        break Ok(HelperExitStatus(code));
                    }
                    if let Some(sig) = status.terminating_signal() {
                        break Err(io::Error::other(format!("helper killed by signal {}", sig)));
                    }
                    break Err(io::Error::other("helper terminated (unknown status)"));
                }
                Ok(None) => {
                    continue;
                }
                Err(Errno::INTR) => continue,
                Err(err) => {
                    break Err(io::Error::other(format!(
                        "error waiting for helper: {}",
                        err
                    )))
                }
            }
        }
    }
}

fn spawn_helper<A>(subcommand: &str, args: A, unshare: bool) -> io::Result<OwnedFd>
where
    A: IntoIterator,
    A::Item: Arg,
{
    let name = HELPER_NAME
        .get()
        .map(|s| s.as_c_str())
        .expect("helper name not initialized");

    let args: Vec<Cow<'_, CStr>> = once(Arg::into_c_str(name))
        .chain(once(Arg::into_c_str(subcommand)))
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

    let mut clone = Clone3::default();
    clone
        .flag_pidfd(&mut pidfd)
        .exit_signal(rustix::process::Signal::CHILD.as_raw() as u64);
    if unshare {
        clone
            .flag_newnet()
            .flag_newpid()
            .flag_newns()
            .flag_newuts()
            .flag_newipc();
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
        _child => Ok(unsafe { OwnedFd::from_raw_fd(pidfd) }),
    }
}

pub fn maybe_run_helper<B: Builder>() {
    let link = match readlinkat(CWD, "/proc/self/exe", vec![0u8; libc::PATH_MAX as usize]) {
        Ok(link) => link,
        Err(_) => return,
    };
    let mut name = match Path::new(OsStr::from_bytes(link.as_bytes())).file_name() {
        Some(name) => name.to_os_string(),
        None => return,
    };
    name.push("-helper");

    let mut args = std::env::args_os();
    if let Some(arg0) = args.next() {
        if arg0 != name {
            init_helper_name(&name);
            return;
        }
    } else {
        return;
    }
    match match args.next() {
        Some(cmd) if cmd == UnshareUserNs::NAME => {
            <<UnshareUserNs as ExecHelper>::PassParam as PassParamStrategy<UnshareUserNs>>::exec(args)
        }
        Some(cmd) if cmd == BuildRunner::<B>::NAME => {
            <<BuildRunner<B> as ExecHelper>::PassParam as PassParamStrategy<BuildRunner<B>>>::exec(args)
        }
        Some(cmd) => Err(std::io::Error::other(format!(
            "unknown command {}",
            cmd.to_string_lossy()
        ))),
        None => Err(std::io::Error::other("no command")),
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


static HELPER_NAME: OnceLock<CString> = OnceLock::new();

pub fn init_helper_name(name: &OsStr) {
    let _ = HELPER_NAME.set(CString::new(name.as_bytes()).expect("a valid process name"));
}

pub trait ExecHelper
where
    Self: Sized,
{
    const NAME: &'static str;
    const UNSHARE: bool = false;
    type PassParam: PassParamStrategy<Self>;
    fn spawn(&self) -> io::Result<Helper> {
        <Self::PassParam as PassParamStrategy<Self>>::spawn(self)
    }
    fn exec(self) -> io::Result<()>;
}

pub trait PassParamStrategy<H: ExecHelper> {
    fn spawn(h: &H) -> io::Result<Helper>;
    fn exec(args: ArgsOs) -> io::Result<()>;
}

pub struct WithArgs;
pub struct WithSerde;

pub trait Argv
where
    Self: Sized,
{
    fn as_argv(&self) -> impl IntoIterator<Item = std::borrow::Cow<'_, str>>;
    fn from_argv<S: AsRef<str>>(args: &[S]) -> io::Result<Self>;
}

impl<H> PassParamStrategy<H> for WithArgs
where
    H: ExecHelper + Argv,
{
    fn spawn(h: &H) -> io::Result<Helper> {
        let args = h.as_argv();
        spawn_helper(H::NAME, args, H::UNSHARE).map(Helper)
    }
    fn exec(args: ArgsOs) -> io::Result<()> {
        let args: Vec<String> = args
            .map(|s| {
                s.into_string()
                    .map_err(|_| io::Error::other("invalid argument"))
            })
            .collect::<Result<_, _>>()?;
        let helper = H::from_argv(&args)?;
        helper.exec()
    }
}

impl<H> PassParamStrategy<H> for WithSerde
where
    H: ExecHelper + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn spawn(h: &H) -> io::Result<Helper> {
        let (rfd, wfd) = pipe::pipe()?;
        let mut flags = fcntl_getfd(&rfd)?;
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(&rfd, flags)?;
        let status = spawn_helper(H::NAME, once(rfd.as_raw_fd().to_string()), H::UNSHARE)?;
        let mut wr: std::fs::File = wfd.into();
        bincode::serde::encode_into_std_write(h, &mut wr, bincode::config::standard()).map_err(
            |err| {
                io::Error::other(format!(
                    "failed to send parameters to helper process: {}",
                    err
                ))
            },
        )?;
        wr.flush()?;
        drop(wr);
        Ok(Helper(status))
    }
    fn exec(mut args: ArgsOs) -> io::Result<()> {
        let fd = args
            .next()
            .ok_or_else(|| io::Error::other("helper: expects an fd param"))
            .and_then(|s| {
                s.into_string().map_err(|err| {
                    io::Error::other(format!(
                        "helper: invalid fd param: {}",
                        err.to_string_lossy()
                    ))
                })
            })
            .and_then(|s| {
                s.parse::<i32>()
                    .map_err(|err| io::Error::other(format!("helper: failed to parse fd: {}", err)))
            })?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut rd: std::fs::File = fd.into();
        let helper: H = bincode::serde::decode_from_std_read(&mut rd, bincode::config::standard())
            .map_err(|err| {
                io::Error::other(format!(
                    "failed to get parameters from calling process: {}",
                    err
                ))
            })?;
        drop(rd);
        helper.exec()
    }
}

pub struct UnshareUserNs {
    pub fd: i32,
    pub ppid: i32,
    pub uid: u32,
    pub subuid_start: u32,
    pub subuid_count: u32,
    pub gid: u32,
    pub subgid_start: u32,
    pub subgid_count: u32,
}

impl UnshareUserNs {
    fn really_unshare(
        uid: Uid,
        subuid: SubIdEntry,
        gid: Gid,
        subgid: SubIdEntry,
    ) -> io::Result<()> {
        let ppid = getpid();
        let (rfd, wfd) = pipe::pipe()?;
        let mut flags = fcntl_getfd(&rfd)?;
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(&rfd, flags)?;

        let helper = Self{
            fd: rfd.as_raw_fd(),
            ppid: ppid.as_raw_pid(),
            uid: uid.as_raw(),
            subuid_start: subuid.start,
            subuid_count: subuid.count,
            gid: gid.as_raw(),
            subgid_start: subgid.start,
            subgid_count: subgid.count,
        }.spawn()?;

        unsafe {
            unshare_unsafe(UnshareFlags::NEWUSER)
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
        }?;

        write(&wfd, &[1])?;
        drop((rfd, wfd));
        helper.sync_status().and_then(|status| if status.is_success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("helper exited with code {}", status.code())))
        })
    }
    pub fn unshare() -> Option<io::Result<()>> {
        let uid = geteuid();
        let gid = getegid();
        let user_name = get_user_name(uid)?;
        let subuid = SubIdEntry::read_entries("/etc/subuid")
            .ok()?
            .find_map(|item| match item {
                Ok(item) => (item.name == user_name).then_some(item),
                _ => None,
            })?;
        let subgid = SubIdEntry::read_entries("/etc/subgid")
            .ok()?
            .find_map(|item| match item {
                Ok(item) => (item.name == user_name).then_some(item),
                _ => None,
            })?;
        Some(Self::really_unshare(uid, subuid, gid, subgid))
    }
}

impl Argv for UnshareUserNs {
    fn as_argv(&self) -> impl IntoIterator<Item = std::borrow::Cow<'_, str>> {
        once(self.fd.to_string())
        .chain(once(self.ppid.to_string()))
        .chain(once(self.uid.to_string()))
        .chain(once(self.subuid_start.to_string()))
        .chain(once(self.subuid_count.to_string()))
        .chain(once(self.gid.to_string()))
        .chain(once(self.subgid_start.to_string()))
        .chain(once(self.subgid_count.to_string()))
        .map(|s| s.into())
    }
    fn from_argv<S: AsRef<str>>(args: &[S]) -> io::Result<Self> {
        let mut args = args.iter().map(|s| s.as_ref());
        fn err<T>(name: &'static str) -> io::Result<T> {
            Err(io::Error::other(format!("helper: missing {}", name)))
        }
        fn parse<T: std::str::FromStr>(s: &str) -> io::Result<T> {
            s.parse::<T>()
                .map_err(|_| io::Error::other(format!("helper: failed to parse param ({})", s)))
        }
        Ok(Self{
            fd: args.next().map_or_else(|| err("fd"), parse)?,
            ppid: args.next().map_or_else(|| err("ppid"), parse)?,
            uid: args.next().map_or_else(|| err("uid"), parse)?,
            subuid_start: args.next().map_or_else(|| err("subuid_start"), parse)?,
            subuid_count: args.next().map_or_else(|| err("subuid_count"), parse)?,
            gid: args.next().map_or_else(|| err("gid"), parse)?,
            subgid_start: args.next().map_or_else(|| err("subgid_start"), parse)?,
            subgid_count: args.next().map_or_else(|| err("subgid_count"), parse)?,
        })
    }
}

impl ExecHelper for UnshareUserNs {
    const NAME: &'static str = "mapuids";
    type PassParam = WithArgs;
    fn exec(self) -> io::Result<()> {
        let fd = unsafe { OwnedFd::from_raw_fd(self.fd) };
        let mut byte = [0u8; 1];
        read(fd, &mut byte)?;
        if byte[0] != 1 {
            return Err(io::Error::other("invalid response"));
        }
        match Command::new("newuidmap")
            .arg(self.ppid.to_string())
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
            .arg(self.ppid.to_string())
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
