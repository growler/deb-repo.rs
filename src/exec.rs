use {
    clone3::Clone3,
    rustix::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        fs::{openat, Mode, OFlags, CWD},
        io::{dup, fcntl_getfd, fcntl_setfd, Errno, FdFlags},
        path::Arg,
        pipe,
        process::{getpid, pidfd_open, waitid, PidfdFlags, WaitId, WaitIdOptions},
    },
    std::{
        borrow::Cow, env::ArgsOs, ffi::{CStr, CString}, io::{self, Write}, iter::once, sync::OnceLock
    },
};

pub use crate::unshare::UnshareUserNs;

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
        let afd = async_io::Async::new(file)?;
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

    static EMPTY_CSTR: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") };

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
                EMPTY_CSTR.as_ptr(),
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
        _child => {
            return Ok(unsafe { OwnedFd::from_raw_fd(pidfd) });
        }
    }
}

#[macro_export]
macro_rules! helper {
    ($vis:vis fn $fn:ident $name:literal [$($path:path),* $(,)?]) => {
        $vis fn $fn() {
            use $crate::exec::{ExecHelper, PassParamStrategy};

            const _: () = {
                const NAMES: &[(&str, &str)] = &[
                    $((<$path as ExecHelper>::NAME, stringify!($path))),*
                ];
                const fn str_eq(a: &str, b: &str) -> bool {
                    let ab = a.as_bytes();
                    let bb = b.as_bytes();
                    if ab.len() != bb.len() { return false; }
                    let mut i = 0;
                    while i < ab.len() {
                        if ab[i] != bb[i] { return false; }
                        i += 1;
                    }
                    true
                }
                let mut i = 0;
                while i < NAMES.len() {
                    match NAMES[i] {
                    $(
                        (name, typename) => {
                            if str_eq(name, <$path as ExecHelper>::NAME) && !str_eq(typename, stringify!($path)) {
                                panic!("non-unique helper ExecHelper::NAME");
                            }
                        }
                    )*
                        _ => {}
                    }
                    i += 1;
                }
            };
            let mut args = std::env::args_os();
            if let Some(arg0) = args.next() {
                if arg0.as_encoded_bytes() != $name.as_bytes() {
                    $crate::exec::init_helper_name($name);
                    return
                }
            } else {
                return
            }
            match match args.next() {
            $(
                Some(cmd) if cmd == <$path>::NAME => {
                    <<$path as ExecHelper>::PassParam as PassParamStrategy<$path>>::exec(args)
                }
            )*
                Some(cmd) => {
                    Err(std::io::Error::other(format!("unknwon command {}", cmd.display())))
                }
                None => {
                    Err(std::io::Error::other("no command"))
                }
            } {
                Ok(()) => std::process::exit(0),
                Err(err) => {
                    eprintln!("helper: {}", err);
                    std::process::exit(127);
                }
            }
        }
    };
    (fn $fn:ident $name:literal [ $($path:path),* $(,)? ]) => {
        $crate::helper!(pub(crate) $fn $name [ $($path),* ]);
    }
}

static HELPER_NAME: OnceLock<CString> = OnceLock::new();

pub fn init_helper_name(name: &str) {
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
        spawn_helper(H::NAME, args, H::UNSHARE).map(|s| Helper(s))
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
                    io::Error::other(format!("helper: invalid fd param: {}", err.display()))
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
