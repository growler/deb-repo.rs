use {
    crate::exec::{Argv, ExecHelper, WithArgs},
    rustix::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        fs::{Gid, Uid},
        io::{fcntl_getfd, fcntl_setfd, read, write, FdFlags},
        pipe,
        process::{getegid, geteuid, getpid},
        thread::{unshare_unsafe, UnshareFlags},
    },
    std::{ffi::CStr, io, iter::once, mem, process::Command, ptr},
};

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

    let mut pwd: libc::passwd = unsafe { mem::zeroed() };
    let mut result: *mut libc::passwd = ptr::null_mut();
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
