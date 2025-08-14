use {
    nix::{
        mount::{mount, MsFlags},
        sched::{unshare, CloneFlags},
        sys::wait::{waitpid, WaitStatus},
        unistd::{fork, pipe, read, ForkResult, Gid, Pid, Uid},
    },
    std::{
        fmt, io,
        os::{fd::AsFd, unix::process::CommandExt},
    },
};

pub(crate) type Result<T> = std::result::Result<T, ExecError>;

pub(crate) struct ExecError {
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
        if self.context.len() > 0 {
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

pub(crate) fn unshare_root() -> Result<()> {
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

pub(crate) fn unshare_user_ns() -> io::Result<()> {
    let uid = Uid::effective();
    let gid = Gid::effective();
    let user = nix::unistd::User::from_uid(uid)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("user record not found for uid {}", uid),
        )
    })?;
    let subuid = SubIdEntry::read_entries("/etc/subuid")?
        .find(|item| match item {
            Ok(item) => item.name == user.name,
            _ => true,
        })
        .unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("/etc/subuid entry not found for user {}", &user.name),
            ))
        })?;
    let subgid = SubIdEntry::read_entries("/etc/subgid")?
        .find(|item| match item {
            Ok(item) => item.name == user.name,
            _ => true,
        })
        .unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::Other,
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
            _ = std::process::exit(1); // unreachable
        }
        ForkResult::Parent { child } => {
            drop(read_fd);
            unshare(CloneFlags::CLONE_NEWUSER)?;
            drop(write_fd);
            match waitpid(child, None)? {
                WaitStatus::Exited(_, code) if code == 0 => Ok(()),
                WaitStatus::Exited(_, code) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to set uid/gid map (code {})", code),
                )),
                status => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to set uid/gid map ({:?})", status),
                )),
            }
        }
    }
}
