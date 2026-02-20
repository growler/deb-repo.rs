use {
    crate::{
        builder::{BuildJob, Executor},
        exec::{setup_root, spawn_helper, unshare_root, unshare_user_ns, HelperStatus},
        staging::HostFileSystem,
    },
    rustix::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        fs::{openat, Mode, OFlags, CWD},
        io::{fcntl_getfd, fcntl_setfd, FdFlags},
        mount::{move_mount, open_tree, MoveMountFlags, OpenTreeFlags},
        path::Arg,
        pipe::{self},
        process::geteuid,
    },
    serde::{Deserialize, Serialize},
    std::{
        ffi::{OsStr, OsString},
        io::{self, Read, Write},
        iter::once,
        os::unix::fs::OpenOptionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
    },
};

#[derive(Serialize, Deserialize)]
pub struct HostSandboxExecutor {
    root: PathBuf,
    env: Vec<(OsString, OsString)>,
}

impl HostSandboxExecutor {
    pub fn new<P: AsRef<Path>>(root: P) -> io::Result<Self> {
        if !geteuid().is_root() {
            unshare_user_ns(std::iter::empty::<&str>())?;
        }
        Ok(Self {
            root: root.as_ref().to_path_buf(),
            env: Vec::new(),
        })
    }
}

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
    fn write_file<P: AsRef<Path>, C: AsRef<str>>(
        &self,
        path: P,
        mode: u32,
        content: C,
    ) -> io::Result<()> {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(mode)
            .open(path.as_ref())
            .and_then(|mut f| f.write_all(content.as_ref().as_bytes()))
    }
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        std::fs::remove_file(path.as_ref())
    }
    fn exec_cmd<I, A, C>(&self, cmd: C, args: I) -> io::Result<()>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
        C: AsRef<OsStr>,
    {
        Command::new(cmd)
            .stdout(Stdio::inherit())
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .args(args)
            .status()?
            .success()
            .then_some(())
            .ok_or_else(|| io::Error::other("command failed"))
    }
    fn exec_script<S>(&self, script: S) -> io::Result<()>
    where
        S: AsRef<str> + Send + 'static,
    {
        let mut child = Command::new("/bin/sh")
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .arg("-s")
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("failed to open stdin"))?;
        std::thread::spawn(move || {
            let _ = stdin.write_all(script.as_ref().as_bytes());
        });
        child
            .wait()?
            .success()
            .then_some(())
            .ok_or_else(|| io::Error::other("script failed"))
    }
}

impl SandboxExecutor for HostSandboxExecutor {
    fn spawn<E>(&mut self, job: BuildJob<Self>, spawner: E) -> io::Result<OwnedFd>
    where
        E: FnOnce(&Self, BuildJob<Self>) -> io::Result<OwnedFd>,
    {
        spawner(self, job)
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
impl<E, J> OutJob<'_, E, J>
where
    E: Serialize,
    J: Serialize,
{
    fn write_to(&self, mut w: std::fs::File) -> io::Result<()> {
        let doc = toml_edit::ser::to_vec(&self).map_err(|err| {
            io::Error::other(format!(
                "failed to encode parameters to helper process: {}",
                err
            ))
        })?;
        w.write_all(&doc).map_err(|err| {
            io::Error::other(format!(
                "failed to send parameters to helper process: {}",
                err
            ))
        })?;
        Ok(())
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
        let mut doc = Vec::new();
        r.read_to_end(&mut doc).map_err(|err| {
            io::Error::other(format!(
                "failed to read parameters from calling process: {}",
                err
            ))
        })?;
        toml_edit::de::from_slice(&doc).map_err(|err| {
            io::Error::other(format!(
                "failed to decode parameters from calling process: {}",
                err
            ))
        })
    }
}

impl<E: SandboxExecutor> Executor for Sandbox<'_, E> {
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
    fn exec_script<S>(&self, _script: S) -> io::Result<()>
    where
        S: AsRef<str>,
    {
        unimplemented!()
    }
    fn write_file<P: AsRef<Path>, C: AsRef<str>>(
        &self,
        _path: P,
        _mode: u32,
        _content: C,
    ) -> io::Result<()> {
        unimplemented!()
    }
    fn remove_file<P: AsRef<Path>>(&self, _path: P) -> io::Result<()> {
        unimplemented!()
    }
    async fn execute(&mut self, job: BuildJob<Self>) -> io::Result<()>
    where
        Self: Sized,
    {
        let pid = self.runner.spawn(job.with_executor::<E>(), |runner, job| {
            let (rfd, wfd) = pipe::pipe()?;
            set_cloexec(&wfd, true)?;
            let pid_fd = spawn_helper("runner", once(rfd.as_raw_fd().to_string()), true)?;
            drop(rfd);
            let wr: std::fs::File = wfd.into();
            OutJob {
                executor: runner,
                job: &job,
            }
            .write_to(wr)?;
            Ok(pid_fd)
        })?;
        HelperStatus::from(pid).status().await.and_then(|status| {
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

pub fn run_sandbox<E: SandboxExecutor>(mut args: std::env::ArgsOs) -> io::Result<()> {
    let rd: std::fs::File = args.fd_arg().map(Into::into)?;
    unshare_root()?;
    let mut job = InJob::<E, BuildJob<E>>::read_from(rd)?;
    let root_dfd = job.executor.setup_rootfs()?;
    setup_root(&root_dfd)?;
    let (job, mut executor) = (job.job, job.executor);
    job.run(&mut executor)
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
