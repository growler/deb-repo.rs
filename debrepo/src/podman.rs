use {
    crate::{BuildJob, Executor, HostFileSystem},
    serde::{Deserialize, Serialize},
    std::{
        ffi::{OsStr, OsString},
        io::{self, Write},
        os::unix::fs::OpenOptionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
    },
};

#[derive(Serialize, Deserialize)]
/// Sandbox executor backed by Podman.
pub struct PodmanSandboxExecutor {
    root: PathBuf,
    env: Vec<(OsString, OsString)>,
}

impl PodmanSandboxExecutor {
    pub fn new<P: AsRef<Path>>(root: P) -> io::Result<Self> {
        std::fs::create_dir_all(&root).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "failed to create root directory {}: {}",
                    root.as_ref().display(),
                    e
                ),
            )
        })?;
        let root = std::fs::canonicalize(root.as_ref()).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "failed to canonicalize root path {}: {}",
                    root.as_ref().display(),
                    e
                ),
            )
        })?;
        Ok(Self { root, env: vec![] })
    }
}

impl Executor for PodmanSandboxExecutor {
    type Filesystem = HostFileSystem;
    async fn execute(&mut self, job: BuildJob<Self>) -> io::Result<()> {
        job.run(self)
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
        let path = self.root.join(path);
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(mode)
            .open(path)
            .and_then(|mut f| f.write_all(content.as_ref().as_bytes()))
    }
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path = self.root.join(path);
        std::fs::remove_file(path)
    }
    fn exec_cmd<I, A, C>(&self, cmd: C, args: I) -> io::Result<()>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
        C: AsRef<OsStr>,
    {
        let args = args
            .into_iter()
            .map(|a| a.as_ref().to_os_string())
            .collect::<Vec<_>>();
        let env = self
            .env
            .iter()
            .map(|(name, value)| {
                let mut item = name.clone();
                item.push("=");
                item.push(value);
                item
            })
            .collect::<Vec<_>>();
        Command::new("podman")
            .stdout(Stdio::inherit())
            .args(
                std::iter::once(OsStr::new("run"))
                    .chain(
                        env.iter()
                            .flat_map(|val| [OsStr::new("--env"), val.as_os_str()]),
                    )
                    .chain(["--rm", "--net", "none", "--rootfs"].iter().map(OsStr::new))
                    .chain(std::iter::once(self.root.as_os_str()))
                    .chain(std::iter::once(cmd.as_ref()))
                    .chain(args.iter().map(|s| s.as_ref())),
            )
            .status()?
            .success()
            .then_some(())
            .ok_or_else(|| io::Error::other("command failed"))
    }
    fn exec_script<S>(&self, script: S) -> io::Result<()>
    where
        S: AsRef<str> + Send + 'static,
    {
        let env = self
            .env
            .iter()
            .map(|(name, value)| {
                let mut item = name.clone();
                item.push("=");
                item.push(value);
                item
            })
            .collect::<Vec<_>>();
        let mut child = Command::new("podman")
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .args(
                std::iter::once(OsStr::new("run"))
                    .chain(env.iter().flat_map(|val| [OsStr::new("--env"), val]))
                    .chain(
                        ["-i", "--rm", "--net", "none", "--rootfs"]
                            .iter()
                            .map(OsStr::new),
                    )
                    .chain(std::iter::once(self.root.as_os_str()))
                    .chain(["/bin/sh", "-s"].iter().map(OsStr::new)),
            )
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
