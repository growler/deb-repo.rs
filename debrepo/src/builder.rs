use {
    crate::{
        podman::PodmanSandboxExecutor, sandbox::HostSandboxExecutor, staging::StagingFileSystem,
        HostFileSystem,
    },
    serde::{Deserialize, Serialize},
    smol::io,
    std::{ffi::OsStr, future::Future, path::Path},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[value(rename_all = "kebab_case")]
pub enum ExecutorKind {
    Podman,
    Sandbox,
}
pub enum BuildExecutor {
    Podman(PodmanSandboxExecutor),
    Sandbox(HostSandboxExecutor),
}
impl ExecutorKind {
    pub fn build_executor(&self, path: &Path) -> io::Result<BuildExecutor> {
        match self {
            ExecutorKind::Podman => Ok(BuildExecutor::Podman(PodmanSandboxExecutor::new(path)?)),
            ExecutorKind::Sandbox => Ok(BuildExecutor::Sandbox(HostSandboxExecutor::new(path)?)),
        }
    }
}
impl BuildExecutor {
    pub async fn build(
        &mut self,
        fs: &HostFileSystem,
        essentials: Vec<String>,
        packages: Vec<Vec<String>>,
        scripts: Vec<String>,
        build_env: Vec<(String, String)>,
    ) -> io::Result<()> {
        match self {
            BuildExecutor::Podman(executor) => {
                executor
                    .build(fs, essentials, packages, scripts, build_env)
                    .await
            }
            BuildExecutor::Sandbox(executor) => {
                executor
                    .build(fs, essentials, packages, scripts, build_env)
                    .await
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
/// Build job definition for repository builds.
pub struct BuildJob<E: Executor> {
    essentials: Vec<String>,
    packages: Vec<Vec<String>>,
    scripts: Vec<String>,
    build_env: Vec<(String, String)>,
    #[serde(skip)]
    _marker: std::marker::PhantomData<E>,
}

impl<E: Executor> BuildJob<E> {
    pub(crate) fn new(
        essentials: Vec<String>,
        packages: Vec<Vec<String>>,
        scripts: Vec<String>,
        build_env: Vec<(String, String)>,
    ) -> Self {
        Self {
            essentials,
            packages,
            scripts,
            build_env,
            _marker: std::marker::PhantomData,
        }
    }
    pub(crate) fn with_executor<O: Executor>(self) -> BuildJob<O> {
        BuildJob::<O> {
            essentials: self.essentials,
            packages: self.packages,
            scripts: self.scripts,
            build_env: self.build_env,
            _marker: std::marker::PhantomData,
        }
    }
    pub(crate) fn run(&self, executor: &mut E) -> io::Result<()> {
        executor.envs([
            ("DEBIAN_FRONTEND", "noninteractive"),
            ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
        ])?;
        if !self.build_env.is_empty() {
            executor.envs(self.build_env.iter().map(|(k, v)| (k.as_str(), v.as_str())))?;
        }
        executor.write_file("./usr/sbin/policy-rc.d", 0o755, "#!/bin/sh\nexit 101\n")?;
        let (base_passwd, base_files, essential_pkgs) = self.essentials.iter().fold(
            (
                false,
                false,
                Vec::<&str>::with_capacity(self.essentials.len()),
            ),
            |(base_passwd, base_files, mut pkgs), pkg| {
                if pkg == "base-files" {
                    (base_passwd, true, pkgs)
                } else if pkg == "base-passwd" {
                    (true, base_files, pkgs)
                } else {
                    pkgs.push(pkg);
                    (base_passwd, base_files, pkgs)
                }
            },
        );
        if base_passwd {
            executor.exec_cmd(
                "/usr/bin/dpkg",
                ["--force-depends", "--configure", "base-passwd"],
            )?;
        }
        if base_files {
            executor.exec_cmd(
                "/usr/bin/dpkg",
                ["--force-depends", "--configure", "base-files"],
            )?;
        }
        if !essential_pkgs.is_empty() {
            executor.exec_cmd(
                "/usr/bin/dpkg",
                ["--force-depends", "--configure"]
                    .into_iter()
                    .chain(essential_pkgs.iter().copied()),
            )?;
        }
        for group in self.packages.iter() {
            executor.exec_cmd(
                "/usr/bin/dpkg",
                std::iter::once("--configure").chain(group.iter().map(String::as_str)),
            )?;
        }
        for script in self.scripts.iter() {
            executor.exec_script(script.clone())?;
        }
        executor.remove_file("./usr/sbin/policy-rc.d")?;
        Ok(())
    }
}

pub trait Executor {
    type Filesystem: StagingFileSystem + ?Sized;
    fn setup(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn prepare_tree(&mut self, _fs: &Self::Filesystem) -> impl Future<Output = io::Result<()>> {
        async { Ok(()) }
    }
    fn process_changes(&mut self, _fs: &Self::Filesystem) -> impl Future<Output = io::Result<()>> {
        async { Ok(()) }
    }
    fn execute(&mut self, job: BuildJob<Self>) -> impl Future<Output = io::Result<()>>
    where
        Self: Sized;
    fn env<K, V>(&mut self, k: K, v: V) -> io::Result<()>
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>;
    fn envs<I, K, V>(&mut self, iter: I) -> io::Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>;
    fn exec_cmd<I, A, C>(&self, cmd: C, args: I) -> io::Result<()>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
        C: AsRef<OsStr>;
    fn exec_script<S>(&self, script: S) -> io::Result<()>
    where
        S: AsRef<str> + Send + 'static;
    fn write_file<P: AsRef<Path>, C: AsRef<str>>(
        &self,
        path: P,
        mode: u32,
        content: C,
    ) -> io::Result<()>;
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()>;
    fn build(
        &mut self,
        fs: &Self::Filesystem,
        essentials: Vec<String>,
        packages: Vec<Vec<String>>,
        scripts: Vec<String>,
        build_env: Vec<(String, String)>,
    ) -> impl Future<Output = io::Result<()>>
    where
        Self: Sized,
    {
        async move {
            self.prepare_tree(fs).await?;
            self.execute(BuildJob::<Self>::new(
                essentials, packages, scripts, build_env,
            ))
            .await?;
            self.process_changes(fs).await
        }
    }
}
