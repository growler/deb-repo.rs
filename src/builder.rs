use {
    crate::staging::StagingFileSystem,
    serde::{Deserialize, Serialize},
    smol::io,
    std::{ffi::OsStr, future::Future, path::Path},
};

#[derive(Serialize, Deserialize)]
pub struct BuildJob<E: Executor> {
    essentials: Vec<String>,
    packages: Vec<Vec<String>>,
    scripts: Vec<String>,
    #[serde(skip)]
    _marker: std::marker::PhantomData<E>,
}

impl<E: Executor> BuildJob<E> {
    pub(crate) fn new(
        essentials: Vec<String>,
        packages: Vec<Vec<String>>,
        scripts: Vec<String>,
    ) -> Self {
        Self {
            essentials,
            packages,
            scripts,
            _marker: std::marker::PhantomData,
        }
    }
    pub(crate) fn with_executor<O: Executor>(self) -> BuildJob<O> {
        BuildJob::<O> {
            essentials: self.essentials,
            packages: self.packages,
            scripts: self.scripts,
            _marker: std::marker::PhantomData,
        }
    }
    pub(crate) fn run(&self, mut executor: E) -> io::Result<()> {
        executor.envs([
            ("DEBIAN_FRONTEND", "noninteractive"),
            ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
        ])?;
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
    ) -> impl Future<Output = io::Result<()>>
    where
        Self: Sized,
    {
        async move {
            self.prepare_tree(fs).await?;
            self.execute(BuildJob::<Self>::new(essentials, packages, scripts))
                .await?;
            self.process_changes(fs).await
        }
    }
}
