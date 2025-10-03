use {
    crate::{
        control::{ControlFile, ControlStanza, MutableControlStanza},
        deployfs::DeploymentFileSystem,
        source::RepositoryFile,
        DeploymentFile, Source, TransportProvider,
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    futures_lite::io::AsyncWriteExt,
    serde::{Deserialize, Serialize},
    smol::io,
    std::{ffi::OsStr, num::NonZero},
};

#[derive(Serialize, Deserialize)]
pub struct BuildJob<E: Executor> {
    essentials: Vec<String>,
    _marker: std::marker::PhantomData<E>,
}

impl<E: Executor> BuildJob<E> {
    pub(crate) fn new(essentials: Vec<String>) -> Self {
        Self {
            essentials,
            _marker: std::marker::PhantomData,
        }
    }
    pub(crate) fn with_executor<O: Executor>(self) -> BuildJob<O> {
        BuildJob::<O> {
            essentials: self.essentials,
            _marker: std::marker::PhantomData,
        }
    }
    pub(crate) fn run(&self, mut executor: E) -> io::Result<()> {
        executor.envs([
            ("DEBIAN_FRONTEND", "noninteractive"),
            ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
        ])?;
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
        // executor.exec_cmd("/bin/sh", ["-c", "sleep 3600"])?;
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
                    .iter()
                    .chain(essential_pkgs.iter())
                    .map(|s| *s),
            )?;
        }
        executor.exec_cmd("/usr/bin/dpkg", ["--configure", "-a"])?;
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
pub trait Executor {
    type Filesystem: DeploymentFileSystem + ?Sized;
    async fn prepare_tree(&mut self, _fs: &Self::Filesystem) -> io::Result<()> {
        Ok(())
    }
    async fn process_changes(&mut self, _fs: &Self::Filesystem) -> io::Result<()> {
        Ok(())
    }
    async fn execute(&mut self, job: BuildJob<Self>) -> io::Result<()>
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
}

pub(crate) async fn build<'a, E, I, T>(
    installed: Option<&ControlFile<'_>>,
    packages: I,
    concurrency: NonZero<usize>,
    transport: &T,
    fs: &E::Filesystem,
    mut executor: E,
) -> io::Result<()>
where
    E: Executor,
    I: IntoIterator<Item = (&'a Source, &'a RepositoryFile)> + 'a,
    T: TransportProvider + ?Sized,
{
    let essentials = stage_debs(installed, packages, concurrency, transport, fs).await?;
    fs.create_file(
        b"#!/bin/sh\nexit 101\n".as_slice(),
        "./usr/sbin/policy-rc.d",
        0,
        0,
        0o755,
        None,
        None,
    )
    .await?
    .persist()
    .await?;
    executor.prepare_tree(fs).await?;
    executor.execute(BuildJob::<E>::new(essentials)).await?;
    executor.process_changes(fs).await?;
    fs.remove_file("./usr/sbin/policy-rc.d").await
}

async fn stage_debs<'a, FS, I, T>(
    installed: Option<&ControlFile<'_>>,
    packages: I,
    concurrency: NonZero<usize>,
    transport: &T,
    fs: &FS,
) -> io::Result<Vec<String>>
where
    FS: DeploymentFileSystem + ?Sized,
    I: IntoIterator<Item = (&'a Source, &'a RepositoryFile)> + 'a,
    T: TransportProvider + ?Sized,
{
    let (new_installed, essentials) =
        stream::iter(packages.into_iter().map(|(source, file)| async move {
            let mut ctrl = fs.import_deb(source, transport, file).await?;
            let mut essential = ctrl
                .field("Essential")
                .map(|v| v.eq_ignore_ascii_case("yes"))
                .unwrap_or(false);
            let mut control_files = ctrl.field("Controlfiles").unwrap_or("").split_whitespace();
            if control_files.all(|s| s == "./md5sums" || s == "./conffiles") {
                ctrl.set("Status", "install ok installed");
                essential = false;
            } else {
                ctrl.set("Status", "install ok unpacked");
            }
            ctrl.sort_fields_deb_order();
            Ok::<_, io::Error>((ctrl, essential))
        }))
        .buffer_unordered(concurrency.into())
        .try_fold(
            (Vec::<MutableControlStanza>::new(), Vec::<String>::new()),
            |(mut pkgs, mut essentials), (ctrl, essential)| async move {
                if essential {
                    essentials.push(ctrl.field("Package").unwrap().to_string());
                }
                pkgs.push(ctrl);
                Ok((pkgs, essentials))
            },
        )
        .await?;
    enum Installed<'a> {
        Old(&'a ControlStanza<'a>),
        New(&'a MutableControlStanza),
    }
    impl<'a> Installed<'a> {
        fn package(&self) -> &str {
            match self {
                Installed::Old(s) => s.field("Package").unwrap(),
                Installed::New(s) => s.field("Package").unwrap(),
            }
        }
        fn len(&self) -> usize {
            match self {
                Installed::Old(s) => s.len(),
                Installed::New(s) => s.len(),
            }
        }
    }
    impl std::fmt::Display for Installed<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Installed::Old(s) => write!(f, "{}", s),
                Installed::New(s) => write!(f, "{}", s),
            }
        }
    }
    let mut all_installed = installed
        .iter()
        .flat_map(|i| i.stanzas().map(Installed::Old))
        .chain(new_installed.iter().map(Installed::New))
        .collect::<Vec<_>>();
    all_installed.sort_by(|a, b| a.package().cmp(b.package()));
    fs.create_dir_all("./var/lib/dpkg", 0, 0, 0o755u32).await?;
    {
        let size = all_installed.iter().map(|i| i.len() + 1).sum();
        let mut status = Vec::<u8>::with_capacity(size);
        for i in all_installed.into_iter() {
            status.write_all(format!("{}", &i).as_bytes()).await?;
            status.write_all(b"\n").await?;
        }
        fs.create_file(
            status.as_slice(),
            "./var/lib/dpkg/status",
            0,
            0,
            0o644,
            None,
            Some(size),
        )
        .await?
        .persist()
        .await?;
    }
    Ok(essentials)
}
