use {
    crate::{
        control::MutableControlStanza,
        deployfs::{DeploymentFileSystem, DeploymentRoot},
        exec::{ExecHelper, HelperExitStatus, WithSerde},
        manifest::Manifest,
        source::RepositoryFile,
        Source, TransportProvider,
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    futures_lite::io::AsyncWriteExt,
    rustix::{
        fd::{AsFd, OwnedFd},
        fs::{mkdirat, openat, symlinkat, Mode, OFlags, CWD},
        io::Errno,
        mount::{
            fsconfig_create, fsconfig_set_string, fsmount, fsopen, mount_change, move_mount,
            open_tree, unmount, FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags,
            MoveMountFlags, OpenTreeFlags, UnmountFlags,
        },
        path::Arg,
        process::{fchdir, pivot_root},
    },
    serde::{Deserialize, Serialize},
    smol::io,
    std::{num::NonZero, os::unix::fs::OpenOptionsExt, path::PathBuf, process::Command},
};

#[async_trait::async_trait(?Send)]
pub trait Builder<FS: DeploymentFileSystem> {
    async fn merge_deb_content<'a, T>(
        &self,
        source: &'a Source,
        transport: &T,
        package: &'a RepositoryFile,
        fs: &FS,
    ) -> io::Result<MutableControlStanza>
    where
        T: TransportProvider + ?Sized;
    async fn build_tree<'a, I, T>(
        &self,
        packages: I,
        concurrency: NonZero<usize>,
        transport: &T,
        fs: &FS,
    ) -> io::Result<Vec<String>>
    where
        I: IntoIterator<Item = (&'a Source, &'a RepositoryFile)> + 'a,
        T: TransportProvider + ?Sized,
    {
        let mut installed = stream::iter(packages.into_iter().map(|(source, file)| async move {
            let mut ctrl = self.merge_deb_content(source, transport, file, fs).await?;
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
        .try_collect::<Vec<_>>()
        .await?;
        let essentials = installed
            .iter()
            .filter_map(|(ctrl, essential)| {
                essential.then_some(ctrl.field("Package").unwrap().to_string())
            })
            .collect::<Vec<_>>();
        installed
            .sort_by(|(a, _), (b, _)| a.field("Package").unwrap().cmp(b.field("Package").unwrap()));
        fs.create_dir_all("./etc/apt", 0, 0, 0o755u32).await?;
        {
            // self.fs.create_file(
            //     sources.as_slice(),
            //     Some("etc/apt/sources.list"),
            //     0,
            //     0,
            //     0o644,
            //     None,
            //     Some(sources.len()),
            // )
            // .await?;
        }
        fs.create_dir_all("./var/lib/dpkg", 0, 0, 0o755u32).await?;
        {
            let size = installed.iter().map(|(i, _)| i.len() + 1).sum();
            let mut status = Vec::<u8>::with_capacity(size);
            for (i, _) in installed.into_iter() {
                status.write_all(format!("{}", &i).as_bytes()).await?;
                status.write_all(b"\n").await?;
            }
            fs.create_file(
                status.as_slice(),
                Some("./var/lib/dpkg/status"),
                0,
                0,
                0o644,
                None,
                Some(size),
            )
            .await?;
        }
        Ok(essentials)
    }
    async fn build<T, S>(
        &self,
        manifest: &Manifest,
        spec: &Option<S>,
        concurrency: NonZero<usize>,
        transport: &T,
        fs: &FS,
    ) -> io::Result<()>
    where
        T: TransportProvider + ?Sized,
        S: AsRef<str>,
    {
        let installables = manifest
            .installables(spec)?
            .collect::<io::Result<Vec<_>>>()?;
        let essentials = self
            .build_tree(installables, concurrency, transport, fs)
            .await?;
        let root = fs.root().await?.path()?.to_path_buf();
        let runner = BuildRunner::new(root, essentials.clone());
        if !runner.run().await?.is_success() {
            Err(io::Error::other("failed to build tree"))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<FS> Builder<FS> for SimpleBuilder<FS>
where
    FS: DeploymentFileSystem + Clone + Send + Sync + 'static,
{
    async fn merge_deb_content<'a, T>(
        &self,
        source: &'a Source,
        transport: &T,
        package: &'a RepositoryFile,
        fs: &FS,
    ) -> io::Result<MutableControlStanza>
    where
        T: TransportProvider + ?Sized,
    {
        let deb = source
            .deb_reader(&package.path, package.size, &package.hash, transport)
            .await?;
        let fs = fs.clone();
        let ctrl =
            blocking::unblock(move || smol::block_on(async { deb.extract_to(&fs).await })).await?;
        Ok(ctrl)
    }
}

pub struct SimpleBuilder<FS: DeploymentFileSystem> {
    _phantom: std::marker::PhantomData<FS>,
}

impl<FS: DeploymentFileSystem + Clone + Send + Sync + 'static> SimpleBuilder<FS> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BuildRunner {
    root: PathBuf,
    essentials: Vec<String>,
}

impl BuildRunner {
    pub fn new(root: PathBuf, essentials: impl IntoIterator<Item = String>) -> Self {
        Self {
            root,
            essentials: essentials.into_iter().collect(),
        }
    }
    pub async fn run(&self) -> io::Result<HelperExitStatus> {
        self.spawn()?.status().await
    }
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

impl ExecHelper for BuildRunner {
    const NAME: &'static str = "builder";
    const UNSHARE: bool = true;
    type PassParam = WithSerde;
    fn exec(mut self) -> std::io::Result<()> {
        use std::io::Write;
        let root_dfd = openat(
            CWD,
            &self.root,
            OFlags::DIRECTORY | OFlags::RDONLY,
            Mode::empty(),
        )?;
        mkdirat_if_not_exist(&root_dfd, "dev", Mode::from_raw_mode(0o755))?;
        mkdirat_if_not_exist(&root_dfd, "proc", Mode::from_raw_mode(0o755))?;
        mkdirat_if_not_exist(&root_dfd, "run", Mode::from_raw_mode(0o755))?;
        make_mountpoint(&root_dfd)?;
        let root_dfd = openat(
            CWD,
            &self.root,
            OFlags::DIRECTORY | OFlags::RDONLY,
            Mode::empty(),
        )?;
        mount_dev(&root_dfd)?;
        mount_pts(&root_dfd)?;
        mount_proc(&root_dfd)?;
        mount_run(&root_dfd)?;
        fchdir(&root_dfd)?;
        pivot_root(".", ".")?;
        unmount(".", UnmountFlags::DETACH)?;
        let env = [
            ("DEBIAN_FRONTEND", "noninteractive"),
            ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
        ];
        self.essentials
            .retain(|s| s != "base-files" && s != "base-passwd");
        let mut f = std::fs::OpenOptions::new()
            .mode(0o755)
            .create(true)
            .write(true)
            .open("usr/sbin/policy-rc.d")?;
        f.write_all(b"#!/bin/sh\nexit 101\n")?;
        f.flush()?;
        drop(f);
        Command::new("/usr/bin/dpkg")
            .env_clear()
            .envs(env)
            .args(["--force-depends", "--configure", "base-passwd"])
            .status()?;
        Command::new("/usr/bin/dpkg")
            .env_clear()
            .envs(env)
            .args(["--force-depends", "--configure", "base-files"])
            .status()?;
        Command::new("/usr/bin/dpkg")
            .env_clear()
            .envs(env)
            .args(
                ["--force-depends", "--configure"]
                    .iter()
                    .map(|s| *s)
                    .chain(self.essentials.iter().map(|s| s.as_str())),
            )
            .status()?;
        Command::new("/usr/bin/dpkg")
            .env_clear()
            .envs(env)
            .args(["--configure", "-a"])
            .status()?;
        std::fs::remove_file("usr/sbin/policy-rc.d")?;
        Ok(())
    }
}
pub fn unshare_root() -> io::Result<()> {
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(Into::into)
}
fn make_mountpoint(dfd: &OwnedFd) -> io::Result<()> {
    let mfd = open_tree(
        dfd,
        "",
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::AT_EMPTY_PATH,
    )?;
    move_mount(
        &mfd,
        "",
        dfd,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )?;
    Ok(())
}
fn mount_dev(dfd: &OwnedFd) -> io::Result<()> {
    let fsfd = fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_set_string(&fsfd, "size", "1024M")?;
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
        dfd,
        "dev",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    let dev_fd = openat(
        dfd,
        "dev",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    mkdirat(&dev_fd, "pts", Mode::from_raw_mode(0o755))?;
    Ok(())
}
fn mount_pts(dfd: &OwnedFd) -> io::Result<()> {
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
    let dev_dfd = openat(
        dfd,
        "dev",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    move_mount(
        mountfd,
        "",
        &dev_dfd,
        "pts",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    symlinkat("pts/ptmx", &dev_dfd, "ptmx")?;
    Ok(())
}
fn mount_proc(dfd: &OwnedFd) -> io::Result<()> {
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
        dfd,
        "proc",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}
fn mount_run(dfd: &OwnedFd) -> io::Result<()> {
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
        dfd,
        "run",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    let run_fd = openat(
        dfd,
        "run",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    mkdirat(&run_fd, "lock", Mode::from_raw_mode(0o1777))?;
    Ok(())
}
