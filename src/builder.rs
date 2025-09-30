use {
    crate::{
        control::MutableControlStanza,
        deployfs::DeploymentFileSystem,
        helper::{ExecHelper, HelperExitStatus, UnshareUserNs, WithSerde},
        manifest::Manifest,
        source::RepositoryFile,
        HostFileSystem, Source, TransportProvider,
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
pub trait UnpackStrategy<FS: DeploymentFileSystem + ?Sized> {
    async fn unpack_deb<T>(
        source: &Source,
        transport: &T,
        package: &RepositoryFile,
        fs: &FS,
    ) -> io::Result<MutableControlStanza>
    where
        T: TransportProvider + ?Sized;
}

pub struct MulitThreaded;

#[async_trait::async_trait(?Send)]
impl<FS> UnpackStrategy<FS> for MulitThreaded
where
    FS: DeploymentFileSystem + Send + Sync + Clone + 'static,
{
    async fn unpack_deb<T>(
        source: &Source,
        transport: &T,
        package: &RepositoryFile,
        fs: &FS,
    ) -> io::Result<MutableControlStanza>
    where
        T: TransportProvider + Send + Sync + ?Sized,
    {
        let deb = source
            .deb_reader(&package.path, package.size, &package.hash, transport)
            .await?;
        let fs = fs.clone();
        blocking::unblock(move || smol::block_on(deb.extract_to(&fs))).await
    }
}

pub struct SingleThreaded;

#[async_trait::async_trait(?Send)]
impl<FS> UnpackStrategy<FS> for SingleThreaded
where
    FS: DeploymentFileSystem + ?Sized,
{
    async fn unpack_deb<T>(
        source: &Source,
        transport: &T,
        package: &RepositoryFile,
        fs: &FS,
    ) -> io::Result<MutableControlStanza>
    where
        T: TransportProvider + ?Sized,
    {
        let deb = source
            .deb_reader(&package.path, package.size, &package.hash, transport)
            .await?;
        deb.extract_to(fs).await
    }
}

pub trait Mounter: Serialize + for<'de> Deserialize<'de> {
    fn mount_root(&self) -> io::Result<OwnedFd>;
}

#[async_trait::async_trait(?Send)]
pub trait Builder
where
    Self: Sized,
{
    type FileSystem: DeploymentFileSystem + ?Sized;
    type Unpack: UnpackStrategy<Self::FileSystem>;
    type Mounter: Mounter;
    fn mounter(&self, fs: &Self::FileSystem) -> io::Result<Self::Mounter>;
    fn unshare_user_ns() -> Option<io::Result<()>> {
        UnshareUserNs::unshare()
    }
    async fn build<'a, S, T>(
        &self,
        manifest: &Manifest,
        spec: &Option<S>,
        concurrency: NonZero<usize>,
        transport: &T,
        fs: &Self::FileSystem,
    ) -> io::Result<()>
    where
        T: TransportProvider + ?Sized,
        S: AsRef<str>,
    {
        let installables = manifest
            .installables(spec)?
            .collect::<io::Result<Vec<_>>>()?;
        let essentials = self
            .unpack_debs(installables, concurrency, transport, fs)
            .await?;
        let mounter = self.mounter(fs)?;
        let runner = BuildRunner::<Self>::new(essentials, mounter);
        if !runner.run().await?.is_success() {
            Err(io::Error::other("failed to build tree"))
        } else {
            Ok(())
        }
    }
    async fn unpack_debs<'a, I, T>(
        &self,
        packages: I,
        concurrency: NonZero<usize>,
        transport: &T,
        fs: &Self::FileSystem,
    ) -> io::Result<Vec<String>>
    where
        I: IntoIterator<Item = (&'a Source, &'a RepositoryFile)> + 'a,
        T: TransportProvider + ?Sized,
    {
        let mut installed = stream::iter(packages.into_iter().map(|(source, file)| async move {
            let mut ctrl = <Self::Unpack as UnpackStrategy<Self::FileSystem>>::unpack_deb(
                source, transport, file, fs,
            )
            .await?;
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
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BuildRunner<B: Builder> {
    essentials: Vec<String>,
    mounter: B::Mounter,
}

impl<B: Builder> BuildRunner<B> {
    fn new(essentials: Vec<String>, mounter: B::Mounter) -> Self {
        Self {
            essentials,
            mounter,
        }
    }
    async fn run(&self) -> io::Result<HelperExitStatus> {
        self.spawn()?.status().await
    }
}

impl<B> BuildRunner<B>
where
    B: Builder,
{
    fn pivot_root(&self) -> io::Result<()> {
        let root_dfd = self.mounter.mount_root()?;
        fchdir(&root_dfd)?;
        mkdirat_if_not_exist(&root_dfd, "dev", Mode::from_raw_mode(0o755))?;
        mkdirat_if_not_exist(&root_dfd, "proc", Mode::from_raw_mode(0o755))?;
        mkdirat_if_not_exist(&root_dfd, "run", Mode::from_raw_mode(0o755))?;
        mount_dev(&root_dfd)?;
        mount_pts(&root_dfd)?;
        mount_proc(&root_dfd)?;
        mount_run(&root_dfd)?;
        pivot_root(".", ".")?;
        unmount(".", UnmountFlags::DETACH)?;
        Ok(())
    }

    fn configure(&self) -> io::Result<()> {
        use std::io::Write;
        let env = [
            ("DEBIAN_FRONTEND", "noninteractive"),
            ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
        ];
        let mut f = std::fs::OpenOptions::new()
            .mode(0o755)
            .create(true)
            .truncate(true)
            .write(true)
            .open("usr/sbin/policy-rc.d")?;
        f.write_all(b"#!/bin/sh\nexit 101\n")?;
        f.flush()?;
        drop(f);
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
            Command::new("/usr/bin/dpkg")
                .env_clear()
                .envs(env)
                .args(["--force-depends", "--configure", "base-passwd"])
                .status()?
                .success()
                .then_some(())
                .ok_or_else(|| io::Error::other("command failed"))?;
        }
        if base_files {
            Command::new("/usr/bin/dpkg")
                .env_clear()
                .envs(env)
                .args(["--force-depends", "--configure", "base-files"])
                .status()?
                .success()
                .then_some(())
                .ok_or_else(|| io::Error::other("command failed"))?;
        }
        if !essential_pkgs.is_empty() {
            Command::new("/usr/bin/dpkg")
                .env_clear()
                .envs(env)
                .args(
                    ["--force-depends", "--configure"]
                        .iter()
                        .chain(essential_pkgs.iter()),
                )
                .status()?
                .success()
                .then_some(())
                .ok_or_else(|| io::Error::other("command failed"))?;
        }
        Command::new("/usr/bin/dpkg")
            .env_clear()
            .envs(env)
            .args(["--configure", "-a"])
            .status()?
            .success()
            .then_some(())
            .ok_or_else(|| io::Error::other("command failed"))?;
        std::fs::remove_file("usr/sbin/policy-rc.d")?;
        Ok(())
    }
}

impl<B> ExecHelper for BuildRunner<B>
where
    B: Builder,
{
    const NAME: &'static str = "build";
    const UNSHARE: bool = true;
    type PassParam = WithSerde;

    fn exec(self) -> std::io::Result<()> {
        unshare_root()?;
        self.pivot_root()?;
        self.configure()
    }
}

#[derive(Serialize, Deserialize)]
pub struct HostMounter {
    root: PathBuf,
}

impl Mounter for HostMounter {
    fn mount_root(&self) -> io::Result<OwnedFd> {
        let root_dfd = openat(
            CWD,
            &self.root,
            OFlags::DIRECTORY | OFlags::RDONLY,
            Mode::empty(),
        )?;
        make_mountpoint(&root_dfd)?;
        let root_dfd = openat(
            CWD,
            &self.root,
            OFlags::DIRECTORY | OFlags::RDONLY,
            Mode::empty(),
        )?;
        Ok(root_dfd)
    }
}

pub struct HostBuilder {}

impl Builder for HostBuilder {
    type FileSystem = HostFileSystem;
    type Unpack = MulitThreaded;
    type Mounter = HostMounter;
    fn mounter(&self, fs: &Self::FileSystem) -> io::Result<Self::Mounter> {
        Ok(HostMounter {
            root: fs.root().to_owned(),
        })
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
    fsconfig_set_string(&fsfd, "mode", "0755")?;
    fsconfig_create(&fsfd)?;
    let mountfd = fsmount(
        &fsfd,
        FsMountFlags::empty(),
        MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )?;
    move_mount(
        mountfd,
        "",
        dfd,
        "dev",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    let dev_dfd = openat(
        dfd,
        "dev",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    mkdirat(&dev_dfd, "pts", Mode::from_raw_mode(0o755))?;
    static LINKS: [(&str, &str); 6] = [
        ("pts/ptmx", "ptmx"),
        ("pts/0", "console"),
        ("/proc/kcore", "core"),
        ("/proc/self/fd/0", "stdin"),
        ("/proc/self/fd/1", "stdout"),
        ("/proc/self/fd/2", "stderr"),
    ];
    for (target, path) in LINKS {
        symlinkat(target, &dev_dfd, path)?;
    }
    static DEVICES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];
    let host_dfd = openat(
        CWD,
        "/dev",
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    for name in DEVICES {
        let target_fd = openat(
            &dev_dfd,
            name,
            OFlags::CREATE | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::from_raw_mode(0o700),
        )?;
        let mnt_fd = open_tree(&host_dfd, name, OpenTreeFlags::OPEN_TREE_CLONE)?;
        move_mount(
            &mnt_fd,
            "",
            &target_fd,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        )?;
    }
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
    move_mount(
        mountfd,
        "",
        dfd,
        "dev/pts",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
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
