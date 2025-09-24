use {
    crate::{
        deployfs::{DeploymentFileSystem, DeploymentRoot},
        exec::{dpkg, exec, Command},
        manifest::Manifest,
        TransportProvider,
    },
    futures::stream::{self, TryStreamExt},
    futures_lite::io::AsyncWriteExt,
    iterator_ext::IteratorExt,
    smol::io,
    std::{num::NonZero, sync::Arc},
};

pub struct Builder<FS: DeploymentFileSystem> {
    fs: Arc<FS>,
}

impl<FS: DeploymentFileSystem + Send + Sync + 'static> Builder<FS> {
    pub fn new(fs: &std::sync::Arc<FS>) -> Self {
        Self { fs: Arc::clone(fs) }
    }
    pub async fn build<T: TransportProvider + ?Sized>(
        &self,
        manifest: &Manifest,
        recipe: Option<&str>,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<()> {
        let mut essentials = self
            .extract_recipe(manifest, recipe, concurrency, transport)
            .await?;
        println!("Configuring essential packages: {:?}", essentials);
        let env = ["DEBIAN_FRONTEND=noninteractive"];
        let root = self.fs.root().await?;
        essentials.retain(|s| s != "base-files" && s != "base-passwd");
        exec(
            root.path()?,
            &[
                dpkg(["--force-depends", "--configure", "base-passwd"], &env)?,
                dpkg(["--force-depends", "--configure", "base-files"], &env)?,
                dpkg(
                    ["--force-depends", "--configure"]
                        .iter()
                        .map(|s| *s)
                        .chain(essentials.iter().map(|s| s.as_str())),
                    &env,
                )?,
                dpkg(["--configure", "-a"], &env)?,
            ],
        )?;
        self.fs.remove_file("usr/sbin/policy-rc.d").await?;
        Ok(())
    }
    pub async fn extract_recipe<T: TransportProvider + ?Sized>(
        &self,
        manifest: &Manifest,
        recipe: Option<&str>,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<Vec<String>> {
        let mut installed = stream::iter(manifest.installables(recipe)?)
            .map_ok(|(source, path, size, hash)| async move {
                let deb = source.deb_reader(path, size, hash, transport).await?;
                tracing::trace!("Extracting package {}", path);
                let fs = Arc::clone(&self.fs);
                let mut ctrl = blocking::unblock(move || {
                    smol::block_on(async { deb.extract_to(fs.as_ref()).await })
                })
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
            })
            .try_buffer_unordered(concurrency.into())
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
        self.fs.create_dir_all("./etc/apt", 0, 0, 0o755u32).await?;
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
        self.fs
            .create_dir_all("./var/lib/dpkg", 0, 0, 0o755u32)
            .await?;
        {
            let size = installed.iter().map(|(i, _)| i.len() + 1).sum();
            let mut status = Vec::<u8>::with_capacity(size);
            for (i, _) in installed.into_iter() {
                status.write_all(format!("{}", &i).as_bytes()).await?;
                status.write_all(b"\n").await?;
            }
            self.fs
                .create_file(
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
        self.fs.create_dir_all("./usr/sbin", 0, 0, 0o755u32).await?;
        self.fs
            .create_file(
                b"#!/bin/sh\nexit 101\n".as_slice(),
                Some("usr/sbin/policy-rc.d"),
                0,
                0,
                0o755,
                None,
                None,
            )
            .await?;

        Ok(essentials)
    }
}
