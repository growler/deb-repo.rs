use {
    crate::{manifest::Manifest, DeploymentFileSystem, TransportProvider},
    futures::stream::{self, TryStreamExt},
    futures_lite::io::AsyncWriteExt,
    iterator_ext::IteratorExt,
    smol::io,
    std::sync::Arc,
};

pub struct Builder<FS: DeploymentFileSystem> {
    fs: Arc<FS>,
}

impl<FS: DeploymentFileSystem + Send + Sync + 'static> Builder<FS> {
    pub fn new(fs: &std::sync::Arc<FS>) -> Self {
        Self { fs: Arc::clone(fs) }
    }
    pub async fn extract_recipe(
        &self,
        manifest: &Manifest,
        recipe: Option<&str>,
        limit: usize,
        transport: &dyn TransportProvider,
    ) -> io::Result<Vec<String>> {
        let mut installed = stream::iter(manifest.installables(recipe.unwrap_or(""))?)
            .map_ok(|(source, path, size, hash)| async move {
                let deb = source.deb_reader(path, size, hash, transport).await?;
                tracing::trace!("Extracting package {}", path);
                let fs = Arc::clone(&self.fs);
                let mut ctrl = blocking::unblock(move || {
                    smol::block_on(async { deb.extract_to(fs.as_ref()).await })
                })
                .await?;
                ctrl.set("Status", "install ok unpacked");
                ctrl.sort_fields_deb_order();
                Ok::<_, io::Error>(ctrl)
            })
            .try_buffer_unordered(limit)
            .try_collect::<Vec<_>>()
            .await?;
        let essentials = installed
            .iter()
            .map(|ctrl| {
                let name = ctrl.field("Package").ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Package field missing in control file",
                    )
                })?;
                let essential = ctrl
                    .field("Essential")
                    .map(|v| v.eq_ignore_ascii_case("yes"))
                    .unwrap_or(false);
                Ok((name, essential))
            })
            .try_filter_map(|(name, essential)| {
                if essential {
                    Ok(Some(name.to_string()))
                } else {
                    Ok(None)
                }
            })
            .collect::<io::Result<Vec<_>>>()?;
        installed.sort_by(|a, b| a.field("Package").unwrap().cmp(b.field("Package").unwrap()));
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
            let size = installed.iter().map(|i| i.len() + 1).sum();
            let mut status = Vec::<u8>::with_capacity(size);
            for i in installed.into_iter() {
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
