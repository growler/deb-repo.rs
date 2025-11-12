use {
    crate::{
        cache::CacheProvider,
        packages::{InstallPriority, Package},
        repo::TransportProvider,
        source::{SnapshotId, SnapshotIdArgParser, Source},
        version::{Constraint, Dependency, Version},
        StagingFileSystem,
    },
    anyhow::Result,
    std::{io, num::NonZero, path::Path, str::FromStr},
};

pub trait Config {
    type FS: StagingFileSystem;
    type Cache: CacheProvider<Target = Self::FS>;
    type Transport: TransportProvider;
    fn log_level(&self) -> i32 {
        0
    }
    fn arch(&self) -> &str;
    fn manifest(&self) -> &Path;
    fn concurrency(&self) -> NonZero<usize>;
    fn cache(&self) -> &Self::Cache;
    fn transport(&self) -> &Self::Transport;
}

pub trait Command<C> {
    fn exec(&self, conf: &C) -> Result<()>;
}

pub mod cmd {
    use {
        super::*,
        crate::{
            artifact::ArtifactArg, builder::Executor, cache::HostCache, manifest::Manifest,
            sandbox::HostSandboxExecutor, staging::HostFileSystem,
        },
        anyhow::{anyhow, Result},
        clap::Parser,
        indicatif::ProgressBar,
        itertools::Itertools,
        smol::io::AsyncWriteExt,
        std::path::PathBuf,
    };
    #[derive(Parser)]
    #[command(
        about = "Create a new manifest file",
        long_about = "Create a new manifest file from a source definition.
If a vendor name is provided as source URL, default sources and packages are derived from it.
Examples:  
    debrepo init --package mc --package libcom-err2 --url debian"
    )]
    pub struct Init {
        /// Overwrite existing manifest if present
        #[arg(long)]
        pub force: bool,

        /// Package to add (can be used multiple times)
        #[arg(short = 'r', long = "package", value_name = "PACKAGE")]
        requirements: Vec<String>,

        /// Source definition (i.e. --url <URL> ...).
        /// URL might be a vendor name (debian, ubuntu, devuan).
        #[command(flatten)]
        source: Source,
    }

    impl<C: Config> Command<C> for Init {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let (sources, packages, comment) =
                    if let Some((sources, mut packages)) = self.source.as_vendor() {
                        if !self.requirements.is_empty() {
                            packages.extend(self.requirements.iter().cloned());
                            packages = packages.into_iter().unique().collect();
                        }
                        (
                            sources,
                            packages,
                            Some(format!("default manifest file for {}", &self.source.url)),
                        )
                    } else {
                        (vec![self.source.clone()], self.requirements.clone(), None)
                    };
                let mut mf = Manifest::from_sources(
                    conf.arch(),
                    sources.iter().cloned(),
                    comment.as_deref(),
                );
                mf.add_requirements(None, packages.iter(), None)?;
                mf.update(true, conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.resolve(conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.store(conf.manifest()).await?;
                Ok(())
            })
        }
    }
    #[derive(Parser)]
    #[command(
        about = "Remove requirements or constraints from a spec",
        long_about = "Remove requirements and/or constraints from a spec
Use --requirements-only or --constraints-only to limit the operation scope."
    )]
    pub struct Drop {
        /// Drop only requirements (do not touch constraints)
        #[arg(
            short = 'R',
            long = "requirements-only",
            conflicts_with = "constraints_only"
        )]
        requirements_only: bool,

        /// Drop only constraints (do not touch requirements)
        #[arg(
            short = 'C',
            long = "constraints-only",
            conflicts_with = "requirements_only"
        )]
        constraints_only: bool,

        /// The spec name to modify (none for the default spec)
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,

        /// Package name or package version set
        #[arg(value_name = "CONSTRAINT")]
        cons: Vec<String>,
    }
    impl<C: Config> Command<C> for Drop {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                if !self.constraints_only {
                    mf.remove_requirements(self.spec.as_deref(), self.cons.iter())?;
                }
                if !self.requirements_only {
                    mf.remove_constraints(self.spec.as_deref(), self.cons.iter())?;
                }
                conf.cache().init().await?;
                mf.update(false, conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.resolve(conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                conf.cache().close().await?;
                mf.store(conf.manifest()).await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Stage an artifact into a spec",
        long_about = "Add an external artifact (URL or file path) to a spec so it is included into the system tree."
    )]
    pub struct Stage {
        /// Target spec (omit to use the default spec)
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,

        /// A comment for the staged artifact
        #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
        comment: Option<String>,

        #[command(flatten)]
        artifact: ArtifactArg,
    }

    impl<C: Config> Command<C> for Stage {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                mf.add_artifact(
                    self.spec.as_deref(),
                    &self.artifact,
                    self.comment.as_deref(),
                    conf.transport(),
                )
                .await?;
                mf.store(conf.manifest()).await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Remove a staged artifact from a spec",
        long_about = "Remove a previously staged artifact (by URL or file path) from the given spec."
    )]
    pub struct Unstage {
        /// Target spec (omit to use the default spec)
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,
        /// Artifact URL or path
        #[arg(value_name = "URL")]
        url: String,
    }

    impl<C: Config> Command<C> for Unstage {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                mf.remove_artifact(self.spec.as_deref(), &self.url)?;
                mf.store(conf.manifest()).await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Add package requirements to a spec",
        long_about = "Add one or more package requirements to a spec. Each requirement can be a bare name or set, and can include a version relation, e.g.:
  foo
  foo (= 1.2.3)
  bar (>= 2.0)
  foo | bar (<< 3.0)"
    )]
    pub struct Include {
        /// Target spec (omit to use the default spec)
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,
        /// Optional comment to record with this change
        #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
        comment: Option<String>,
        /// Requirement(s) to include (repeatable)
        #[arg(value_name = "REQUIREMENT", value_parser = DependencyParser)]
        reqs: Vec<Dependency<String>>,
    }

    impl<C: Config> Command<C> for Include {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                mf.add_requirements(
                    self.spec.as_deref(),
                    self.reqs.iter(),
                    self.comment.as_deref(),
                )?;
                conf.cache().init().await?;
                mf.update(false, conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.resolve(conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.store(conf.manifest()).await?;
                conf.cache().close().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Add package constraints to a spec",
        long_about = "Add one or more constraints to restrict resolution. Examples:
  foo (= 1.2.3)
  foo (<< 2.0)  
  bar (<= 3.4)"
    )]
    pub struct Exclude {
        /// Target spec (omit to use the default spec)
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,
        /// Optional comment to record with this change
        #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
        comment: Option<String>,
        /// Requirement(s) to include (repeatable)
        #[arg(value_name = "CONSTRAINT", value_parser = ConstraintParser)]
        reqs: Vec<Constraint<String>>,
    }

    impl<C: Config> Command<C> for Exclude {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                mf.add_constraints(
                    self.spec.as_deref(),
                    self.reqs.iter(),
                    self.comment.as_deref(),
                )?;
                conf.cache().init().await?;
                mf.update(false, conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.resolve(conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.store(conf.manifest()).await?;
                conf.cache().close().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Update sources and snapshot/lock state",
        long_about = "Fetch or retrieve from cache package indexes, solve the specs and update lock file. Optionally set a snapshot before updating."
    )]
    pub struct Update {
        /// Re-fetch sources even if they appear up to date. Do not use cache.
        #[arg(short = 'f', long = "force", action)]
        force: bool,
        /// Snapshot to use for all sources that support it and have snapshotting enabled
        #[arg(short = 's', long = "snapshot", value_name = "SNAPSHOT_ID", value_parser = SnapshotIdArgParser)]
        snapshot: Option<SnapshotId>,
    }

    impl<C: Config> Command<C> for Update {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                if let Some(snapshot) = &self.snapshot {
                    mf.set_snapshot(*snapshot).await;
                }
                conf.cache().init().await?;
                mf.update(
                    self.force,
                    conf.concurrency(),
                    conf.transport(),
                    conf.cache(),
                )
                .await?;
                mf.store(conf.manifest()).await?;
                conf.cache().close().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Search packages in sources",
        long_about = "Search for packages matching the given regex pattern(s)."
    )]
    pub struct Search {
        /// Match only package names (ignore descriptions)
        #[arg(short = 'p', long = "names-only")]
        names_only: bool,
        /// Regex pattern(s) to search for (repeatable)
        #[arg(value_name = "PATTERN")]
        pattern: Vec<String>,
    }

    impl<C: Config> Command<C> for Search {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                conf.cache().init().await?;
                mf.update(false, conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.load_universe(conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                conf.cache().close().await?;
                let res = self
                    .pattern
                    .iter()
                    .map(|p| {
                        regex::RegexBuilder::new(p)
                            .unicode(true)
                            .case_insensitive(true)
                            .build()
                            .map_err(|err| anyhow!("invalid regex: {}", err))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let mut pkgs = mf
                    .packages()?
                    .filter(|p| {
                        res.iter().any(|re| {
                            re.is_match(p.name())
                                || (!self.names_only
                                    && re.is_match(p.field("Description").unwrap_or("")))
                        })
                    })
                    .collect::<Vec<_>>();
                pkgs.sort_by_key(|&pkg| pkg.name());
                let mut out = std::io::stdout().lock();
                let mut out = smol::io::BufWriter::new(async_io::Async::new(&mut out)?);
                pretty_print_packages(&mut out, pkgs, false).await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Show a package's control record",
        long_about = "Print the raw control record for the given package."
    )]
    pub struct Show {
        #[arg(value_name = "PACKAGE")]
        package: String,
    }

    impl<C: Config> Command<C> for Show {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                conf.cache().init().await?;
                mf.update(false, conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.load_universe(conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                conf.cache().close().await?;
                let pkg = mf.packages()?.find(|p| self.package == p.name());
                if let Some(pkg) = pkg {
                    let mut out = async_io::Async::new(std::io::stdout().lock())?;
                    out.write_all(pkg.src().as_bytes()).await?;
                    Ok(())
                } else {
                    Err(anyhow!("package {} not found", &self.package))
                }
            })
        }
    }

    #[derive(Parser)]
    #[command(about = "List manifest items", long_about = "List manifest items")]
    pub struct List {
        #[arg(short = 'e', long = "only-essential", hide = true)]
        only_essential: bool,
        //
        #[arg(long = "specs", conflicts_with = "spec", action)]
        list_specs: bool,
        /// List packages for the target spec (omit to use the default spec)
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,
    }

    impl<C: Config> Command<C> for List {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let mut mf = Manifest::from_file(conf.manifest(), conf.arch()).await?;
                conf.cache().init().await?;
                mf.update(false, conf.concurrency(), conf.transport(), conf.cache())
                    .await?;
                mf.resolve(conf.concurrency(), conf.transport(), conf.cache())
                    .await
                    .map_err(|e| anyhow!("failed to update specs: {e}"))?;
                conf.cache().close().await?;
                let mut pkgs = mf
                    .spec_packages(self.spec.as_deref())?
                    .filter(|p| !self.only_essential || p.essential())
                    .collect::<Vec<_>>();
                pkgs.sort_by_key(|&pkg| pkg.name());
                let mut out = std::io::stdout().lock();
                let mut out = smol::io::BufWriter::new(async_io::Async::new(&mut out)?);
                pretty_print_packages(&mut out, pkgs, false).await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Build an installable root for a spec",
        long_about = "Stage required artifacts and build the spec into the target directory."
    )]
    pub struct Build {
        /// The spec name to build
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,
        /// The target directory
        #[arg(short, long, value_name = "PATH")]
        path: PathBuf,
    }

    impl<C: Config<FS = HostFileSystem, Cache = HostCache>> Command<C> for Build {
        fn exec(&self, conf: &C) -> Result<()> {
            let mut builder = HostSandboxExecutor::new(&self.path)?;
            smol::block_on(async move {
                let fs =
                    HostFileSystem::new(&self.path, rustix::process::geteuid().is_root()).await.map_err(|err| {
                        anyhow!(
                            "failed to initialize staging filesystem at {}: {}",
                            self.path.display(),
                            err
                        )
                    })?;
                conf.cache().init().await?;
                let manifest = Manifest::from_file(conf.manifest(), conf.arch())
                    .await
                    .map_err(|err| {
                        anyhow!(
                            "failed to load manifest from {}: {}",
                            conf.manifest().display(),
                            err
                        )
                    })?;
                let pb = if conf.log_level() == 0 {
                    Some(|size| {
                        ProgressBar::new(size).with_style(
                                indicatif::ProgressStyle::with_template(
                                    "staging files: {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}",
                                )
                                .unwrap()
                                .progress_chars("#>-"),
                            ).with_finish(indicatif::ProgressFinish::AndClear)
                    })
                } else {
                    None
                };
                tracing::debug!(
                    "Staging spec '{}' into '{}'",
                    self.spec.as_deref().unwrap_or("default"),
                    self.path.display()
                );
                let (essentials, other, scripts) = manifest
                    .stage_(
                        self.spec.as_deref(),
                        &fs,
                        conf.concurrency(),
                        conf.transport(),
                        conf.cache(),
                        pb,
                    )
                    .await?;
                builder.build(&fs, essentials, other, scripts).await?;
                Ok(())
            })
        }
    }
}

/// A parser type for converting command-line argument strings into a `Dependency`.
///
/// Example:
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Args {
///     #[arg(value_parser = DependencyParser)]
///     dependency: Vec<Dependency>,
/// }
/// ```
#[derive(Clone)]
pub struct DependencyParser;

impl clap::builder::TypedValueParser for DependencyParser {
    type Value = Dependency<String>;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err
        })?;
        Self::Value::from_str(value).map_err(|e| {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(value.to_string()),
            );
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String(format!("{}", e)),
            );
            err
        })
    }
}

struct PackageDisplay<'a> {
    name: &'a str,
    arch: &'a str,
    ver: Version<&'a str>,
    desc: &'a str,
    prio: InstallPriority,
}

impl<'a> From<&'a Package<'a>> for PackageDisplay<'a> {
    fn from(pkg: &'a Package<'a>) -> Self {
        Self {
            name: pkg.name(),
            arch: pkg.arch(),
            ver: pkg.raw_version(),
            desc: pkg.field("Description").unwrap_or(""),
            prio: pkg.install_priority(),
        }
    }
}

pub async fn pretty_print_packages<'a, W: smol::io::AsyncWrite + Unpin>(
    f: &mut W,
    iter: impl IntoIterator<Item = &'a Package<'a>>,
    sort: bool,
) -> Result<usize> {
    let mut w0 = 0usize;
    let mut w1 = 0usize;
    let mut w2 = 0usize;
    let mut w3 = 0usize;
    let mut w4 = 0usize;
    let mut packages = iter
        .into_iter()
        .map(PackageDisplay::try_from)
        .map(|pkg| {
            let pkg = pkg?;
            w0 = std::cmp::max(w0, pkg.arch.len());
            w1 = std::cmp::max(w1, pkg.prio.as_ref().len());
            w2 = std::cmp::max(w2, pkg.name.len());
            w3 = std::cmp::max(w3, pkg.ver.as_ref().len());
            w4 = std::cmp::max(w4, pkg.desc.len());
            Ok(pkg)
        })
        .collect::<Result<Vec<_>>>()?;
    if sort {
        packages.sort_by(|this, that| match this.name.cmp(that.name) {
            std::cmp::Ordering::Equal => this.ver.cmp(&that.ver),
            other => other,
        });
    }
    let mut buffer = Vec::<u8>::new();
    for p in packages.iter() {
        use smol::io::AsyncWriteExt;
        use std::io::Write;
        writeln!(
            &mut buffer,
            "{:>w0$} {:<w2$} {:>w3$} {:<w4$}",
            p.arch, p.name, p.ver, p.desc
        )?;
        f.write_all(&buffer).await?;
    }
    Ok(packages.len())
}

/// A parser type for converting command-line argument strings into a `Constraint`.
///
/// Example:
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Args {
///     #[arg(value_parser = ConstraintParser)]
///     dependency: Vec<Constraint>,
/// }
/// ```
#[derive(Clone)]
pub struct ConstraintParser;

impl clap::builder::TypedValueParser for ConstraintParser {
    type Value = Constraint<String>;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err
        })?;
        Self::Value::from_str(value).map_err(|e| {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(value.to_string()),
            );
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String(format!("{}", e)),
            );
            err
        })
    }
}
