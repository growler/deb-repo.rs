use {
    crate::{
        archive::{Archive, SnapshotId, SnapshotIdArgParser},
        content::ContentProvider,
        manifest::LockBase,
        packages::{InstallPriority, Package},
        version::{Constraint, Dependency, Version},
        StagingFileSystem,
    },
    anyhow::Result,
    indicatif::ProgressBar,
    std::{
        io,
        num::NonZero,
        path::Path,
        str::FromStr,
        sync::{
            atomic::{AtomicU64, AtomicU8},
            Arc,
        },
    },
};

pub trait Config {
    type FS: StagingFileSystem;
    type Cache: ContentProvider<Target = Self::FS>;
    fn log_level(&self) -> i32 {
        0
    }
    fn arch(&self) -> &str;
    fn manifest(&self) -> &Path;
    fn lock_base(&self) -> Option<&LockBase> {
        None
    }
    fn concurrency(&self) -> NonZero<usize>;
    fn fetcher(&self) -> io::Result<&Self::Cache>;
}

pub trait Command<C> {
    fn exec(&self, conf: &C) -> Result<()>;
}

#[derive(Clone)]
pub enum StageProgress {
    Indicatif(ProgressBar),
    Percent(PercentProgress),
}

impl StageProgress {
    pub fn from_progress_bar(pb: ProgressBar) -> Self {
        Self::Indicatif(pb)
    }

    pub fn percent(total: u64) -> Self {
        Self::Percent(PercentProgress::new(total))
    }

    pub(crate) fn inc(&self, delta: u64) {
        match self {
            StageProgress::Indicatif(pb) => pb.inc(delta),
            StageProgress::Percent(progress) => progress.inc(delta),
        }
    }

    pub(crate) fn finish(&self) {
        match self {
            StageProgress::Indicatif(pb) => pb.finish_using_style(),
            StageProgress::Percent(progress) => progress.finish(),
        }
    }
}

pub struct PercentProgress {
    inner: Arc<PercentProgressInner>,
}
impl Clone for PercentProgress {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct PercentProgressInner {
    total: u64,
    current: AtomicU64,
    last: AtomicU8,
}

impl PercentProgress {
    fn new(total: u64) -> Self {
        {
            use std::io::Write as _;
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(b"... ");
            let _ = stdout.flush();
        }
        Self {
            inner: Arc::new(PercentProgressInner {
                total,
                current: AtomicU64::new(0),
                last: AtomicU8::new(0),
            }),
        }
    }

    fn inc(&self, delta: u64) {
        use std::sync::atomic::Ordering;
        let current = self
            .inner
            .current
            .fetch_add(delta, Ordering::Relaxed)
            .saturating_add(delta);
        self.print_thresholds(self.percent(current));
    }

    fn finish(&self) {
        self.print_thresholds(100);
    }

    fn percent(&self, current: u64) -> u8 {
        if self.inner.total == 0 {
            100
        } else {
            ((current.saturating_mul(100)) / self.inner.total).min(100) as u8
        }
    }

    fn print_thresholds(&self, percent: u8) {
        use std::sync::atomic::Ordering;
        let last = self.inner.last.load(Ordering::Relaxed);
        let next = last + 10;
        if percent > next
            && self
                .inner
                .last
                .compare_exchange(last, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            use std::io::Write as _;
            let mut stdout = std::io::stdout();
            let _ = writeln!(stdout, "{}%", next);
            if next != 100 {
                let _ = write!(stdout, "... ");
            }
            let _ = stdout.flush();
        }
    }
}

pub mod cmd {
    pub use crate::cli_edit::Edit;
    use {
        super::*,
        crate::{
            artifact::{hash_directory, ArtifactArg},
            builder::ExecutorKind,
            comp::is_comp_ext,
            content::{ContentProviderGuard, HostCache},
            hash::{Hash, HashAlgo},
            manifest::Manifest,
            staging::HostFileSystem,
            version::ProvidedName,
        },
        anyhow::{anyhow, Result},
        clap::Parser,
        indicatif::ProgressBar,
        itertools::Itertools,
        rustix::path::Arg,
        smol::io::AsyncWriteExt,
        std::{io::IsTerminal, path::PathBuf},
    };
    #[derive(Parser)]
    #[command(
        about = "Create a new manifest file",
        long_about = r#"Create a new manifest file from an archive definition.
If a vendor name is provided as the archive URL, default archives and packages are derived from it.
Examples:
    rdebootstrap init debian --package mc --package libcom-err2"#
    )]
    pub struct Init {
        /// Overwrite existing manifest if present
        #[arg(long)]
        pub force: bool,

        /// Comment to add to the manifest file
        #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
        comment: Option<String>,

        /// Package to add (can be used multiple times)
        #[arg(short = 'r', long = "package", value_name = "PACKAGE")]
        requirements: Vec<String>,

        /// Archive definition (URL plus suite/component/snapshot options).
        /// URL might be a vendor name (debian, ubuntu, devuan).
        #[command(flatten)]
        archive: Archive,

        /// Do not verify InRelease signatures by default (not recommended)
        #[arg(long = "no-verify", display_order = 0, action)]
        insecure_release: bool,
    }

    impl<C: Config> Command<C> for Init {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let (archives, packages, comment) =
                    if let Some((archives, mut packages)) = self.archive.as_vendor() {
                        if !self.requirements.is_empty() {
                            packages.extend(self.requirements.iter().cloned());
                            packages = packages.into_iter().unique().collect();
                        }
                        (
                            archives,
                            packages,
                            Some(format!("default manifest file for {}", &self.archive.url)),
                        )
                    } else {
                        (vec![self.archive.clone()], self.requirements.clone(), None)
                    };
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let mut mf = Manifest::from_archives(
                    conf.arch(),
                    archives.iter().cloned(),
                    self.comment.as_deref().or(comment.as_deref()),
                );
                mf.add_requirements(None, packages.iter(), None)?;
                mf.update(
                    true,
                    false,
                    self.insecure_release,
                    conf.concurrency(),
                    fetcher,
                )
                .await?;
                mf.resolve(conf.concurrency(), fetcher).await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Add an archive",
        long_about = "Add an archive definition to the manifest file."
    )]
    pub struct AddArchive {
        /// Optional comment to record with this change
        #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
        comment: Option<String>,
        #[command(flatten)]
        archive: Archive,

        /// Do not verify InRelease signatures by default (not recommended)
        #[arg(long = "no-verify", display_order = 0, action)]
        insecure_release: bool,
    }
    impl<C: Config> Command<C> for AddArchive {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.add_archive(self.archive.clone(), self.comment.as_deref())?;
                mf.update(false, false, false, conf.concurrency(), fetcher)
                    .await?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                mf.resolve(conf.concurrency(), fetcher).await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Add a local package",
        long_about = "Add a local .deb package to the manifest file so it can be staged alongside archives."
    )]
    pub struct AddLocalPackage {
        /// Optional comment to record with this change
        #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
        comment: Option<String>,
        /// Path to a local .deb file
        #[arg(value_name = "PATH")]
        path: PathBuf,
    }
    impl<C: Config> Command<C> for AddLocalPackage {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let path = self
                    .path
                    .as_str()
                    .map_err(|err| anyhow!("invalid path: {}", err))?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                let (file, ctrl) = fetcher.ensure_deb(path).await?;
                mf.add_local_package(file, ctrl, self.comment.as_deref())?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                mf.resolve(conf.concurrency(), fetcher).await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[allow(clippy::large_enum_variant)]
    #[derive(Parser)]
    pub enum AddCommands {
        Archive(AddArchive),
        Local(AddLocalPackage),
    }

    #[derive(Parser)]
    #[command(about = "Add an archive or a local package to the manifest")]
    pub struct Add {
        #[command(subcommand)]
        cmd: AddCommands,
    }
    impl<C: Config> Command<C> for Add {
        fn exec(&self, conf: &C) -> Result<()> {
            match &self.cmd {
                AddCommands::Archive(cmd) => cmd.exec(conf),
                AddCommands::Local(cmd) => cmd.exec(conf),
            }
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Remove an archive",
        long_about = "Remove an archive reference from the manifest file."
    )]
    pub struct RemoveArchive {
        #[command(flatten)]
        archive: Archive,
    }
    impl<C: Config> Command<C> for RemoveArchive {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                mf.resolve(conf.concurrency(), fetcher).await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Remove local package",
        long_about = "Remove a local package from the manifest file."
    )]
    pub struct RemoveLocalPackage {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    }
    impl<C: Config> Command<C> for RemoveLocalPackage {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                mf.resolve(conf.concurrency(), fetcher).await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    pub enum RemoveCommands {
        Archive(RemoveArchive),
        Local(RemoveLocalPackage),
    }

    #[derive(Parser)]
    #[command(
        about = "Remove requirements or constraints from a spec",
        long_about = r#"Remove requirements and/or constraints from a spec.
Use --requirements-only or --constraints-only to limit the operation scope."#
    )]
    pub struct Remove {
        #[command(subcommand)]
        cmd: RemoveCommands,
    }
    impl<C: Config> Command<C> for Remove {
        fn exec(&self, conf: &C) -> Result<()> {
            match &self.cmd {
                RemoveCommands::Archive(cmd) => cmd.exec(conf),
                RemoveCommands::Local(cmd) => cmd.exec(conf),
            }
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Remove requirements or constraints from a spec",
        long_about = r#"Remove requirements and/or constraints from a spec.
Use --requirements-only or --constraints-only to limit the operation scope."#
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
        #[arg(value_name = "PACKAGE_OR_SET")]
        cons: Vec<String>,
    }
    impl<C: Config> Command<C> for Drop {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                if !self.constraints_only {
                    mf.remove_requirements(self.spec.as_deref(), self.cons.iter())?;
                }
                if !self.requirements_only {
                    mf.remove_constraints(self.spec.as_deref(), self.cons.iter())?;
                }
                mf.load_universe(conf.concurrency(), fetcher).await?;
                mf.resolve(conf.concurrency(), fetcher).await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Stage an artifact into a spec",
        long_about = "Add an external artifact (URL or file path) to a spec so it is included in the system tree."
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
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.add_artifact(
                    self.spec.as_deref(),
                    &self.artifact,
                    self.comment.as_deref(),
                    fetcher,
                )
                .await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
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
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.remove_artifact(self.spec.as_deref(), &self.url)?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Add package requirements to a spec",
        long_about = r#"Add one or more package requirements to a spec. Each requirement can be a bare package name or a set, and can include a version relation, e.g.:
  foo
  foo (= 1.2.3)
  bar (>= 2.0)
  foo | bar (<< 3.0)

  Alternatively, requirement might be a path to .deb file to include directly."#
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
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.add_requirements(
                    self.spec.as_deref(),
                    self.reqs.iter(),
                    self.comment.as_deref(),
                )?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                mf.resolve(conf.concurrency(), fetcher).await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Add package constraints to a spec",
        long_about = r#"Add one or more constraints to restrict resolution. Examples:
  foo (= 1.2.3)
  foo (<< 2.0)  
  bar (<= 3.4)"#
    )]
    pub struct Exclude {
        /// Target spec (omit to use the default spec)
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,
        /// Optional comment to record with this change
        #[arg(short = 'c', long = "comment", value_name = "COMMENT")]
        comment: Option<String>,
        /// Constraint(s) to apply (repeatable)
        #[arg(value_name = "CONSTRAINT", value_parser = ConstraintParser)]
        reqs: Vec<Constraint<String>>,
    }

    impl<C: Config> Command<C> for Exclude {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.add_constraints(
                    self.spec.as_deref(),
                    self.reqs.iter(),
                    self.comment.as_deref(),
                )?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                mf.resolve(conf.concurrency(), fetcher).await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Update archives and snapshot/lock state",
        long_about = "Refresh archive metadata, solve specs, and rewrite the lock file."
    )]
    pub struct Update {
        /// Update lock file even if it appears up to date
        /// (refresh package indexes and re-resolve everything)
        #[arg(short = 'f', long = "force", action)]
        force: bool,
        /// Re-fetch package archives even if they appear up to date (implies --force).
        #[arg(short = 'A', long = "archives", action)]
        archives: bool,
        /// Refresh local packages index (implies --force).
        #[arg(short = 'L', long = "locals", action)]
        locals: bool,
        /// Snapshot ID to use for all snapshot-enabled archives (use 'now' for current time)
        #[arg(short = 's', long = "snapshot", value_name = "SNAPSHOT_ID", value_parser = SnapshotIdArgParser)]
        snapshot: Option<SnapshotId>,
        /// Do not verify InRelease signatures by default (not recommended)
        #[arg(long = "no-verify", display_order = 0, action)]
        insecure_release: bool,
    }

    impl<C: Config> Command<C> for Update {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let force = self.force || self.archives || self.locals;
                let (mut mf, has_valid_lock) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                if has_valid_lock && !force {
                    tracing::debug!("Lock file is up to date, nothing to do");
                    return Ok(());
                }
                if let Some(snapshot) = &self.snapshot {
                    mf.set_snapshot(*snapshot).await;
                }
                mf.update(
                    self.archives,
                    self.locals,
                    self.insecure_release,
                    conf.concurrency(),
                    fetcher,
                )
                .await?;
                mf.store_with_lock_base(conf.manifest(), conf.lock_base())
                    .await?;
                guard.commit().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Search packages in archives",
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
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                guard.commit().await?;
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
                        res.is_empty()
                            || res.iter().any(|re| {
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
                out.flush().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    pub enum ShowCommands {
        Package(ShowPackage),
        Source(ShowSource),
        SpecHash(ShowSpecHash),
    }

    #[derive(Parser)]
    #[command(about = "Show package records or spec information")]
    pub struct Show {
        #[command(subcommand)]
        cmd: ShowCommands,
    }
    impl<C: Config> Command<C> for Show {
        fn exec(&self, conf: &C) -> Result<()> {
            match &self.cmd {
                ShowCommands::Source(cmd) => cmd.exec(conf),
                ShowCommands::Package(cmd) => cmd.exec(conf),
                ShowCommands::SpecHash(cmd) => cmd.exec(conf),
            }
        }
    }

    #[derive(Parser)]
    #[command(
        name = "spec-hash",
        about = "Show a spec hash",
        long_about = "Print the hash of a spec definition. By default the hash is printed as a hexadecimal string; use --sri to emit Subresource Integrity format."
    )]
    pub struct ShowSpecHash {
        /// Use SRI format for the hash output
        ///
        /// Outputs the hash as SRI (Subresource Integrity) format, e.g.
        /// sha256-<base64-encoded-hash>. If not specified, the hash is printed
        /// as a hexadecimal string.
        #[arg(long = "sri", action)]
        sri: bool,
        /// Spec name (omit to use the default spec)
        #[arg(value_name = "SPEC")]
        spec: Option<String>,
    }

    impl<C: Config> Command<C> for ShowSpecHash {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let (mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                let hash = mf.spec_hash(self.spec.as_deref())?;
                if self.sri {
                    println!("{}", hash.to_sri());
                } else {
                    println!("{}", hash.to_hex());
                }
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        name = "package",
        about = "Show a package's control record",
        long_about = "Print the raw control record for the given package."
    )]
    pub struct ShowPackage {
        /// Package name
        #[arg(value_name = "PACKAGE")]
        package: String,
    }

    impl<C: Config> Command<C> for ShowPackage {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                guard.commit().await?;
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
    #[command(
        name = "source",
        about = "Show a package's source control record",
        long_about = "Print the raw source control record for the given package or source package."
    )]
    pub struct ShowSource {
        /// Find and print source files as artifacts to stage in path.
        /// Fails if there are multiple source packages matching the name.
        #[arg(long = "stage-to", value_name = "PATH")]
        stage_to: Option<String>,
        /// Package or source package name. May include version (pkg=version)
        #[arg(value_name = "PACKAGE")]
        package: String,
    }

    impl<C: Config> Command<C> for ShowSource {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let name = ProvidedName::try_parse_display(&self.package).map_err(|err| {
                    anyhow!("invalid package/source name '{}': {}", &self.package, err)
                })?;
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.load_source_universe(conf.concurrency(), fetcher).await?;
                guard.commit().await?;
                let found = mf.find_source(&name)?;
                if found.is_empty() {
                    return Err(anyhow!("package/source {} not found", &self.package));
                }
                let mut out = async_io::Async::new(std::io::stdout().lock())?;
                if let Some(target) = self.stage_to.as_deref() {
                    if found.len() > 1 {
                        return Err(anyhow!(
                            "multiple source packages found for {}, cannot show as artifacts",
                            &self.package
                        ));
                    }
                    let src = found.first().unwrap();
                    let mut first = true;
                    let mut staged = vec![];
                    for artifact in src.files() {
                        if first {
                            first = false;
                        } else {
                            out.write_all(b"\n").await?;
                        }
                        let file_name = match artifact.path.rsplit('/').next() {
                            Some(name) => name,
                            None => &artifact.path,
                        };
                        out.write_all(
                            format!(
                                "[artifact.\"{}\"]
type = \"file\"
target = \"{}/{}\"
size = {}
hash = \"{}\"
",
                                &artifact.path,
                                target.trim_end_matches('/'),
                                file_name,
                                artifact.size,
                                artifact.hash.to_sri(),
                            )
                            .as_bytes(),
                        )
                        .await?;
                        if is_comp_ext(&artifact.path) {
                            out.write_all(b"unpack = false\n").await?;
                        }
                        staged.push(&artifact.path);
                    }
                    out.write_all(b"\nstage = [\n").await?;
                    for staged in staged {
                        out.write_all(format!("    \"{}\",\n", staged).as_bytes())
                            .await?;
                    }
                    out.write_all(b"]\n").await?;
                } else {
                    for src in found.iter() {
                        out.write_all(src.as_ref().as_bytes()).await?;
                        out.write_all(b"\n").await?;
                    }
                }
                out.flush().await?;
                Ok(())
            })
        }
    }

    fn normalize_hash_name(name: &str) -> Result<&'static str> {
        let name = name.trim();
        if name.is_empty() {
            return Err(anyhow!("hash name cannot be empty"));
        }
        match name.to_ascii_lowercase().as_str() {
            "md5" | "md5sum" => Ok(md5::Md5::NAME),
            "sha1" => Ok(sha1::Sha1::NAME),
            "sha256" => Ok(sha2::Sha256::NAME),
            "sha512" => Ok(sha2::Sha512::NAME),
            "blake3" => Ok(blake3::Hasher::NAME),
            _ => Err(anyhow!(
                "unsupported hash {}, expected one of: md5, sha1, sha256, sha512, blake3",
                name
            )),
        }
    }

    #[derive(Parser)]
    pub enum ToolCommands {
        HexToSri(ToolHexToSri),
        SriToHex(ToolSriToHex),
        Hash(ToolHash),
    }

    #[derive(Parser)]
    #[command(about = "Internal tooling helpers", hide = true)]
    pub struct Tool {
        #[command(subcommand)]
        cmd: ToolCommands,
    }

    impl<C: Config> Command<C> for Tool {
        fn exec(&self, conf: &C) -> Result<()> {
            match &self.cmd {
                ToolCommands::HexToSri(cmd) => cmd.exec(conf),
                ToolCommands::SriToHex(cmd) => cmd.exec(conf),
                ToolCommands::Hash(cmd) => cmd.exec(conf),
            }
        }
    }

    #[derive(Parser)]
    #[command(
        name = "hex-to-sri",
        about = "Convert a hex digest to SRI format",
        long_about = "Convert a hex digest and hash name to SRI (Subresource Integrity) format."
    )]
    pub struct ToolHexToSri {
        #[arg(value_name = "HASH_NAME")]
        hash: String,
        #[arg(value_name = "HEX_DIGEST")]
        digest: String,
    }

    impl<C: Config> Command<C> for ToolHexToSri {
        fn exec(&self, _conf: &C) -> Result<()> {
            let name = normalize_hash_name(&self.hash)?;
            let hash = Hash::from_hex(name, &self.digest)
                .map_err(|err| anyhow!("error decoding hex digest: {}", err))?;
            println!("{}", hash.to_sri());
            Ok(())
        }
    }

    #[derive(Parser)]
    #[command(
        name = "sri-to-hex",
        about = "Convert an SRI digest to hex",
        long_about = "Convert an SRI (Subresource Integrity) digest to hexadecimal."
    )]
    pub struct ToolSriToHex {
        #[arg(value_name = "SRI_DIGEST")]
        digest: String,
    }

    impl<C: Config> Command<C> for ToolSriToHex {
        fn exec(&self, _conf: &C) -> Result<()> {
            let hash = Hash::from_sri(&self.digest)
                .map_err(|err| anyhow!("error decoding SRI digest: {}", err))?;
            println!("{}", hash.to_hex());
            Ok(())
        }
    }

    #[derive(Parser)]
    #[command(
        name = "hash",
        about = "Hash a file, directory, or stdin",
        long_about = "Hash a file, directory, or stdin. For directories the artifact tree hash (blake3) is used."
    )]
    pub struct ToolHash {
        #[arg(value_name = "HASH_NAME")]
        hash: String,
        /// Output in SRI format instead of hex
        #[arg(long = "sri", conflicts_with = "hex", action)]
        sri: bool,
        /// Output in hex (default)
        #[arg(long = "hex", conflicts_with = "sri", action)]
        hex: bool,
        /// File or directory to hash (stdin if omitted)
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    }

    impl<C: Config> Command<C> for ToolHash {
        fn exec(&self, _conf: &C) -> Result<()> {
            let name = normalize_hash_name(&self.hash)?;
            let use_sri = self.sri;
            smol::block_on(async move {
                let hash = if let Some(path) = self.path.as_ref() {
                    let meta = smol::fs::metadata(path)
                        .await
                        .map_err(|err| anyhow!("failed to stat {}: {}", path.display(), err))?;
                    if meta.is_dir() {
                        let (hash, _) = hash_directory(path, name).await.map_err(|err| {
                            anyhow!("failed to hash directory {}: {}", path.display(), err)
                        })?;
                        hash
                    } else {
                        let file = smol::fs::File::open(path)
                            .await
                            .map_err(|err| anyhow!("failed to open {}: {}", path.display(), err))?;
                        let mut hasher = Hash::hashing_reader_for(name, file)?;
                        smol::io::copy(&mut hasher, &mut smol::io::sink())
                            .await
                            .map_err(|err| anyhow!("failed to read stdin: {}", err))?;
                        hasher.as_mut().hash()
                    }
                } else {
                    let stdin = async_io::Async::new(std::io::stdin())
                        .map_err(|err| anyhow!("failed to read stdin: {}", err))?;
                    let mut hasher = Hash::hashing_reader_for(name, stdin)?;
                    smol::io::copy(&mut hasher, &mut smol::io::sink())
                        .await
                        .map_err(|err| anyhow!("failed to read stdin: {}", err))?;
                    hasher.as_mut().hash()
                };
                if use_sri {
                    println!("{}", hash.to_sri());
                } else {
                    println!("{}", hash.to_hex());
                }
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "List manifest items",
        long_about = "List manifest items (use --specs to list specs, or --spec <name> to list packages for a spec)."
    )]
    pub struct List {
        #[arg(short = 'e', long = "only-essential", hide = true)]
        only_essential: bool,
        //
        /// List available spec names instead of package contents
        #[arg(long = "specs", conflicts_with = "spec", action)]
        list_specs: bool,
        /// List packages for the target spec (omit to use the default spec)
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,
    }

    impl<C: Config> Command<C> for List {
        fn exec(&self, conf: &C) -> Result<()> {
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let (mut mf, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await?;
                mf.load_universe(conf.concurrency(), fetcher).await?;
                guard.commit().await?;
                let mut pkgs = mf
                    .spec_packages(self.spec.as_deref())?
                    .filter(|p| !self.only_essential || p.essential())
                    .collect::<Vec<_>>();
                pkgs.sort_by_key(|&pkg| pkg.name());
                let mut out = std::io::stdout().lock();
                let mut out = smol::io::BufWriter::new(async_io::Async::new(&mut out)?);
                pretty_print_packages(&mut out, pkgs, false).await?;
                out.flush().await?;
                Ok(())
            })
        }
    }

    #[derive(Parser)]
    #[command(
        about = "Build an installable root for a spec",
        long_about = "Build an installable root filesystem tree for a spec."
    )]
    pub struct Build {
        /// The spec name to build
        #[arg(short = 's', long = "spec", value_name = "SPEC")]
        spec: Option<String>,
        /// Build executor to use
        #[arg(
            long = "executor",
            value_name = "EXECUTOR",
            value_enum,
            default_value = "sandbox"
        )]
        executor: ExecutorKind,
        /// The target directory
        #[arg(short, long, value_name = "PATH")]
        path: PathBuf,
    }

    impl<C: Config<FS = HostFileSystem, Cache = HostCache>> Command<C> for Build {
        fn exec(&self, conf: &C) -> Result<()> {
            let mut builder = self.executor.build_executor(&self.path)?;
            tracing::debug!("current process state {}", current_process_state(),);
            smol::block_on(async move {
                let fetcher = conf.fetcher()?;
                let guard = fetcher.init().await?;
                let fs = HostFileSystem::new(&self.path, rustix::process::geteuid().is_root())
                    .await
                    .map_err(|err| {
                        anyhow!(
                            "failed to initialize staging filesystem at {}: {}",
                            self.path.display(),
                            err
                        )
                    })?;
                let (manifest, _) = Manifest::from_file_with_lock_base(
                    conf.manifest(),
                    conf.arch(),
                    conf.lock_base(),
                )
                .await
                .map_err(|err| {
                    anyhow!(
                        "failed to load manifest from {}: {}",
                        conf.manifest().display(),
                        err
                    )
                })?;
                let pb = if conf.log_level() == 0 {
                    let use_tty = std::io::stderr().is_terminal();
                    Some(move |size| {
                        if use_tty {
                            StageProgress::from_progress_bar(
                                ProgressBar::new(size).with_style(
                                    indicatif::ProgressStyle::with_template(
                                        "staging files: {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}",
                                    )
                                    .unwrap()
                                    .progress_chars("#>-"),
                                ).with_finish(indicatif::ProgressFinish::AndClear),
                            )
                        } else {
                            StageProgress::percent(size)
                        }
                    })
                } else {
                    None
                };
                tracing::debug!(
                    "Staging spec '{}' into '{}'",
                    self.spec.as_deref().unwrap_or("default"),
                    self.path.display()
                );
                let (essentials, other, scripts, build_env) = manifest
                    .stage(self.spec.as_deref(), &fs, conf.concurrency(), fetcher, pb)
                    .await?;
                builder
                    .build(&fs, essentials, other, scripts, build_env)
                    .await?;
                guard.commit().await?;
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
            desc: pkg
                .field("Description")
                .map_or("", |d| d.split('\n').next().unwrap_or("")),
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
    let mut buf = Vec::new();
    for p in packages.iter() {
        use smol::io::AsyncWriteExt;
        use std::io::Write;
        buf.truncate(0);
        writeln!(
            &mut buf,
            "{:>w0$} {:<w2$} {:>w3$} {:<w4$}",
            p.arch, p.name, p.ver, p.desc
        )?;
        f.write_all(&buf).await?;
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

pub fn current_process_state() -> impl std::fmt::Display {
    ProcessState::collect()
}

struct ProcessState {
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    uid_map: String,
    gid_map: String,
    setgroups: String,
    status_filtered: String,
    chown_test_result: String,
}

impl ProcessState {
    fn read_file(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| format!("(failed to read {path}: {e})"))
    }

    fn collect() -> Self {
        use rustix::process::{getegid, geteuid, getgid, getuid};
        let uid = getuid().as_raw();
        let euid = geteuid().as_raw();
        let gid = getgid().as_raw();
        let egid = getegid().as_raw();

        let uid_map = Self::read_file("/proc/self/uid_map");
        let gid_map = Self::read_file("/proc/self/gid_map");
        let setgroups = Self::read_file("/proc/self/setgroups");

        let status = Self::read_file("/proc/self/status");
        let mut status_filtered = String::new();
        for line in status.lines() {
            if line.starts_with("Uid:")
                || line.starts_with("Gid:")
                || line.starts_with("Groups:")
                || line.starts_with("CapEff:")
                || line.starts_with("CapPrm:")
                || line.starts_with("CapBnd:")
                || line.starts_with("NoNewPrivs:")
                || line.starts_with("Seccomp:")
            {
                status_filtered.push_str(line);
                status_filtered.push('\n');
            }
        }

        // Controlled chown test in current directory
        let chown_test_result = match Self::chown_test() {
            Ok(msg) => msg,
            Err(e) => format!("chown test failed to run: {e}"),
        };

        Self {
            uid,
            euid,
            gid,
            egid,
            uid_map,
            gid_map,
            setgroups,
            status_filtered,
            chown_test_result,
        }
    }

    fn chown_test() -> io::Result<String> {
        use rustix::fd::OwnedFd;
        use rustix::fs::{fchown, openat, unlinkat, AtFlags, Mode, OFlags};
        use rustix::process::{Gid, Uid};

        let path = "rdebootstrap_chown_test";

        // remove if exists
        let _ = unlinkat(rustix::fs::CWD, path, AtFlags::empty());

        let fd: OwnedFd = openat(
            rustix::fs::CWD,
            path,
            OFlags::CREATE | OFlags::WRONLY,
            Mode::from_bits_truncate(0o644),
        )?;

        let result = match fchown(&fd, Some(Uid::from_raw(0)), Some(Gid::from_raw(42))) {
            Ok(()) => "fchown(fd, 0, 42) succeeded".to_string(),
            Err(e) => format!("fchown(fd, 0, 42) failed: {e}"),
        };

        drop(fd);
        let _ = unlinkat(rustix::fs::CWD, path, AtFlags::empty());

        Ok(result)
    }
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "== ids ==")?;
        writeln!(
            f,
            "uid={} euid={} gid={} egid={}",
            self.uid, self.euid, self.gid, self.egid
        )?;

        writeln!(f, "\n== /proc/self/uid_map ==")?;
        writeln!(f, "{}", self.uid_map)?;

        writeln!(f, "== /proc/self/gid_map ==")?;
        writeln!(f, "{}", self.gid_map)?;

        writeln!(f, "== /proc/self/setgroups ==")?;
        writeln!(f, "{}", self.setgroups)?;

        writeln!(f, "== filtered /proc/self/status ==")?;
        writeln!(f, "{}", self.status_filtered)?;

        writeln!(f, "== chown test ==")?;
        writeln!(f, "{}", self.chown_test_result)?;

        Ok(())
    }
}
