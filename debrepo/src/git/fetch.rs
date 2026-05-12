//! Subprocess-`git` driver used by `HostCache` for git imports.
//!
//! Strategy:
//! 1. Maintain a per-repo bare clone under `<cache>/git/<sha256(url)>/repo.git`
//!    for `GitRemote::Url`.  Local (`git+file://`) sources are read directly
//!    from the user's repository — no bare clone is created.
//! 2. `git fetch --depth 1 --filter=blob:none origin <rev-or-ref>` into it.
//!    `--filter=blob:none` keeps the partial clone small for monorepos; we
//!    only need the manifest, lock, and a few `[[local]]` blobs.
//! 3. Resolve symbolic refs via `git ls-remote` (no clone needed).  Local
//!    sources resolve symbolic refs through `git -C <abs> ls-remote .`.
//! 4. Read individual blobs by spawning `git -C <repo_dir> cat-file -p
//!    <sha>:<path>` for each blob.  For hosted remotes `<repo_dir>` is the
//!    cache clone; for local sources it is the user's repository.
//! 5. Materialise the requested paths into `<cache>/git/<id>/revs/<rev>/`,
//!    mirroring their in-repo layout so the higher layer can read them
//!    by simple path join.
//!
//! HTTPS/HTTP auth is driven via `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` /
//! `GIT_CONFIG_VALUE_n` environment variables so secrets never appear on
//! `git`'s argv.  The `[[auth]]` entry for the URL's hostname (resolved via
//! `AuthProvider::auth`) maps to:
//!
//! - `Auth::Basic`  → `http.extraHeader: Authorization: Basic <b64>`
//! - `Auth::Token`  → `http.extraHeader: Authorization: Bearer <token>`
//! - `Auth::Cert`   → `http.sslCert` / `http.sslKey` / `http.sslKeyPasswd`
//!   (cert/key bytes written to temp files, cleaned up on drop)
//!
//! SSH auth defers entirely to the user's system `ssh` configuration.
//! Local sources need no auth.

use {
    super::{
        is_full_sha1,
        url::{check_in_repo_path, GitRemote, GitRepo, GitRevSpec},
    },
    crate::auth::{Auth, AuthProvider},
    base64::Engine as _,
    sha2::{Digest, Sha256},
    smol::process::Command,
    std::{
        ffi::OsString,
        io,
        path::{Path, PathBuf},
        process::Stdio,
        sync::Arc,
    },
    url::Url,
};

/// Handle returned by `GitFetcher::fetch_repo`.
#[derive(Clone, Debug)]
pub struct MaterializedGitRepo {
    /// Root of the materialised subtree.
    tree_root: PathBuf,
    /// Resolved commit SHA.
    rev: String,
    /// Directory passed to `git -C` for `cat-file`.
    pub(crate) repo_dir: PathBuf,
    /// Canonical remote identifier.
    pub(crate) remote: GitRemote,
}

impl MaterializedGitRepo {
    pub fn tree_root(&self) -> &Path {
        &self.tree_root
    }

    pub fn rev(&self) -> &str {
        &self.rev
    }
}

/// RAII handle that keeps temporary cert/key files alive for the duration of
/// a git command.  Files are deleted when this value is dropped.
struct TempCertFiles {
    /// Cert file — held for its `Drop` side-effect (file deletion).
    _cert: tempfile::NamedTempFile,
    /// Key file — held for its `Drop` side-effect (file deletion).
    _key: Option<tempfile::NamedTempFile>,
}

/// Auth configuration to inject into a git subprocess via `GIT_CONFIG_*`
/// environment variables.
struct GitAuthEnv {
    /// `(key, value)` pairs for `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`.
    pairs: Vec<(String, String)>,
    /// Keeps temp cert/key files alive until the subprocess exits.
    _certs: Option<TempCertFiles>,
}

impl GitAuthEnv {
    fn empty() -> Self {
        Self {
            pairs: vec![],
            _certs: None,
        }
    }

    /// Sets `GIT_CONFIG_COUNT` and the indexed key/value pairs on `cmd`.
    /// No-op when there are no pairs.
    fn apply(&self, cmd: &mut Command) {
        if self.pairs.is_empty() {
            return;
        }
        cmd.env("GIT_CONFIG_COUNT", self.pairs.len().to_string());
        for (i, (k, v)) in self.pairs.iter().enumerate() {
            cmd.env(format!("GIT_CONFIG_KEY_{}", i), k);
            cmd.env(format!("GIT_CONFIG_VALUE_{}", i), v);
        }
    }
}

/// Subprocess-`git` driver.
pub struct GitFetcher {
    cache_root: PathBuf,
    auth: Arc<AuthProvider>,
    git_program: OsString,
}

impl GitFetcher {
    pub fn new(cache_root: PathBuf, auth: Arc<AuthProvider>) -> Self {
        let git_program = std::env::var_os("GIT").unwrap_or_else(|| OsString::from("git"));
        Self {
            cache_root,
            auth,
            git_program,
        }
    }

    fn cache_id(&self, remote: &GitRemote) -> String {
        repo_cache_id(&remote.cache_key())
    }

    fn rev_dir(&self, remote: &GitRemote, rev: &str) -> PathBuf {
        self.cache_root
            .join(self.cache_id(remote))
            .join("revs")
            .join(rev)
    }

    /// Builds a `Command` invoking the configured git binary with hardened
    /// defaults (no terminal prompt, no global pager, no credential helpers).
    fn git(&self) -> Command {
        let mut cmd = Command::new(&self.git_program);
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        cmd.env("GIT_PAGER", "cat");
        cmd.env("LC_ALL", "C");
        cmd
    }

    /// Resolves HTTPS/HTTP auth for `url` from the `AuthProvider` and returns
    /// a `GitAuthEnv` ready to be applied to any `Command` that talks to that
    /// URL.  SSH and `file://` URLs return an empty env (no auth needed).
    async fn resolve_auth(&self, url: &str) -> io::Result<GitAuthEnv> {
        let scheme = url.split_once("://").map(|(s, _)| s).unwrap_or_default();
        if !matches!(scheme, "http" | "https") {
            return Ok(GitAuthEnv::empty());
        }

        let parsed = Url::parse(url)
            .map_err(|e| io::Error::other(format!("invalid git URL `{}`: {}", url, e)))?;

        let auth = match self.auth.auth(&parsed).await {
            Some(a) => a,
            None => return Ok(GitAuthEnv::empty()),
        };

        match auth.as_ref() {
            Auth::Basic { login, password } => {
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", login, password));
                Ok(GitAuthEnv {
                    pairs: vec![(
                        "http.extraHeader".into(),
                        format!("Authorization: Basic {}", encoded),
                    )],
                    _certs: None,
                })
            }
            Auth::Token { token } => Ok(GitAuthEnv {
                pairs: vec![(
                    "http.extraHeader".into(),
                    format!("Authorization: Bearer {}", token),
                )],
                _certs: None,
            }),
            Auth::Cert {
                cert,
                key,
                password,
            } => {
                let cert_file = tempfile::NamedTempFile::new().map_err(|e| {
                    io::Error::other(format!("failed to create temp cert file: {}", e))
                })?;
                smol::fs::write(cert_file.path(), cert).await?;

                let mut pairs = vec![(
                    "http.sslCert".into(),
                    cert_file.path().display().to_string(),
                )];

                let key_file = if let Some(key_bytes) = key {
                    let kf = tempfile::NamedTempFile::new().map_err(|e| {
                        io::Error::other(format!("failed to create temp key file: {}", e))
                    })?;
                    smol::fs::write(kf.path(), key_bytes).await?;
                    pairs.push(("http.sslKey".into(), kf.path().display().to_string()));
                    Some(kf)
                } else {
                    None
                };

                if let Some(pw) = password {
                    pairs.push(("http.sslKeyPasswd".into(), pw.clone()));
                }

                Ok(GitAuthEnv {
                    pairs,
                    _certs: Some(TempCertFiles {
                        _cert: cert_file,
                        _key: key_file,
                    }),
                })
            }
        }
    }

    async fn ensure_bare_repo(&self, remote: &GitRemote) -> io::Result<PathBuf> {
        let dir = self.cache_root.join(self.cache_id(remote)).join("repo.git");
        if smol::fs::metadata(dir.join("HEAD")).await.is_ok() {
            return Ok(dir);
        }
        smol::fs::create_dir_all(&dir).await?;
        let status = self
            .git()
            .arg("-C")
            .arg(&dir)
            .arg("init")
            .arg("--bare")
            .arg("-q")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "`git init --bare` failed at {}",
                dir.display()
            )));
        }
        Ok(dir)
    }

    async fn ensure_local_source(&self, path: &Path) -> io::Result<PathBuf> {
        let meta = smol::fs::metadata(path).await.map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "git import source `{}` is not accessible: {}",
                    path.display(),
                    err
                ),
            )
        })?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("git import source `{}` is not a directory", path.display()),
            ));
        }
        let output = self
            .git()
            .arg("-C")
            .arg(path)
            .arg("rev-parse")
            .arg("--git-dir")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "`{}` is not a git repository: {}",
                    path.display(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }
        Ok(path.to_path_buf())
    }

    fn build_fetch_command(
        &self,
        repo_dir: &Path,
        url: &str,
        refspec: &str,
        auth: &GitAuthEnv,
    ) -> Command {
        let mut cmd = self.git();
        cmd.arg("-C").arg(repo_dir);
        // Suppress credential helpers so we drive auth entirely via
        // GIT_CONFIG_* env vars.
        cmd.arg("-c").arg("credential.helper=");
        cmd.arg("fetch");
        cmd.arg("--depth=1");
        cmd.arg("--filter=blob:none");
        cmd.arg("--no-tags");
        cmd.arg("--prune");
        cmd.arg(url);
        cmd.arg(refspec);
        auth.apply(&mut cmd);
        cmd
    }

    async fn fetch_rev(&self, repo_dir: &Path, url: &str, rev: &str) -> io::Result<()> {
        let auth = self.resolve_auth(url).await?;
        let refspec = format!("+{}:refs/rdebootstrap/fetched", rev);
        let mut cmd = self.build_fetch_command(repo_dir, url, &refspec, &auth);
        run_command(&mut cmd, "git fetch").await
    }

    async fn fetch_symbolic(
        &self,
        repo_dir: &Path,
        url: &str,
        sym_ref: &str,
    ) -> io::Result<String> {
        let sha = self.ls_remote(url, sym_ref).await?;
        self.fetch_rev(repo_dir, url, &sha).await?;
        Ok(sha)
    }

    async fn ls_remote(&self, url: &str, ref_name: &str) -> io::Result<String> {
        let auth = self.resolve_auth(url).await?;
        let mut cmd = self.git();
        cmd.arg("ls-remote");
        cmd.arg("--exit-code");
        cmd.arg(url);
        cmd.arg(format!("refs/heads/{}", ref_name));
        cmd.arg(format!("refs/tags/{}", ref_name));
        cmd.arg(format!("refs/tags/{}^{{}}", ref_name));
        cmd.arg(ref_name);
        auth.apply(&mut cmd);
        let output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "`git ls-remote {}` failed: {}",
                ref_name,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut chosen: Option<String> = None;
        for line in stdout.lines() {
            let mut parts = line.split_whitespace();
            let sha = match parts.next() {
                Some(s) if s.len() == 40 => s.to_string(),
                _ => continue,
            };
            let refname = parts.next().unwrap_or("");
            if refname.ends_with("^{}") {
                return Ok(sha);
            }
            if chosen.is_none() || refname == format!("refs/tags/{}", ref_name) {
                chosen = Some(sha);
            }
        }
        chosen.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("git ref `{}` not found in {}", ref_name, url),
            )
        })
    }

    async fn verify_local_sha(&self, repo_dir: &Path, sha: &str) -> io::Result<()> {
        let object = format!("{}^{{commit}}", sha);
        let output = self
            .git()
            .arg("-C")
            .arg(repo_dir)
            .arg("cat-file")
            .arg("-e")
            .arg(&object)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "git commit `{}` not present in `{}`",
                sha,
                repo_dir.display()
            ),
        ))
    }

    async fn read_blob(&self, repo_dir: &Path, rev: &str, path: &Path) -> io::Result<Vec<u8>> {
        check_in_repo_path(path)?;
        let object = format!("{}:{}", rev, path.to_string_lossy());
        let mut cmd = self.git();
        cmd.arg("-C").arg(repo_dir);
        cmd.env("GIT_OPTIONAL_LOCKS", "0");
        cmd.arg("cat-file").arg("-p").arg(&object);
        let output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let trimmed = stderr.trim();
            if trimmed.contains("does not exist")
                || trimmed.contains("Not a valid object name")
                || trimmed.contains("could not get object info")
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("git object `{}` not found", object),
                ));
            }
            return Err(io::Error::other(format!(
                "`git cat-file -p {}` failed: {}",
                object, trimmed
            )));
        }
        Ok(output.stdout)
    }

    /// Ensures the on-disk state needed to read blobs for `repo.revspec` is
    /// ready.  For `GitRemote::Url` this means a per-remote bare clone; for
    /// `GitRemote::Local` the user's repository is used directly.  Resolves
    /// the rev to a SHA, creates an empty `tree_root`, and returns a
    /// `MaterializedGitRepo` handle.  No blobs are written.
    pub async fn fetch_repo(&self, repo: &GitRepo) -> io::Result<MaterializedGitRepo> {
        let (repo_dir, rev) = match &repo.remote {
            GitRemote::Url(url) => {
                let repo_dir = self.ensure_bare_repo(&repo.remote).await?;
                let rev = match &repo.revspec {
                    GitRevSpec::Sha(sha) => {
                        if !is_full_sha1(sha) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("invalid commit SHA `{}`", sha),
                            ));
                        }
                        self.fetch_rev(&repo_dir, url, sha).await?;
                        sha.to_lowercase()
                    }
                    GitRevSpec::Symbolic(name) => self.fetch_symbolic(&repo_dir, url, name).await?,
                };
                (repo_dir, rev)
            }
            GitRemote::Local(path) => {
                let repo_dir = self.ensure_local_source(path).await?;
                let rev = match &repo.revspec {
                    GitRevSpec::Sha(sha) => {
                        if !is_full_sha1(sha) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("invalid commit SHA `{}`", sha),
                            ));
                        }
                        self.verify_local_sha(&repo_dir, sha).await?;
                        sha.to_lowercase()
                    }
                    GitRevSpec::Symbolic(name) => {
                        // ls-remote against `file://<abs>` resolves the ref
                        // without needing a clone.
                        let file_url = format!("file://{}", path.display());
                        let sha = self.ls_remote(&file_url, name).await?;
                        self.verify_local_sha(&repo_dir, &sha).await?;
                        sha
                    }
                };
                (repo_dir, rev)
            }
        };
        let tree_root = self.rev_dir(&repo.remote, &rev);
        if smol::fs::metadata(&tree_root).await.is_ok() {
            smol::fs::remove_dir_all(&tree_root).await.ok();
        }
        smol::fs::create_dir_all(&tree_root).await?;
        Ok(MaterializedGitRepo {
            tree_root,
            rev,
            repo_dir,
            remote: repo.remote.clone(),
        })
    }

    /// Materialises a list of in-repo paths under `m.tree_root()`.
    pub async fn materialize_paths(
        &self,
        m: &MaterializedGitRepo,
        paths: &[PathBuf],
    ) -> io::Result<()> {
        for path in paths {
            check_in_repo_path(path)?;
            if path.as_os_str().to_string_lossy().ends_with('/') {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "materialize_git_paths: directory targets not yet supported (`{}`)",
                        path.display()
                    ),
                ));
            }
            if smol::fs::metadata(m.tree_root.join(path)).await.is_ok() {
                continue;
            }
            let bytes = self.read_blob(&m.repo_dir, &m.rev, path).await?;
            write_blob(&m.tree_root, path, &bytes).await?;
        }
        let _ = &m.remote;
        Ok(())
    }
}

async fn write_blob(root: &Path, rel: &Path, bytes: &[u8]) -> io::Result<()> {
    let dest = root.join(rel);
    if let Some(parent) = dest.parent() {
        smol::fs::create_dir_all(parent).await?;
    }
    smol::fs::write(&dest, bytes).await
}

fn repo_cache_id(remote: &str) -> String {
    let mut h = Sha256::new();
    h.update(remote.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(2 * digest.len());
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

async fn run_command(cmd: &mut Command, what: &'static str) -> io::Result<()> {
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "`{}` failed: {}",
            what,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}
