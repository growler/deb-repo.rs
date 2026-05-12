//! Parsing of `--import` argument shapes used by the CLI and of the
//! `[import.git].remote` field stored in manifests.

use std::{
    borrow::Cow,
    io,
    path::{Path, PathBuf},
};

/// Repository coordinates: a full git URL plus a revision spec.
/// No in-repo path lives here; per-blob targets are supplied to
/// `ContentProvider::materialize_git_paths`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitRepo {
    pub remote: GitRemote,
    pub revspec: GitRevSpec,
}

/// Result of parsing a unified `--import` argument.
///
/// `parse_import_target` produces this; both `cli::cmd::Init` and
/// `cli::cmd::ImportCmd` dispatch on the variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportTarget {
    /// A path to a local manifest file (relative or absolute).
    LocalPath(PathBuf),
    /// A git-sourced import: repository coordinates + in-repo manifest path.
    Git(GitImportArg),
}

/// Parsed `--import` argument when the input names a git repository: the
/// repository coordinates plus the in-repo manifest path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitImportArg {
    pub repo: GitRepo,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitRevSpec {
    Sha(String),
    Symbolic(String),
}

/// Remote identifier for `[import.git]`.
///
/// `Url` is a full git URL including the transport scheme (`https://`,
/// `http://`, or `ssh://`).  It is stored verbatim in the manifest and
/// passed directly to `git fetch`.  Transport selection is therefore
/// explicit: the same manifest will always use the same transport.
///
/// `Local` is an absolute, canonicalised filesystem path pointing at a git
/// repository (bare or working tree).  Local remotes are read directly via
/// `git -C <abs> cat-file`; no bare clone is created in the cache, and the
/// auth lookup is bypassed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitRemote {
    /// Full git URL with scheme, e.g. `https://gitlab.com/org/repo` or
    /// `ssh://git@gitlab.com/org/repo`.
    Url(String),
    /// Absolute path to a local git repository.
    Local(PathBuf),
}

impl GitRemote {
    /// Wire form used by serde and by callers that need a single string
    /// identifier.  `Url` remotes return the URL; `Local` remotes return
    /// `file://<abs>`.
    pub fn as_wire(&self) -> Cow<'_, str> {
        match self {
            GitRemote::Url(s) => Cow::Borrowed(s.as_str()),
            GitRemote::Local(p) => Cow::Owned(format!("file://{}", p.display())),
        }
    }

    /// Input used to derive `<cache>/git/<sha256>/` directory names.
    pub fn cache_key(&self) -> Cow<'_, str> {
        self.as_wire()
    }

    /// Display label used in user-facing messages.
    pub fn display_label(&self) -> Cow<'_, str> {
        self.as_wire()
    }

    /// Parses a stored `[import.git].remote` value.
    ///
    /// Accepts:
    /// - `https://[user@]host/path[.git]`
    /// - `http://[user@]host/path[.git]`
    /// - `ssh://[user@]host/path[.git]`
    /// - `file:///abs/path`
    ///
    /// Bare `host/path` identifiers (the legacy transport-agnostic form) are
    /// rejected with an error.
    pub fn parse(s: &str) -> io::Result<Self> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("file://") {
            return parse_local_path(rest).map(GitRemote::Local);
        }
        for scheme in ["https://", "http://", "ssh://"] {
            if let Some(rest) = s.strip_prefix(scheme) {
                let after_user = match rest.split_once('@') {
                    Some((user, tail)) if !user.contains('/') => tail,
                    _ => rest,
                };
                if !after_user.contains('/') {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "git remote `{}` is missing a path component after the host",
                            s
                        ),
                    ));
                }
                return Ok(GitRemote::Url(s.to_string()));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "git remote `{}` must be a full URL (`https://`, `http://`, or `ssh://`) \
                 or `file:///abs/path`",
                s
            ),
        ))
    }
}

/// Parses the unified `--import` argument.  Accepted shapes:
///
/// * `path/to/manifest.toml`                 — local manifest.
/// * `file:///absolute/path/manifest.toml`   — local manifest, absolute.
/// * `git+ssh://[git@]host/repo[.git]?...#path`
/// * `git+https://host/repo[.git]?...#path`
/// * `git+http://host/repo[.git]?...#path`
/// * `git+file:///absolute/path/to/repo?...#path`
///
/// Everything else is rejected.
pub fn parse_import_target(input: &str) -> io::Result<ImportTarget> {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix("git+") {
        return parse_import_arg_inner(rest).map(ImportTarget::Git);
    }
    if let Some(rest) = trimmed.strip_prefix("file://") {
        let path = parse_local_path(rest)?;
        return Ok(ImportTarget::LocalPath(path));
    }
    if trimmed.contains("://") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unsupported `--import` target `{}`: only `file:///<abs>` and \
`git+{{ssh,https,http,file}}://<remote>?rev=<sha>|ref=<name>#<path>` URL shapes are accepted",
                input
            ),
        ));
    }
    Ok(ImportTarget::LocalPath(PathBuf::from(trimmed)))
}

/// Parses a git-only `--import` argument (the variants under the `git+`
/// prefix in [`parse_import_target`]).
pub fn parse_import_arg(input: &str) -> io::Result<GitImportArg> {
    let trimmed = input.trim();
    let rest = trimmed.strip_prefix("git+").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "git import argument `{}` must start with the `git+` prefix \
(`git+ssh://`, `git+https://`, `git+http://`, or `git+file://`)",
                input
            ),
        )
    })?;
    parse_import_arg_inner(rest)
}

fn parse_import_arg_inner(rest_after_git_prefix: &str) -> io::Result<GitImportArg> {
    let (rest, path) = match rest_after_git_prefix.split_once('#') {
        Some((rest, path)) if !path.is_empty() => (rest, path.to_string()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "git import is missing the in-repo path; expected `git+<scheme>://<remote>?rev=<sha>|ref=<name>#<path>`",
            ));
        }
    };
    let (rest, query) = match rest.split_once('?') {
        Some((rest, query)) => (rest, Some(query)),
        None => (rest, None),
    };
    let remote = parse_remote_after_scheme(rest)?;
    let revspec = parse_query(query)?;
    let path_buf = PathBuf::from(&path);
    check_in_repo_path(&path_buf)?;
    Ok(GitImportArg {
        repo: GitRepo { remote, revspec },
        path: path_buf,
    })
}

/// Parses the scheme+host+path portion of a `git+<scheme>://...` URL,
/// returning a `GitRemote` with the full URL (scheme included).
///
/// For `https://` and `http://`, the `user@` portion is stripped: credentials
/// come from `auth.toml` via `GIT_CONFIG_*` env vars, not the URL.
/// For `ssh://`, the `user@` portion is preserved as it identifies the SSH
/// principal on the remote host.
fn parse_remote_after_scheme(s: &str) -> io::Result<GitRemote> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("https://") {
        let normalized = normalize_hosted_url(strip_user(rest))?;
        return Ok(GitRemote::Url(format!("https://{}", normalized)));
    }
    if let Some(rest) = s.strip_prefix("http://") {
        let normalized = normalize_hosted_url(strip_user(rest))?;
        return Ok(GitRemote::Url(format!("http://{}", normalized)));
    }
    if let Some(rest) = s.strip_prefix("ssh://") {
        let normalized = normalize_hosted_url(rest)?;
        return Ok(GitRemote::Url(format!("ssh://{}", normalized)));
    }
    if let Some(rest) = s.strip_prefix("file://") {
        return parse_local_path(rest).map(GitRemote::Local);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "unsupported git URL scheme in `git+{}` (expected `ssh`, `https`, `http`, or `file`)",
            s
        ),
    ))
}

/// Strips the optional `user@` prefix from the host portion of an HTTP/HTTPS URL.
fn strip_user(s: &str) -> &str {
    match s.split_once('@') {
        Some((user, host_rest)) if !user.contains('/') => host_rest,
        _ => s,
    }
}

/// Normalises the `[user@]host/path[.git]` portion of a git URL: strips a
/// trailing `.git` suffix and trailing slashes, then validates that a
/// non-empty host and path are present.  Does not strip any `user@` prefix
/// (callers do that before calling this function when desired).
fn normalize_hosted_url(s: &str) -> io::Result<String> {
    let s = s.trim_end_matches('/');
    let s = s.strip_suffix(".git").unwrap_or(s);
    let s = s.trim_end_matches('/');
    // Find the first `/` to separate host (possibly `user@host`) from path.
    let slash = s.find('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("git URL `{}` is missing a path component after the host", s),
        )
    })?;
    let host_part = &s[..slash];
    let path_part = s[slash + 1..].trim_start_matches('/');
    // Extract the hostname, stripping any `user@` prefix for validation only.
    let hostname = host_part.rsplit('@').next().unwrap_or(host_part);
    if hostname.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "git URL host must not be empty",
        ));
    }
    if path_part.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "git URL for host `{}` is missing a repository path",
                hostname
            ),
        ));
    }
    Ok(format!("{}/{}", host_part, path_part))
}

fn parse_local_path(rest_after_file_scheme: &str) -> io::Result<PathBuf> {
    let path_str = rest_after_file_scheme;
    if path_str.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "`file://` target has no path component",
        ));
    }
    if !path_str.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "`file://` target must be absolute (got `file://{}`); use `file:///<abs>`",
                path_str
            ),
        ));
    }
    let path = PathBuf::from(path_str);
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "`file://` target `{}` may not contain `..` components",
                    path.display()
                ),
            ));
        }
    }
    std::fs::canonicalize(&path)
        .map_err(|err| io::Error::new(err.kind(), format!("`file://{}`: {}", path.display(), err)))
}

fn parse_query(query: Option<&str>) -> io::Result<GitRevSpec> {
    let query = query.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "git import requires `?rev=<sha-or-ref>` or `?ref=<name>`",
        )
    })?;
    let mut rev = None;
    let mut sym_ref = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid git query parameter `{}`", pair),
            )
        })?;
        match k {
            "rev" => rev = Some(v.to_string()),
            "ref" | "branch" | "tag" => sym_ref = Some(v.to_string()),
            "path" => { /* accepted but the in-repo path lives in the fragment */ }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown git query parameter `{}`", other),
                ));
            }
        }
    }
    match (rev, sym_ref) {
        (Some(rev), None) => {
            if super::is_full_sha1(&rev) {
                Ok(GitRevSpec::Sha(rev.to_lowercase()))
            } else {
                Ok(GitRevSpec::Symbolic(rev))
            }
        }
        (None, Some(name)) => Ok(GitRevSpec::Symbolic(name)),
        (Some(_), Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "git import accepts either `rev` or `ref/branch/tag`, not both",
        )),
        (None, None) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "git import is missing `?rev=<sha-or-ref>` or `?ref=<name>`",
        )),
    }
}

/// Normalise an in-repo path to a Unix-style relative path; reject
/// absolute components and `..` traversal.
pub(crate) fn check_in_repo_path(path: &Path) -> io::Result<()> {
    use std::path::Component;
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "git import path must not be empty",
        ));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "git import path `{}` may not contain `..` traversal",
                        path.display()
                    ),
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("git import path `{}` must be relative", path.display()),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_style_https() {
        let a = parse_import_arg(
            "git+https://gitlab.com/myorg/repo.git?rev=v1.2.3#system/Manifest.toml",
        )
        .unwrap();
        assert_eq!(
            a.repo.remote,
            GitRemote::Url("https://gitlab.com/myorg/repo".into())
        );
        assert_eq!(a.repo.revspec, GitRevSpec::Symbolic("v1.2.3".into()));
        assert_eq!(a.path, PathBuf::from("system/Manifest.toml"));
    }

    #[test]
    fn parse_http_form() {
        let a = parse_import_arg("git+http://example.invalid/o/r?ref=main#m.toml").unwrap();
        assert_eq!(
            a.repo.remote,
            GitRemote::Url("http://example.invalid/o/r".into())
        );
    }

    #[test]
    fn parse_ssh_form() {
        let a =
            parse_import_arg("git+ssh://git@gitlab.com/myorg/repo.git?ref=main#m.toml").unwrap();
        assert_eq!(
            a.repo.remote,
            GitRemote::Url("ssh://git@gitlab.com/myorg/repo".into())
        );
        assert_eq!(a.repo.revspec, GitRevSpec::Symbolic("main".into()));
        assert_eq!(a.path, PathBuf::from("m.toml"));
    }

    #[test]
    fn parse_https_strips_embedded_user() {
        // Credentials in HTTPS URLs are stripped; auth comes from auth.toml.
        let a =
            parse_import_arg("git+https://gitlab-ci-token:sometoken@gitlab.com/o/r?rev=abc#m.toml")
                .unwrap();
        assert_eq!(
            a.repo.remote,
            GitRemote::Url("https://gitlab.com/o/r".into())
        );
    }

    #[test]
    fn parse_full_sha() {
        let sha = "5b1f9c2a4d3e0f8b7a6c9d2e1f0a3b4c5d6e7f80";
        let a =
            parse_import_arg(&format!("git+https://gitlab.com/o/r?rev={}#m.toml", sha)).unwrap();
        assert_eq!(a.repo.revspec, GitRevSpec::Sha(sha.to_string()));
    }

    #[test]
    fn missing_path_rejected() {
        assert!(parse_import_arg("git+https://gitlab.com/o/r?rev=abc").is_err());
    }

    #[test]
    fn missing_rev_rejected() {
        assert!(parse_import_arg("git+https://gitlab.com/o/r#m.toml").is_err());
    }

    #[test]
    fn scp_form_rejected() {
        assert!(parse_import_arg("git@gitlab.com:myorg/repo.git?rev=abcdef#m.toml").is_err());
    }

    #[test]
    fn bare_host_path_rejected() {
        assert!(parse_import_arg("gitlab.com/myorg/repo?rev=abc#m.toml").is_err());
    }

    #[test]
    fn plain_https_without_git_prefix_rejected() {
        assert!(parse_import_arg("https://gitlab.com/o/r?rev=abc#m.toml").is_err());
    }

    #[test]
    fn unknown_scheme_rejected() {
        assert!(parse_import_arg("git+ftp://gitlab.com/o/r?rev=abc#m.toml").is_err());
    }

    #[test]
    fn parse_target_local_path_relative() {
        let t = parse_import_target("path/to/Manifest.toml").unwrap();
        assert_eq!(
            t,
            ImportTarget::LocalPath(PathBuf::from("path/to/Manifest.toml"))
        );
    }

    #[test]
    fn parse_target_file_url_local() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("Manifest.toml");
        std::fs::write(&manifest_path, "").unwrap();
        let canonical = std::fs::canonicalize(&manifest_path).unwrap();
        let url = format!("file://{}", canonical.display());
        let t = parse_import_target(&url).unwrap();
        assert_eq!(t, ImportTarget::LocalPath(canonical));
    }

    #[test]
    fn parse_target_file_url_requires_absolute() {
        assert!(parse_import_target("file://relative/Manifest.toml").is_err());
    }

    #[test]
    fn parse_target_git_file_url() {
        // `git+file://` requires an existing directory; create a temp
        // git repo so canonicalize succeeds.
        let dir = tempfile::tempdir().unwrap();
        let repo_path = dir.path().to_path_buf();
        let url = format!(
            "git+file://{}?rev=abc#system/Manifest.toml",
            repo_path.display()
        );
        let t = parse_import_target(&url).unwrap();
        let canonical = std::fs::canonicalize(&repo_path).unwrap();
        let ImportTarget::Git(arg) = t else {
            panic!("expected Git target");
        };
        assert_eq!(arg.repo.remote, GitRemote::Local(canonical));
        assert_eq!(arg.path, PathBuf::from("system/Manifest.toml"));
    }

    #[test]
    fn parse_target_unknown_url_rejected() {
        assert!(parse_import_target("ftp://example.invalid/m.toml").is_err());
        assert!(parse_import_target("https://gitlab.com/o/r?rev=abc#m.toml").is_err());
        assert!(parse_import_target("ssh://git@gitlab.com/o/r?rev=abc#m.toml").is_err());
        // The scp-like form has no `://`; it is accepted as a literal
        // local path here and rejected later by `set_import`.
        let target = parse_import_target("git@gitlab.com:o/r?rev=abc#m.toml").unwrap();
        assert!(matches!(target, ImportTarget::LocalPath(_)));
    }

    #[test]
    fn check_in_repo_path_rejects_traversal() {
        assert!(check_in_repo_path(Path::new("../escape")).is_err());
        assert!(check_in_repo_path(Path::new("/abs/path")).is_err());
        assert!(check_in_repo_path(Path::new("dir/file.toml")).is_ok());
    }

    #[test]
    fn git_remote_parse_url() {
        assert_eq!(
            GitRemote::parse("https://gitlab.com/o/r").unwrap(),
            GitRemote::Url("https://gitlab.com/o/r".into())
        );
        assert_eq!(
            GitRemote::parse("ssh://git@gitlab.com/o/r").unwrap(),
            GitRemote::Url("ssh://git@gitlab.com/o/r".into())
        );
    }

    #[test]
    fn git_remote_parse_local() {
        let dir = tempfile::tempdir().unwrap();
        let value = format!("file://{}", dir.path().display());
        let remote = GitRemote::parse(&value).unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(remote, GitRemote::Local(canonical));
    }

    #[test]
    fn git_remote_parse_rejects_bare_host_path() {
        // Legacy transport-agnostic form must not be accepted.
        assert!(GitRemote::parse("gitlab.com/o/r").is_err());
    }
}
