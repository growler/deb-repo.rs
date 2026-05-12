//! Git-sourced manifest imports.
//!
//! `[import.git]` references a manifest by **repository URL + commit +
//! path-within-repo**.  The transport is part of the URL stored in the
//! manifest; the same manifest always uses the same transport.
//!
//! Implementation: subprocess `git` + `cat-file --batch` for blob reads.
//! Requires `git >= 2.30` on `PATH`.
//!
//! ```text
//! Manifest authors write:
//!     [import.git]
//!     remote = "https://gitlab.com/myorg/system-manifests"
//!     rev    = "5b1f9c2a..."
//!     ref    = "release-2024.10"   # optional
//!     path   = "system/Manifest.toml"
//! ```
//!
//! HTTPS git auth comes from `[[auth]]` entries in `auth.toml` keyed by
//! hostname, applied via `GIT_CONFIG_*` environment variables so secrets
//! never appear on argv.  SSH delegates entirely to the system `ssh`
//! (honours `~/.ssh/config`, ssh-agent, smart cards, etc.).
//! For URL substitution use git's own `url.<base>.insteadOf` mechanism
//! in `~/.gitconfig` or `$GIT_CONFIG_GLOBAL`.

mod fetch;
pub(crate) mod url;

pub use {
    fetch::{GitFetcher, MaterializedGitRepo},
    url::{
        parse_import_arg, parse_import_target, GitImportArg, GitRemote, GitRepo, GitRevSpec,
        ImportTarget,
    },
};

/// Returns true if `s` looks like a 40-character lowercase-hex SHA-1 commit.
pub fn is_full_sha1(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
