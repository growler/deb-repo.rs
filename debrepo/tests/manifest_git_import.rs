//! End-to-end test for `[import.git]`-sourced manifest imports.
//!
//! Drives a real `git` subprocess against a local bare repo
//! (no network).  Skipped automatically when `git` is not on `PATH`.

#![allow(clippy::missing_safety_doc)]

mod common;

use {
    common::{create_locked_manifest, one, ARCH},
    debrepo::{
        auth::AuthProvider,
        content::{HostCache, HostCacheOptions},
        git::{GitRemote, GitRevSpec},
        Manifest,
    },
    std::{
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::Arc,
    },
};

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_git(workdir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(workdir)
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()
        .expect("spawn git");
    assert!(
        status.success(),
        "git {} failed in {}",
        args.join(" "),
        workdir.display()
    );
}

/// Returns the resolved commit SHA of the current HEAD in `workdir`.
fn head_sha(workdir: &Path) -> String {
    let out = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(workdir)
        .output()
        .expect("git rev-parse");
    assert!(out.status.success(), "git rev-parse HEAD failed");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

/// Builds a bare repo at `<dir>/imported.git` whose tree contains a
/// locked imported manifest under `system/imported.toml`.  Returns
/// `(bare_repo_path, head_sha)`.
fn build_bare_repo_with_manifest(dir: &Path) -> (PathBuf, String) {
    let bare = dir.join("imported.git");
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    run_git(dir, &["init", "--bare", "-q", bare.to_str().unwrap()]);
    run_git(&work, &["init", "-q", "-b", "main"]);
    run_git(&work, &["remote", "add", "origin", bare.to_str().unwrap()]);

    let manifest_dir = work.join("system");
    std::fs::create_dir_all(&manifest_dir).unwrap();
    let manifest_path = manifest_dir.join("imported.toml");
    smol::block_on(async {
        let provider = common::TestProvider::new();
        create_locked_manifest(&manifest_path, &provider)
            .await
            .expect("create imported manifest");
    });

    run_git(&work, &["add", "-A"]);
    run_git(&work, &["commit", "-q", "-m", "import seed"]);
    run_git(&work, &["push", "-q", "origin", "main"]);
    let sha = head_sha(&work);

    let bare = std::fs::canonicalize(&bare).unwrap();
    (bare, sha)
}

fn make_host_cache(cache_root: &Path) -> HostCache {
    let auth = AuthProvider::new::<&str>(None).expect("auth");
    HostCache::new(
        cache_root,
        Arc::new(auth),
        HostCacheOptions {
            cache_http: false,
            insecure: false,
            force_http11: false,
            timeout: None,
        },
    )
}

#[test]
fn set_import_git_round_trip_against_local_bare_repo() {
    if !git_available() {
        eprintln!("skipping: git not on PATH");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let (bare, sha) = build_bare_repo_with_manifest(dir.path());

    let cache_root = dir.path().join("cache");
    std::fs::create_dir_all(&cache_root).expect("create cache root");
    let fetcher = make_host_cache(&cache_root);

    // Use a git+file:// URL so the test exercises the Local branch of
    // GitFetcher without needing network access.
    let remote = GitRemote::Local(bare.clone());

    let downstream_path = dir.path().join("downstream.toml");
    let mut downstream = Manifest::new(&downstream_path, ARCH, None);
    smol::block_on(async {
        downstream
            .set_import_git(
                &fetcher,
                remote,
                GitRevSpec::Sha(sha.clone()),
                Path::new("system/imported.toml"),
                std::iter::empty::<String>(),
            )
            .await
            .expect("set_import_git");
        let provider = common::TestProvider::new();
        downstream
            .resolve(one(), &provider)
            .await
            .expect("resolve downstream");
        downstream.store().await.expect("store downstream");
    });

    // Reload through the public API to confirm round-trip.
    smol::block_on(async {
        let (loaded, has_valid_lock) = Manifest::from_file(&downstream_path, ARCH, &fetcher)
            .await
            .expect("load");
        assert!(has_valid_lock, "downstream lock must be valid after store");
        let _ = loaded;
    });
}

#[test]
fn import_git_rejects_non_sha_rev_in_lock_load() {
    // Manually craft a manifest with a non-SHA `rev` to confirm the
    // load-time validation kicks in.  The URL doesn't need to be
    // reachable — validation fires before any fetch attempt.
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    std::fs::write(
        &manifest_path,
        r#"
[import]
hash = "blake3-1XY3lOEk7vDIvRRm2vZGQ7VMUbDoMbQuPwcxRKNFi5o="
specs = []

[import.git]
remote = "https://git.test/repo"
rev    = "main"
path   = "Manifest.toml"
"#,
    )
    .unwrap();

    let cache_root = dir.path().join("cache");
    std::fs::create_dir_all(&cache_root).expect("create cache root");
    let fetcher = make_host_cache(&cache_root);

    let err = smol::block_on(async {
        match Manifest::from_file(&manifest_path, ARCH, &fetcher).await {
            Ok(_) => panic!("non-sha rev must be rejected at load"),
            Err(err) => err,
        }
    });
    let msg = err.to_string();
    assert!(
        msg.contains("not a 40-hex commit SHA"),
        "expected validation error, got: {}",
        msg,
    );
}
