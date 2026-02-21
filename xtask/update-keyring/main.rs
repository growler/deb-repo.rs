use anyhow::{Context, Result};
use gpgme::{Context as GpgContext, Protocol};
use isahc::prelude::*;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let workspace_root = workspace_root()?;
    let keyring_dir = workspace_root.join("debrepo").join("keyring");
    let keys_bin = keyring_dir.join("keys.bin");
    let keys_list = keyring_dir.join("keys.list");

    if !needs_update(&keys_bin, &keys_list)? {
        println!("Keyring is up to date.");
        return Ok(());
    }

    let gpg_home = tempfile::Builder::new()
        .prefix("debrepo-gpg-home-")
        .tempdir()
        .context("create temp gpg home")?;

    let mut ctx = GpgContext::from_protocol(Protocol::OpenPgp).context("gpgme context")?;
    ctx.set_engine_home_dir(gpg_home.path().as_os_str().as_encoded_bytes())
        .context("set gpgme home")?;

    let client = isahc::HttpClient::builder()
        .redirect_policy(isahc::config::RedirectPolicy::Limit(10))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to create HTTP client")?;

    let list_file = File::open(&keys_list)
        .with_context(|| format!("Failed to open {}", keys_list.display()))?;

    for line in BufReader::new(list_file).lines() {
        let line = line.context("failed to read key list")?;
        let uri = line.trim();
        if uri.is_empty() || uri.starts_with('#') {
            continue;
        }

        let mut response = client
            .get(uri)
            .with_context(|| format!("Failed to fetch URI: {}", uri))?;
        let bytes = response
            .bytes()
            .with_context(|| format!("Failed to read response body: {}", uri))?;
        ctx.import(&bytes)
            .with_context(|| format!("Failed to import key: {}", uri))?;
    }

    fs::create_dir_all(&keyring_dir)
        .with_context(|| format!("ensure {}", keyring_dir.display()))?;
    let mut out_f =
        File::create(&keys_bin).with_context(|| format!("create {}", keys_bin.display()))?;
    ctx.export(None::<&str>, gpgme::ExportMode::empty(), &mut out_f)
        .context("export keys")?;

    println!("Updated keyring at {}", keys_bin.display());

    Ok(())
}

fn needs_update(keys_bin: &Path, keys_list: &Path) -> Result<bool> {
    if !keys_bin.exists() {
        return Ok(true);
    }

    let keys_bin_time = keys_bin
        .metadata()
        .with_context(|| format!("metadata {}", keys_bin.display()))?
        .modified()
        .with_context(|| format!("modified time {}", keys_bin.display()))?;

    let keys_list_time = keys_list
        .metadata()
        .with_context(|| format!("metadata {}", keys_list.display()))?
        .modified()
        .with_context(|| format!("modified time {}", keys_list.display()))?;

    Ok(keys_list_time > keys_bin_time)
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    let manifest_dir = PathBuf::from(manifest_dir);
    manifest_dir
        .parent()
        .map(PathBuf::from)
        .context("resolve workspace root")
}
