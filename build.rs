use isahc::prelude::*;
use gpgme::{Context, Protocol};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

fn main() {
    let keyring_dir = Path::new("keyring");
    let keys_bin = keyring_dir.join("keys.bin");
    let keys_list = keyring_dir.join("keys.list");

    let needs_update = !keys_bin.exists() || {
        let kb = keys_bin.metadata().unwrap().modified().unwrap();
        let kl = keys_list.metadata().unwrap().modified().unwrap();
        kl > kb
    };

    if !needs_update {
        return;
    }

    println!("cargo:rerun-if-changed={}", keys_list.display());

    let out = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let gpg_home = Path::new(&out).join("gpg-home-build");
    fs::create_dir_all(&gpg_home).expect("create gpg home");

    let mut ctx = Context::from_protocol(Protocol::OpenPgp).expect("gpgme context");
    ctx.set_engine_home_dir(gpg_home.as_os_str().as_encoded_bytes()).expect("set engine home");

    let client = isahc::HttpClient::builder()
        .redirect_policy(isahc::config::RedirectPolicy::Limit(10))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to create an HTTP client");

    BufReader::new(File::open(&keys_list).expect("Failed to open keys.list"))
        .lines()
        .map(|l| l.expect("failed to read key list").trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|uri| {
            client
                .get(&uri)
                .expect(&format!("Failed to fetch URI: {}", uri))
                .bytes()
                .expect(&format!("Failed to read response body: {}", uri))
        })
        .for_each(|data| {
            ctx.import(&data).expect("Failed to import key");
        });

    fs::create_dir_all(keyring_dir).expect("ensure keyring dir");
    let mut out_f = File::create(&keys_bin).expect("create keys.bin");
    ctx.export(None::<&str>, gpgme::ExportMode::empty(), &mut out_f)
        .expect("export keys");

    let _ = fs::remove_dir_all(&gpg_home);
}
