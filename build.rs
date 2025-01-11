use gpgme::{Context, Protocol};
use isahc::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use tempfile::TempDir;

fn main() {
    let keyring_dir = Path::new("keyring");
    let keys_bin = keyring_dir.join("debian-keys.bin");
    let keys_list = keyring_dir.join("debian-keys.list");
    let keys_bin_needs_update = if !keys_bin.exists() {
        true
    } else {
        let keys_bin_metadata = keys_bin.metadata().unwrap();
        let keys_list_metadata = keys_list.metadata().unwrap();
        keys_list_metadata.modified().unwrap() > keys_bin_metadata.modified().unwrap()
    };
    if keys_bin_needs_update {
        println!("cargo:rerun-if-changed={}", keys_list.display());
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let temp_dir_path = temp_dir.path();
        let mut ctx =
            Context::from_protocol(Protocol::OpenPgp).expect("Failed to create GPGME context");
        ctx.set_engine_home_dir(temp_dir_path.as_os_str().as_encoded_bytes())
            .expect("Failed to set GPGME engine home directory");
        let file = File::open(&keys_list).expect("Failed to open keys.list");
        let reader = BufReader::new(file);
        let client = isahc::HttpClient::builder()
            .redirect_policy(isahc::config::RedirectPolicy::Limit(10))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to create an HTTP client");
        for line in reader.lines() {
            let uri = line.expect("Failed to read line from keys.list");
            let mut response = client.get(uri).expect("Failed to fetch URI");
            let key_data = response.bytes().expect("Failed to read response body");
            ctx.import(&key_data).expect("Failed to import key");
        }
        let mut export_file = File::create(&keys_bin).expect("Failed to create keys.bin");
        ctx.export(None::<&str>, gpgme::ExportMode::empty(), &mut export_file)
            .expect("Failed to export keys to keys.bin");
    }
}
