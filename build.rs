use isahc::prelude::*;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;
use openpgp::serialize::Marshal;
use sequoia_openpgp as openpgp;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn main() {
    let keyring_dir = Path::new("keyring");
    let keys_bin = keyring_dir.join("keys.bin");
    let keys_list = keyring_dir.join("keys.list");
    let keys_bin_needs_update = if !keys_bin.exists() {
        true
    } else {
        let keys_bin_metadata = keys_bin.metadata().unwrap();
        let keys_list_metadata = keys_list.metadata().unwrap();
        keys_list_metadata.modified().unwrap() > keys_bin_metadata.modified().unwrap()
    };
    if keys_bin_needs_update {
        println!("cargo:rerun-if-changed={}", keys_list.display());
        let client = isahc::HttpClient::builder()
            .redirect_policy(isahc::config::RedirectPolicy::Limit(10))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to create an HTTP client");
        let mut export_file = File::create(&keys_bin).expect("Failed to create keys.bin");
        BufReader::new(File::open(&keys_list).expect("Failed to open keys.list"))
            .lines()
            .map(|l| l.expect("Failed to read line from keys.list"))
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|uri| {
                client
                    .get(&uri)
                    .expect(&format!("Failed to fetch URI: {}", uri))
                    .bytes()
                    .expect(&format!("Failed to read response body: {}", uri))
            })
            .flat_map(|data| {
                CertParser::from_reader(std::io::Cursor::new(data))
                    .expect("Failed to create certificate parser")
                    .map(|res| res.expect("Failed to parse certificate"))
            })
            .for_each(|cert| {
                cert.serialize(&mut export_file)
                    .expect("Failed to write certificate to keys.bin")
            });
    }
}
