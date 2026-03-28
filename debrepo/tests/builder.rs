mod common;

use {
    clap::Parser,
    common::{one, TestConfig, ARCH},
    debrepo::{
        auth::AuthProvider,
        cli::{cmd, Command},
        content::{ContentProvider, HostCache},
        HttpTransport, Manifest,
    },
    std::path::{Path, PathBuf},
};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("deb")
        .join(name)
}

fn new_host_cache() -> HostCache {
    HostCache::new(
        HttpTransport::new(AuthProvider::new::<&str>(None).expect("auth"), false, false),
        Option::<&Path>::None,
    )
}

async fn create_build_manifest(path: &Path, local_deb: &Path) {
    let cache = new_host_cache();
    let mut manifest = Manifest::new(path, ARCH, None);
    let (file, ctrl) = cache
        .ensure_deb("local.deb", local_deb)
        .await
        .expect("index local deb");
    manifest
        .add_local_package(file, ctrl, None)
        .expect("add local package");
    manifest
        .add_requirements(None, ["fixture-minimal"], None)
        .expect("require local package");
    manifest
        .set_build_env(
            None,
            [("CUSTOM_ENV".to_string(), "custom-value".to_string())]
                .into_iter()
                .collect(),
        )
        .expect("set build env");
    manifest
        .set_build_script(None, Some("echo from fake script\n".to_string()))
        .expect("set build script");
    manifest
        .resolve(one(), &cache)
        .await
        .expect("resolve manifest");
    manifest.store().await.expect("store manifest");
}

#[test]
fn cli_build_reports_podman_root_path_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let local_deb = dir.path().join("local.deb");
    std::fs::copy(fixture_path("minimal-none.deb"), &local_deb).expect("copy deb fixture");
    smol::block_on(create_build_manifest(&manifest_path, &local_deb));
    let conf = TestConfig::new(manifest_path, new_host_cache());

    let root_file = dir.path().join("not-a-directory");
    std::fs::write(&root_file, b"root file").expect("write root file");
    let err = cmd::Build::try_parse_from([
        "build",
        "--executor",
        "podman",
        "--path",
        &root_file.to_string_lossy(),
    ])
    .expect("parse build")
    .exec(&conf)
    .expect_err("file root must fail");
    assert!(err.to_string().contains("failed to create root directory"));
}
