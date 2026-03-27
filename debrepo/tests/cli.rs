mod common;

use {
    clap::Parser,
    common::{
        create_locked_imported_manifest, create_locked_manifest, read_manifest_doc,
        update_manifest_file, CurrentDirGuard, TestConfig, TestProvider, ARCH,
    },
    debrepo::{cli::cmd, cli::Command, Manifest},
    std::{path::PathBuf, sync::atomic::AtomicUsize, sync::Arc},
};

#[test]
fn init_import_creates_manifest_with_import_and_no_local_archives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let manifest_path = dir.path().join("downstream.toml");
    let conf = TestConfig::new(manifest_path.clone(), TestProvider::new());

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let _cwd = CurrentDirGuard::set(dir.path());
    let cmd = cmd::Init::try_parse_from(["init", "--import", "imported.toml"]).expect("parse init");
    cmd.exec(&conf).expect("init from import");

    let doc = read_manifest_doc(&manifest_path);
    let import = doc["import"].as_table().expect("import table");
    assert_eq!(
        import.get("path").and_then(|item| item.as_str()),
        Some("imported.toml")
    );
    assert!(import
        .get("specs")
        .and_then(|item| item.as_array())
        .map(|specs| specs.is_empty())
        .unwrap_or(true));
    assert!(doc.get("archive").is_none());
    assert!(manifest_path
        .with_extension(format!("{}.lock", ARCH))
        .exists());
}

#[test]
fn init_import_exports_requested_specs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let manifest_path = dir.path().join("downstream.toml");
    let conf = TestConfig::new(manifest_path.clone(), TestProvider::new());

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let _cwd = CurrentDirGuard::set(dir.path());
    let cmd = cmd::Init::try_parse_from(["init", "--import", "imported.toml", "--spec", "base"])
        .expect("parse init");
    cmd.exec(&conf).expect("init from import");

    update_manifest_file(&manifest_path, |doc| {
        doc["spec"]["extends"] = toml_edit::value("base");
    });

    smol::block_on(async {
        let (mut manifest, _) = Manifest::from_file(&manifest_path, ARCH)
            .await
            .expect("load manifest");
        manifest
            .resolve(common::one(), &TestProvider::new())
            .await
            .expect("resolve with imported parent");
    });
}

#[test]
fn init_import_rejects_missing_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let manifest_path = dir.path().join("downstream.toml");
    let conf = TestConfig::new(manifest_path, TestProvider::new());

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let _cwd = CurrentDirGuard::set(dir.path());
    let cmd = cmd::Init::try_parse_from(["init", "--import", "imported.toml", "--spec", "missing"])
        .expect("parse init");
    let err = cmd
        .exec(&conf)
        .expect_err("missing imported spec must fail");
    assert!(err
        .to_string()
        .contains("imported manifest imported.toml does not contain spec missing"));
}

#[test]
fn init_import_requires_locked_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("downstream.toml");
    let imported_path = dir.path().join("imported.toml");
    let conf = TestConfig::new(manifest_path, TestProvider::new());

    let doc = toml_edit::DocumentMut::new();
    std::fs::write(&imported_path, doc.to_string()).expect("write import file");

    let _cwd = CurrentDirGuard::set(dir.path());
    let cmd = cmd::Init::try_parse_from(["init", "--import", "imported.toml"]).expect("parse init");
    let err = cmd.exec(&conf).expect_err("unlocked import must fail");
    assert!(err
        .to_string()
        .contains("imported manifest imported.toml is not locked; lock if first"));
}

#[test]
fn cli_artifact_add_and_stage_rebases_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    std::fs::write(shared_dir.join("data.blob"), b"blob").expect("write artifact");
    let manifest_path = frontend_dir.join("Manifest.toml");
    let provider = TestProvider::new();

    smol::block_on(create_locked_manifest(&manifest_path, &provider)).expect("create manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let cmd = cmd::ArtifactAdd::try_parse_from([
        "artifact-add",
        "--stage",
        "shared/data.blob",
        "/opt/data.blob",
    ])
    .expect("parse artifact add");
    cmd.exec(&conf).expect("artifact add");

    let doc = read_manifest_doc(&manifest_path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    let staged = stage
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(staged, vec!["../shared/data.blob"]);
    let artifacts = doc["artifact"].as_table().expect("artifact table");
    assert!(artifacts.get("../shared/data.blob").is_some());
}

#[test]
fn cli_stage_and_unstage_rebase_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    std::fs::write(shared_dir.join("data.blob"), b"blob").expect("write artifact");
    let manifest_path = frontend_dir.join("Manifest.toml");
    let provider = TestProvider::new();

    smol::block_on(create_locked_manifest(&manifest_path, &provider)).expect("create manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let add =
        cmd::ArtifactAdd::try_parse_from(["artifact-add", "shared/data.blob", "/opt/data.blob"])
            .expect("parse artifact add");
    add.exec(&conf).expect("artifact add");

    let stage = cmd::Stage::try_parse_from(["stage", "shared/data.blob"]).expect("parse stage");
    stage.exec(&conf).expect("stage");
    let doc = read_manifest_doc(&manifest_path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    let staged = stage
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(staged, vec!["../shared/data.blob"]);

    let unstage = cmd::Unstage::try_parse_from(["unstage", "shared/data.blob"]).expect("parse");
    unstage.exec(&conf).expect("unstage");
    let doc = read_manifest_doc(&manifest_path);
    assert!(doc.get("spec").and_then(|spec| spec.get("stage")).is_none());
}

#[test]
fn cli_deb_add_and_remove_rebase_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    std::fs::write(shared_dir.join("pkg.deb"), b"not-a-real-deb").expect("write deb");
    let manifest_path = frontend_dir.join("Manifest.toml");
    let provider = TestProvider::new();

    smol::block_on(create_locked_manifest(&manifest_path, &provider)).expect("create manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let add = cmd::DebAdd::try_parse_from(["deb-add", "shared/pkg.deb"]).expect("parse");
    add.exec(&conf).expect("deb add");
    let doc = read_manifest_doc(&manifest_path);
    let locals = doc["local"].as_array_of_tables().expect("locals");
    assert_eq!(
        locals
            .get(0)
            .and_then(|entry| entry.get("path"))
            .and_then(|v| v.as_str()),
        Some("../shared/pkg.deb")
    );

    let remove = cmd::DebRemove::try_parse_from(["deb-remove", "shared/pkg.deb"]).expect("parse");
    remove.exec(&conf).expect("deb remove");
    let doc = read_manifest_doc(&manifest_path);
    assert!(doc.get("local").is_none());
}

#[test]
fn cli_init_import_rebases_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    let provider = TestProvider::new();
    let manifest_path = frontend_dir.join("Manifest.toml");

    smol::block_on(create_locked_imported_manifest(&shared_dir, &provider))
        .expect("create imported manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let cmd = cmd::Init::try_parse_from(["init", "--import", "shared/imported.toml"])
        .expect("parse init");
    cmd.exec(&conf).expect("init import");

    let doc = read_manifest_doc(&manifest_path);
    assert_eq!(
        doc["import"]["path"].as_str(),
        Some("../shared/imported.toml")
    );
}

#[test]
fn cli_import_cmd_rebases_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    let provider = TestProvider::new();
    let manifest_path = frontend_dir.join("Manifest.toml");

    smol::block_on(create_locked_manifest(&manifest_path, &provider)).expect("create manifest");
    smol::block_on(create_locked_imported_manifest(&shared_dir, &provider))
        .expect("create imported manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let cmd =
        cmd::ImportCmd::try_parse_from(["import", "shared/imported.toml"]).expect("parse import");
    cmd.exec(&conf).expect("import");

    let doc = read_manifest_doc(&manifest_path);
    assert_eq!(
        doc["import"]["path"].as_str(),
        Some("../shared/imported.toml")
    );
}

#[test]
fn cli_init_rebases_signed_by_keyring_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let keys_dir = workspace.join("keys");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&keys_dir).expect("create keys");
    std::fs::write(keys_dir.join("repo.gpg"), b"dummy-keyring").expect("write keyring");
    let manifest_path = frontend_dir.join("Manifest.toml");
    let release_fetches = Arc::new(AtomicUsize::new(0));

    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(
        PathBuf::from("frontend/Manifest.toml"),
        TestProvider::with_release_counter(Arc::clone(&release_fetches)),
    );

    let cmd = cmd::Init::try_parse_from([
        "init",
        "https://example.test/repo",
        "--suite",
        "stable",
        "--components",
        "main",
        "--signed-by",
        "keys/repo.gpg",
        "--no-verify",
    ])
    .expect("parse init");
    cmd.exec(&conf).expect("init archive");

    let doc = read_manifest_doc(&manifest_path);
    let archives = doc["archive"].as_array_of_tables().expect("archive array");
    assert_eq!(
        archives
            .get(0)
            .and_then(|entry| entry.get("signed-by"))
            .and_then(|v| v.as_str()),
        Some("../keys/repo.gpg")
    );
}
