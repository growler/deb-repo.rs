mod common;

use {
    chrono::{TimeZone, Utc},
    common::{
        create_locked_imported_manifest, make_archive, persist_manifest, read_manifest_doc,
        TestProvider, ARCH,
    },
    debrepo::{
        artifact::ArtifactArg, control::MutableControlStanza, hash::Hash, Manifest, RepositoryFile,
        Snapshot, SnapshotId,
    },
    std::path::Path,
};

fn local_package_ctrl(path: &str, size: u64) -> MutableControlStanza {
    let mut ctrl = MutableControlStanza::new();
    ctrl.set("Package", "local-test");
    ctrl.set("Version", "1.0");
    ctrl.set("Architecture", ARCH);
    ctrl.set("Filename", path.to_string());
    ctrl.set("Size", size.to_string());
    ctrl.set("SHA256", Hash::default().to_hex());
    ctrl
}

fn snapshot_id() -> SnapshotId {
    SnapshotId(Utc.with_ymd_and_hms(2024, 3, 5, 12, 34, 56).unwrap())
}

#[test]
fn manifest_public_apis_reject_invalid_and_reserved_spec_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);

    let err = manifest
        .add_spec(Some("bad name"))
        .expect_err("reject invalid name");
    assert!(err
        .to_string()
        .contains("only alphanumeric characters, '-' and '_' are allowed"));

    let err = manifest
        .spec_update_env_block(Some("include"), "FOO=bar\n".to_string())
        .expect_err("reject reserved name");
    assert!(err.to_string().contains("invalid spec name \"include\""));
}

#[test]
fn set_import_roundtrips_manifest_doc_and_reloads_with_valid_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("downstream.toml");

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");

        let mut manifest = Manifest::new(&path, ARCH, None);
        manifest
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
        manifest
            .set_import(Path::new("./imported.toml"), ["base"])
            .await
            .expect("replace import");
        manifest
            .resolve(common::one(), &provider)
            .await
            .expect("resolve");
        manifest.store().await.expect("store");

        let (loaded, has_valid_lock) = Manifest::from_file(&path, ARCH).await.expect("reload");
        assert!(has_valid_lock);
        assert!(loaded.spec_ids().next().is_none());
    });

    let doc = read_manifest_doc(&path);
    let import = doc["import"].as_table().expect("import table");
    assert_eq!(
        import.get("path").and_then(|item| item.as_str()),
        Some("./imported.toml")
    );
    let specs = import
        .get("specs")
        .and_then(|item| item.as_array())
        .expect("specs");
    assert_eq!(
        specs
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["base"]
    );
}

#[test]
fn from_file_loads_default_spec_and_artifacts_from_handwritten_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");

    std::fs::write(
        &path,
        concat!(
            "[artifact.note]\n",
            "type = \"text\"\n",
            "target = \"/etc/note\"\n",
            "text = \"hello\"\n",
            "\n",
            "[spec]\n",
            "include = [\"foo (>= 1.0)\"]\n",
            "exclude = [\"bar (<< 2.0)\"]\n",
            "stage = [\"note\"]\n",
            "meta = [\"owner:ops\"]\n",
            "build-script = \"echo hi\\n\"\n",
            "\n",
            "[spec.build-env]\n",
            "FOO = \"bar\"\n",
        ),
    )
    .expect("write manifest");

    let (manifest, has_valid_lock) =
        smol::block_on(Manifest::from_file(&path, ARCH)).expect("load manifest");
    assert!(!has_valid_lock);
    let spec = manifest.lookup_spec(None).expect("default spec");
    assert_eq!(spec.build_env().get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(spec.get_meta("owner").expect("meta"), Some("ops"));
    assert_eq!(spec.build_script(), Some("echo hi\n"));
    assert!(manifest.artifact("note").is_some());
}

#[test]
fn from_file_rejects_non_utf8_manifest_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(&path, [0xff, 0xfe, 0xfd]).expect("write invalid utf8");

    let err = match smol::block_on(Manifest::from_file(&path, ARCH)) {
        Ok(_) => panic!("reject invalid utf8"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("failed to read manifest"));
}

#[test]
fn from_file_rejects_invalid_default_spec_meta_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(&path, "[spec]\nmeta = [\"owner\"]\n").expect("write manifest");

    let err = match smol::block_on(Manifest::from_file(&path, ARCH)) {
        Ok(_) => panic!("reject invalid meta"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("invalid meta entry in spec <default>"));
}

#[test]
fn removing_artifact_from_one_spec_keeps_shared_artifact_definition() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("Manifest.toml");
    let artifact_path = dir.path().join("artifact-dir");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");

    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };

    let mut manifest = Manifest::new(&path, ARCH, None);
    smol::block_on(async {
        manifest
            .add_artifact(Some("base"), &arg, Some("artifact-comment"), &provider)
            .await
            .expect("add artifact");
    });
    manifest
        .add_stage_items(Some("custom"), vec!["artifact-dir".to_string()], None)
        .expect("share artifact");
    manifest
        .remove_artifact(Some("base"), "artifact-dir")
        .expect("remove from base");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let base = doc["spec"]["base"].as_table().expect("base spec");
    assert!(base.get("stage").is_none());
    let custom_stage = doc["spec"]["custom"]["stage"]
        .as_array()
        .expect("custom stage");
    assert_eq!(
        custom_stage
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["artifact-dir"]
    );
    assert!(doc["artifact"]["artifact-dir"].is_table());
}

#[test]
fn remove_artifact_reports_missing_stage_entry_for_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("Manifest.toml");
    let artifact_path = dir.path().join("artifact-dir");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");

    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };

    let mut manifest = Manifest::new(&path, ARCH, None);
    smol::block_on(async {
        manifest
            .add_artifact(Some("base"), &arg, None, &provider)
            .await
            .expect("add artifact");
    });
    manifest.add_spec(Some("custom")).expect("add custom");

    let err = manifest
        .remove_artifact(Some("custom"), "artifact-dir")
        .expect_err("reject missing stage entry");
    assert!(err
        .to_string()
        .contains("artifact artifact-dir not found in spec custom"));
}

#[test]
fn upsert_text_artifact_is_noop_when_content_is_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);

    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "hello".to_string(),
            None,
            Some("amd64".to_string()),
        )
        .expect("create text artifact");
    smol::block_on(async {
        manifest
            .resolve(common::one(), &provider)
            .await
            .expect("resolve");
        manifest.store().await.expect("store");
    });
    let before = std::fs::read_to_string(&path).expect("read before");

    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "hello".to_string(),
            None,
            Some("amd64".to_string()),
        )
        .expect("noop update");
    smol::block_on(manifest.store()).expect("store unchanged manifest");

    let after = std::fs::read_to_string(&path).expect("read after");
    assert_eq!(before, after);
}

#[test]
fn set_spec_meta_replaces_existing_entry_without_duplication() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);

    manifest
        .set_spec_meta(Some("custom"), "owner", "ops")
        .expect("set first meta");
    manifest
        .set_spec_meta(Some("custom"), "owner", "release")
        .expect("replace meta");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let meta = doc["spec"]["custom"]["meta"]
        .as_array()
        .expect("meta array");
    assert_eq!(meta.len(), 1);
    assert_eq!(
        meta.get(0).and_then(|item| item.as_str()),
        Some("owner:release")
    );
}

#[test]
fn add_stage_items_renders_multiline_comments_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);

    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "hello".to_string(),
            None,
            None,
        )
        .expect("create artifact");
    manifest
        .add_stage_items(
            None,
            vec!["note".to_string()],
            Some("first line\nsecond line"),
        )
        .expect("add stage");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    assert!(text.contains("# first line"));
    assert!(text.contains("# second line"));
    let doc = read_manifest_doc(&path);
    let stage = doc["spec"]["stage"].as_array().expect("stage");
    assert_eq!(
        stage
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["note"]
    );
}

#[test]
fn local_package_updates_cover_noop_drop_and_not_found_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    let file = RepositoryFile::new("pkg.deb".to_string(), Hash::default(), 10);

    manifest.add_spec(None).expect("add default spec");
    manifest
        .add_local_package(
            file.clone(),
            local_package_ctrl("pkg.deb", 10),
            Some("local-comment"),
        )
        .expect("add local package");
    manifest
        .add_local_package(
            file,
            local_package_ctrl("pkg.deb", 10),
            Some("ignored-comment"),
        )
        .expect("noop update");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    assert_eq!(doc["local"].as_array_of_tables().expect("locals").len(), 1);

    manifest
        .drop_local_package("pkg.deb")
        .expect("drop local package");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist drop");

    let doc = read_manifest_doc(&path);
    assert!(doc.get("local").is_none());

    let err = manifest
        .drop_local_package("missing.deb")
        .expect_err("reject missing package");
    assert!(err
        .to_string()
        .contains("local package missing.deb not found"));
}

#[test]
fn archive_updates_cover_noop_drop_and_not_found_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    let archive = make_archive("https://example.invalid/debian", "stable");

    manifest
        .add_archive(archive.clone(), Some("archive-comment"))
        .expect("add archive");
    manifest
        .add_archive(archive, Some("ignored-comment"))
        .expect("noop archive update");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    assert_eq!(
        doc["archive"].as_array_of_tables().expect("archives").len(),
        1
    );

    manifest
        .drop_archive("https://example.invalid/debian")
        .expect("drop archive");
    smol::block_on(async {
        manifest
            .resolve(common::one(), &provider)
            .await
            .expect("resolve");
        manifest.store().await.expect("store");
    });

    let doc = read_manifest_doc(&path);
    assert!(doc.get("archive").is_none());

    let err = manifest
        .drop_archive("https://example.invalid/missing")
        .expect_err("reject missing archive");
    assert!(err
        .to_string()
        .contains("archive https://example.invalid/missing not found"));
}

#[test]
fn set_snapshot_updates_only_eligible_archives_in_manifest_doc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("Manifest.toml");
    let stamp = snapshot_id();

    let mut enabled = make_archive("https://example.invalid/enabled", "stable");
    enabled.snapshot = Some(Snapshot::Enable);

    let mut already_pinned = make_archive("https://example.invalid/pinned", "stable");
    already_pinned.snapshot = Some(Snapshot::Use(
        "20240101T000000Z".try_into().expect("parse snapshot"),
    ));

    let mut disabled = make_archive("https://example.invalid/disabled", "stable");
    disabled.snapshot = Some(Snapshot::Disable);

    let mut snapshots_only = make_archive("https://example.invalid/snapshots", "stable");
    snapshots_only.snapshots = Some("https://snapshot.example/{snapshot}/".to_string());

    let mut manifest = Manifest::from_archives(
        &path,
        ARCH,
        [enabled, already_pinned, disabled, snapshots_only],
        None,
    );

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");
    smol::block_on(manifest.set_snapshot(stamp));
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist snapshot");

    let doc = read_manifest_doc(&path);
    let archives = doc["archive"].as_array_of_tables().expect("archives");
    assert_eq!(
        archives
            .get(0)
            .expect("enabled archive")
            .get("snapshot")
            .and_then(|item| item.as_str()),
        Some("20240305T123456Z")
    );
    assert_eq!(
        archives
            .get(1)
            .expect("pinned archive")
            .get("snapshot")
            .and_then(|item| item.as_str()),
        Some("20240305T123456Z")
    );
    assert_eq!(
        archives
            .get(2)
            .expect("disabled archive")
            .get("snapshot")
            .and_then(|item| item.as_str()),
        Some("Disable")
    );
    assert_eq!(
        archives
            .get(3)
            .expect("snapshots archive")
            .get("snapshot")
            .and_then(|item| item.as_str()),
        Some("20240305T123456Z")
    );
}
