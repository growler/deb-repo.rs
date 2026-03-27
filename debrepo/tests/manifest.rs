mod common;

use {
    common::{
        create_locked_imported_manifest, make_archive, one, persist_manifest, read_manifest_doc,
        update_manifest_file, TestProvider, ARCH, REQUIREMENTS_PACKAGES,
    },
    debrepo::{
        artifact::ArtifactArg, cli::StageProgress, control::MutableControlStanza, Dependency,
        Manifest, RepositoryFile,
    },
    std::{
        num::NonZero,
        path::Path,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    },
};

#[test]
fn store_rejects_unlocked_manifest_without_writing_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let lock_path = path.with_extension(format!("{}.lock", ARCH));
    let mut manifest = Manifest::new(&path, ARCH, None);

    smol::block_on(async {
        let err = manifest.store().await.expect_err("store must fail");
        assert!(err.to_string().contains("run update first"));
    });

    assert!(!path.exists());
    assert!(!lock_path.exists());
}

#[test]
fn store_uses_manifest_owned_path_when_lock_is_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("imported.toml");
    let lock_path = path.with_extension(format!("{}.lock", ARCH));

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create locked manifest");
        let (mut manifest, has_valid_lock) = Manifest::from_file(&path, ARCH).await.expect("load");
        assert!(has_valid_lock);
        manifest.store().await.expect("store");
    });

    assert!(path.exists());
    assert!(lock_path.exists());
}

#[test]
fn update_locals_refreshes_local_artifact_hashes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-file");
    std::fs::write(&artifact_path, b"before").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-file".to_string(),
        target: Some("/opt/artifact-file".to_string()),
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, None, &provider)
            .await
            .expect("add artifact");
    });

    let old_hash = manifest
        .artifact("artifact-file")
        .expect("artifact exists")
        .hash();

    std::fs::write(&artifact_path, b"after").expect("update artifact");

    smol::block_on(async {
        manifest
            .update(false, true, true, one(), &provider)
            .await
            .expect("update locals")
    });

    let new_hash = manifest
        .artifact("artifact-file")
        .expect("artifact exists")
        .hash();
    assert_ne!(old_hash, new_hash);
}

#[test]
fn add_requirements_default_spec_adds_items_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::with_packages(REQUIREMENTS_PACKAGES);
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(None, ["foo"], Some("req-comment"))
        .expect("add requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let include = doc["spec"]["include"].as_array().expect("include array");
    let items = include
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["foo"]);
    assert!(text.contains("req-comment"));
}

#[test]
fn add_requirements_named_spec_adds_items_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::with_packages(REQUIREMENTS_PACKAGES);
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["bar"], Some("named-comment"))
        .expect("add requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let include = doc["spec"]["custom"]["include"]
        .as_array()
        .expect("include array");
    let items = include
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["bar"]);
    assert!(text.contains("named-comment"));
}

#[test]
fn add_requirements_prevents_duplicate_comment_on_existing_item() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::with_packages(REQUIREMENTS_PACKAGES);
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(None, ["dup"], Some("first-comment"))
        .expect("add requirements");
    manifest
        .add_requirements(None, ["dup"], Some("second-comment"))
        .expect("add requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let include = doc["spec"]["include"].as_array().expect("include array");
    assert_eq!(include.len(), 1);
    assert!(text.contains("first-comment"));
    assert!(!text.contains("second-comment"));
}

#[test]
fn remove_requirements_default_spec_removes_items_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(None, ["foo"], Some("remove-comment"))
        .expect("add requirements");
    manifest
        .remove_requirements(None, ["foo"])
        .expect("remove requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("include").is_none());
    assert!(!text.contains("remove-comment"));
    assert!(!text.contains("foo"));
}

#[test]
fn remove_requirements_named_spec_removes_items_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["foo"], Some("remove-comment"))
        .expect("add requirements");
    manifest
        .remove_requirements(Some("custom"), ["foo"])
        .expect("remove requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("include").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn add_constraints_default_spec_adds_items_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(None, ["foo (>= 1.0)"], Some("exclude-comment"))
        .expect("add constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let exclude = doc["spec"]["exclude"].as_array().expect("exclude array");
    let items = exclude
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["foo (>= 1.0)"]);
    assert!(text.contains("exclude-comment"));
}

#[test]
fn add_constraints_named_spec_adds_items_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(Some("custom"), ["bar (<< 2.0)"], Some("exclude-comment"))
        .expect("add constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let exclude = doc["spec"]["custom"]["exclude"]
        .as_array()
        .expect("exclude array");
    let items = exclude
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["bar (<< 2.0)"]);
    assert!(text.contains("exclude-comment"));
}

#[test]
fn add_constraints_prevents_duplicate_comment_on_existing_item() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(None, ["dup (>= 1)"], Some("first-comment"))
        .expect("add constraints");
    manifest
        .add_constraints(None, ["dup (>= 1)"], Some("second-comment"))
        .expect("add constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let exclude = doc["spec"]["exclude"].as_array().expect("exclude array");
    assert_eq!(exclude.len(), 1);
    assert!(text.contains("first-comment"));
    assert!(!text.contains("second-comment"));
}

#[test]
fn remove_constraints_default_spec_removes_items_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(None, ["foo (<= 2.0)"], Some("remove-comment"))
        .expect("add constraints");
    manifest
        .remove_constraints(None, ["foo (<= 2.0)"])
        .expect("remove constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("exclude").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn remove_constraints_named_spec_removes_items_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(Some("custom"), ["foo (= 1)"], Some("remove-comment"))
        .expect("add constraints");
    manifest
        .remove_constraints(Some("custom"), ["foo (= 1)"])
        .expect("remove constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("exclude").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn add_archive_adds_entry_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    let archive = make_archive("https://example.invalid/debian", "stable");
    manifest
        .add_archive(archive, Some("archive-comment"))
        .expect("add archive");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let archives = doc["archive"].as_array_of_tables().expect("archive array");
    assert_eq!(archives.len(), 1);
    let entry = archives.get(0).expect("archive entry");
    assert_eq!(
        entry.get("url").and_then(|v| v.as_str()),
        Some("https://example.invalid/debian")
    );
    let suites = entry
        .get("suites")
        .and_then(|v| v.as_array())
        .expect("suites array");
    let suites = suites
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(suites, vec!["stable"]);
    assert!(text.contains("archive-comment"));
}

#[test]
fn add_archive_update_removes_comment_when_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    let archive = make_archive("https://example.invalid/debian", "stable");
    manifest
        .add_archive(archive.clone(), Some("archive-comment"))
        .expect("add archive");
    let mut updated = archive;
    updated.suites = vec!["testing".to_string()];
    manifest.add_archive(updated, None).expect("update archive");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let archives = doc["archive"].as_array_of_tables().expect("archive array");
    let entry = archives.get(0).expect("archive entry");
    let suites = entry
        .get("suites")
        .and_then(|v| v.as_array())
        .expect("suites array");
    let suites = suites
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(suites, vec!["testing"]);
    assert!(!text.contains("archive-comment"));
}

#[test]
fn add_local_package_adds_entry_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");
    let file = RepositoryFile::new("pkg.deb".to_string(), debrepo::hash::Hash::default(), 10);
    let mut ctrl = MutableControlStanza::new();
    ctrl.set("Package", "local-test");
    ctrl.set("Version", "1.0");
    ctrl.set("Architecture", ARCH);
    ctrl.set("Filename", "pkg.deb");
    ctrl.set("Size", "10");
    ctrl.set("SHA256", debrepo::hash::Hash::default().to_hex());
    manifest
        .add_local_package(file, ctrl, Some("local-comment"))
        .expect("add local package");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let locals = doc["local"].as_array_of_tables().expect("local array");
    assert_eq!(locals.len(), 1);
    let entry = locals.get(0).expect("local entry");
    assert_eq!(entry.get("path").and_then(|v| v.as_str()), Some("pkg.deb"));
    assert_eq!(entry.get("size").and_then(|v| v.as_integer()), Some(10));
    assert!(text.contains("local-comment"));
}

#[test]
fn add_local_package_update_removes_comment_when_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");

    let mut ctrl = MutableControlStanza::new();
    ctrl.set("Package", "local-test");
    ctrl.set("Version", "1.0");
    ctrl.set("Architecture", ARCH);
    ctrl.set("Filename", "pkg.deb");
    ctrl.set("Size", "10");
    ctrl.set("SHA256", debrepo::hash::Hash::default().to_hex());
    manifest
        .add_local_package(
            RepositoryFile::new("pkg.deb".to_string(), debrepo::hash::Hash::default(), 10),
            ctrl,
            Some("local-comment"),
        )
        .expect("add local package");

    let mut ctrl = MutableControlStanza::new();
    ctrl.set("Package", "local-test");
    ctrl.set("Version", "1.0");
    ctrl.set("Architecture", ARCH);
    ctrl.set("Filename", "pkg.deb");
    ctrl.set("Size", "22");
    ctrl.set("SHA256", debrepo::hash::Hash::default().to_hex());
    manifest
        .add_local_package(
            RepositoryFile::new("pkg.deb".to_string(), debrepo::hash::Hash::default(), 22),
            ctrl,
            None,
        )
        .expect("update local package");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let locals = doc["local"].as_array_of_tables().expect("local array");
    let entry = locals.get(0).expect("local entry");
    assert_eq!(entry.get("size").and_then(|v| v.as_integer()), Some(22));
    assert!(!text.contains("local-comment"));
}

#[test]
fn add_artifact_default_spec_adds_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, Some("artifact-comment"), &provider)
            .await
    })
    .expect("add artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    let items = stage
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["artifact-dir"]);
    let artifacts = doc["artifact"].as_table().expect("artifact table");
    assert!(artifacts.get("artifact-dir").is_some());
    assert!(text.contains("artifact-comment"));
}

#[test]
fn add_artifact_prevents_duplicate_stage_and_comment_on_update() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, Some("artifact-comment"), &provider)
            .await
            .expect("add artifact");
        manifest
            .add_artifact(None, &arg, None, &provider)
            .await
            .expect("update artifact");
    });

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    assert_eq!(stage.len(), 1);
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn add_artifact_named_spec_adds_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(Some("custom"), &arg, Some("artifact-comment"), &provider)
            .await
    })
    .expect("add artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let stage = doc["spec"]["custom"]["stage"]
        .as_array()
        .expect("stage array");
    let items = stage
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["artifact-dir"]);
    assert!(text.contains("artifact-comment"));
}

#[test]
fn upsert_text_artifact_creates_and_updates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");
    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "hello".to_string(),
            None,
            None,
        )
        .expect("create text artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    assert!(text.contains("type = \"text\""));
    let artifact = doc["artifact"]["note"].as_table().expect("artifact table");
    assert_eq!(
        artifact
            .get("target")
            .and_then(|item| item.as_value())
            .and_then(|value| value.as_str()),
        Some("/etc/note")
    );
    assert_eq!(
        artifact
            .get("text")
            .and_then(|item| item.as_value())
            .and_then(|value| value.as_str()),
        Some("hello")
    );

    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "updated".to_string(),
            NonZero::new(0o644),
            Some("amd64".to_string()),
        )
        .expect("update text artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let artifact = doc["artifact"]["note"].as_table().expect("artifact table");
    assert_eq!(
        artifact
            .get("text")
            .and_then(|item| item.as_value())
            .and_then(|value| value.as_str()),
        Some("updated")
    );
    assert_eq!(
        artifact
            .get("mode")
            .and_then(|item| item.as_value())
            .map(|value| value.to_string().trim().to_string()),
        Some("0o644".to_string())
    );
}

#[test]
fn upsert_text_artifact_rejects_non_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-file");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(&artifact_path, b"data").expect("write artifact");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-file".to_string(),
        target: Some("/etc/host".to_string()),
    };
    smol::block_on(async { manifest.add_artifact(None, &arg, None, &provider).await })
        .expect("add artifact");

    let err = manifest
        .upsert_text_artifact(
            "artifact-file",
            "/etc/host".to_string(),
            "text".to_string(),
            None,
            None,
        )
        .expect_err("reject non-text");
    assert!(err.to_string().contains("not text"));
}

#[test]
fn remove_artifact_default_spec_removes_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, Some("artifact-comment"), &provider)
            .await
            .expect("add artifact");
    });
    manifest
        .remove_artifact(None, "artifact-dir")
        .expect("remove artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("stage").is_none());
    let artifacts = doc.get("artifact").and_then(|item| item.as_table());
    assert!(artifacts
        .map(|table| table.get("artifact-dir").is_none())
        .unwrap_or(true));
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn remove_artifact_named_spec_removes_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(Some("custom"), &arg, Some("artifact-comment"), &provider)
            .await
            .expect("add artifact");
    });
    manifest
        .remove_artifact(Some("custom"), "artifact-dir")
        .expect("remove artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("stage").is_none());
    let artifacts = doc.get("artifact").and_then(|item| item.as_table());
    assert!(artifacts
        .map(|table| table.get("artifact-dir").is_none())
        .unwrap_or(true));
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn set_build_script_default_spec_adds_and_removes_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");

    manifest
        .set_build_script(None, Some("echo hello\n".to_string()))
        .expect("set build script");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert_eq!(
        spec.get("build-script").and_then(|v| v.as_str()),
        Some("echo hello\n")
    );

    manifest
        .set_build_script(None, None)
        .expect("remove build script");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("build-script").is_none());
}

#[test]
fn set_build_script_named_spec_adds_and_removes_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(Some("custom")).expect("add named spec");

    manifest
        .set_build_script(Some("custom"), Some("echo hello\n".to_string()))
        .expect("set build script");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert_eq!(
        spec.get("build-script").and_then(|v| v.as_str()),
        Some("echo hello\n")
    );

    manifest
        .set_build_script(Some("custom"), None)
        .expect("remove build script");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("build-script").is_none());
}

#[test]
fn manifest_setters_create_missing_spec_consistently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);

    manifest
        .set_spec_meta(Some("custom"), "owner", "ops")
        .expect("set spec meta");
    manifest
        .set_build_env(
            Some("custom"),
            [("FOO".to_string(), "bar".to_string())]
                .into_iter()
                .collect(),
        )
        .expect("set build env");
    manifest
        .set_build_script(Some("custom"), Some("echo hello\n".to_string()))
        .expect("set build script");

    assert_eq!(manifest.spec_names().collect::<Vec<_>>(), vec!["custom"]);
    assert_eq!(
        manifest
            .get_spec_meta(Some("custom"), "owner")
            .expect("get meta"),
        Some("ops")
    );
    assert_eq!(
        manifest
            .spec_env_block(Some("custom"))
            .expect("get env block"),
        "FOO=bar\n"
    );
    assert_eq!(
        manifest
            .spec_build_script(Some("custom"))
            .expect("get build script")
            .as_deref(),
        Some("echo hello\n")
    );
}

#[test]
fn manifest_spec_env_block_renders_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);

    let block = "# prefix-foo\n\nFOO=bar # inline-foo\nBAZ=qux\n".to_string();
    manifest
        .spec_update_env_block(None, block.clone())
        .expect("update env block");

    assert_eq!(
        manifest.spec_env_block(None).expect("render env block"),
        block
    );
}

#[test]
fn manifest_spec_update_env_block_updates_values_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    let block = "# prefix-foo\n\nFOO=bar # inline-foo\nBAZ=qux\n".to_string();

    manifest
        .spec_update_env_block(None, block.clone())
        .expect("update env block");

    assert_eq!(
        manifest.spec_env_block(None).expect("render env block"),
        block
    );
}

#[test]
fn manifest_spec_update_env_block_empty_removes_build_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);

    manifest
        .set_spec_meta(None, "owner", "ops")
        .expect("set spec meta");
    manifest
        .set_build_env(
            None,
            [("FOO".to_string(), "bar".to_string())]
                .into_iter()
                .collect(),
        )
        .expect("set build env");

    manifest
        .spec_update_env_block(None, String::new())
        .expect("clear env block");

    assert_eq!(manifest.spec_env_block(None).expect("render env block"), "");
    assert_eq!(
        manifest.get_spec_meta(None, "owner").expect("get owner"),
        Some("ops")
    );
}

#[test]
fn manifest_missing_spec_noops_do_not_create_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);

    manifest
        .set_build_env(
            Some("custom"),
            std::iter::empty::<(String, String)>().collect(),
        )
        .expect("empty build env is a no-op");
    manifest
        .set_build_script(Some("custom"), None)
        .expect("missing build script is a no-op");
    manifest
        .add_requirements(Some("custom"), Vec::<Dependency<String>>::new(), None)
        .expect("empty requirements are a no-op");
    manifest
        .add_constraints(
            Some("custom"),
            Vec::<debrepo::Constraint<String>>::new(),
            None,
        )
        .expect("empty constraints are a no-op");
    manifest
        .add_stage_items(Some("custom"), Vec::new(), None)
        .expect("empty stage items are a no-op");

    assert!(manifest.spec_names().next().is_none());
    assert!(manifest.spec_build_script(Some("custom")).is_err());
}

#[test]
fn update_without_valid_lock_refreshes_archives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let release_fetches = Arc::new(AtomicUsize::new(0));
    let provider = TestProvider::with_release_counter(Arc::clone(&release_fetches));

    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_archive(
            make_archive("https://example.invalid/debian", "stable"),
            None,
        )
        .expect("add archive");

    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &provider)
            .await
            .expect("update");
        manifest.store().await.expect("store");
    });

    assert!(release_fetches.load(Ordering::Relaxed) > 0);
    assert!(path.with_extension(format!("{}.lock", ARCH)).exists());
}

#[test]
fn update_skips_archive_refresh_when_lock_is_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let first_fetches = Arc::new(AtomicUsize::new(0));
    let provider = TestProvider::with_release_counter(Arc::clone(&first_fetches));

    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_archive(
            make_archive("https://example.invalid/debian", "stable"),
            None,
        )
        .expect("add archive");
    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &provider)
            .await
            .expect("update");
        manifest.store().await.expect("store");
    });

    let release_fetches = Arc::new(AtomicUsize::new(0));
    let provider = TestProvider::with_release_counter(Arc::clone(&release_fetches));

    smol::block_on(async {
        let (mut loaded, has_valid_lock) = Manifest::from_file(&path, ARCH).await.expect("load");
        assert!(has_valid_lock);
        loaded
            .update(false, false, true, one(), &provider)
            .await
            .expect("update");
    });

    assert_eq!(release_fetches.load(Ordering::Relaxed), 0);
}

#[test]
fn add_stage_items_rejects_imported_artifacts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let downstream_path = dir.path().join("downstream.toml");

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let mut downstream = Manifest::new(&downstream_path, ARCH, None);
    smol::block_on(async {
        downstream
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
    });

    let err = downstream
        .add_stage_items(None, vec!["./base.txt".to_string()], None)
        .expect_err("downstream manifest must not stage imported artifact directly");
    assert!(err
        .to_string()
        .contains("artifact ./base.txt not found in manifest"));
}

#[test]
fn resolve_rejects_downstream_stage_reference_to_imported_artifact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let downstream_path = dir.path().join("downstream.toml");
    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
        let mut downstream = Manifest::new(&downstream_path, ARCH, None);
        downstream.add_spec(None).expect("add default spec");
        downstream
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
        downstream.resolve(one(), &provider).await.expect("resolve");
        downstream.store().await.expect("store downstream manifest");
    });

    update_manifest_file(&downstream_path, |doc| {
        let mut stage = toml_edit::Array::new();
        stage.push("./base.txt");
        doc["spec"]["stage"] = toml_edit::Item::Value(stage.into());
    });

    smol::block_on(async {
        let (mut loaded, _) = Manifest::from_file(&downstream_path, ARCH)
            .await
            .expect("load");
        let err = loaded
            .resolve(one(), &provider)
            .await
            .expect_err("resolve must reject imported artifact in downstream stage");
        assert!(err
            .to_string()
            .contains("missing artifact './base.txt' in spec stage list"));
    });
}

#[test]
fn stage_local_allows_inherited_imported_artifact_stage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let downstream_path = dir.path().join("downstream.toml");
    let root = dir.path().join("root");
    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
        let mut downstream = Manifest::new(&downstream_path, ARCH, None);
        downstream.add_spec(None).expect("add default spec");
        downstream
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
        downstream.resolve(one(), &provider).await.expect("resolve");
        downstream.store().await.expect("store downstream manifest");
    });

    update_manifest_file(&downstream_path, |doc| {
        doc["spec"]["extends"] = toml_edit::value("base");
    });

    smol::block_on(async {
        let (mut loaded, _) = Manifest::from_file(&downstream_path, ARCH)
            .await
            .expect("load");
        loaded.resolve(one(), &provider).await.expect("resolve");
        let mut fs = debrepo::HostFileSystem::new(&root, false)
            .await
            .expect("staging fs");
        loaded
            .stage_local(
                None,
                &mut fs,
                one(),
                &provider,
                Option::<fn(u64) -> StageProgress>::None,
            )
            .await
            .expect("stage inherited imported artifact");
    });

    let staged = std::fs::read_to_string(root.join("opt/import/base.txt")).expect("staged file");
    assert_eq!(staged, "base artifact\n");
}
