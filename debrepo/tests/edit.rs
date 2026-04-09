mod common;

use {
    clap::Parser,
    common::{
        one, read_manifest_doc, update_manifest_file, write_executable, CurrentDirGuard, EnvGuard,
        TestConfig, TestProvider, ARCH,
    },
    debrepo::{
        cli::{cmd, Command},
        Manifest,
    },
    std::path::PathBuf,
};

fn editor_path(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

async fn create_locked_edit_manifest(path: &std::path::Path) {
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(path, ARCH, None);
    manifest
        .set_spec_meta(None, "owner", "seed")
        .expect("set default spec meta");
    manifest
        .resolve(one(), &provider)
        .await
        .expect("resolve manifest");
    manifest.store().await.expect("store manifest");
}

#[test]
fn edit_env_and_script_cover_editor_resolution_and_updates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    smol::block_on(create_locked_edit_manifest(&manifest_path));
    let conf = TestConfig::new(manifest_path.clone(), TestProvider::new());

    let editor_env = dir.path().join("edit-env.sh");
    write_executable(
        &editor_env,
        "#!/bin/sh\ncat > \"$1\" <<'EOF'\nFOO=bar\n# keep comment\nBAR=baz\nEOF\n",
    );
    let mut env = EnvGuard::new();
    env.remove("VISUAL");
    env.set("EDITOR", &editor_env);

    cmd::Edit::try_parse_from(["edit", "env"])
        .expect("parse edit env")
        .exec(&conf)
        .expect("edit env");

    let (manifest, has_valid_lock) =
        smol::block_on(Manifest::from_file(&manifest_path, ARCH)).expect("reload manifest");
    assert!(has_valid_lock);
    let spec = manifest.lookup_spec(None).expect("default spec");
    assert_eq!(
        spec.build_env()
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAR".to_string(), "baz".to_string()),
        ]
    );
    assert!(std::fs::read_to_string(&manifest_path)
        .expect("read manifest")
        .contains("# keep comment"));

    let editor_script = dir.path().join("edit-script.sh");
    write_executable(
        &editor_script,
        "#!/bin/sh\ncat > \"$1\" <<'EOF'\n#!/bin/sh\necho edited-script\nEOF\n",
    );
    cmd::Edit::try_parse_from(["edit", "--editor", &editor_path(&editor_script), "script"])
        .expect("parse edit script")
        .exec(&conf)
        .expect("edit script");

    let (manifest, has_valid_lock) =
        smol::block_on(Manifest::from_file(&manifest_path, ARCH)).expect("reload manifest");
    assert!(has_valid_lock);
    assert_eq!(
        manifest
            .lookup_spec(None)
            .expect("default spec")
            .build_script(),
        Some("#!/bin/sh\necho edited-script\n")
    );

    let clear_script = dir.path().join("clear-script.sh");
    write_executable(&clear_script, "#!/bin/sh\nprintf '   \\n' > \"$1\"\n");
    cmd::Edit::try_parse_from(["edit", "--editor", &editor_path(&clear_script), "script"])
        .expect("parse clear script")
        .exec(&conf)
        .expect("clear script");

    let (manifest, has_valid_lock) =
        smol::block_on(Manifest::from_file(&manifest_path, ARCH)).expect("reload manifest");
    assert!(has_valid_lock);
    assert_eq!(
        manifest
            .lookup_spec(None)
            .expect("default spec")
            .build_script(),
        None
    );
}

#[test]
fn edit_artifact_creates_updates_and_rejects_non_text_artifacts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    std::fs::write(dir.path().join("payload.bin"), b"binary").expect("write payload");
    smol::block_on(create_locked_edit_manifest(&manifest_path));

    let _cwd = CurrentDirGuard::set(dir.path());
    let conf = TestConfig::new(PathBuf::from("Manifest.toml"), TestProvider::new());

    let create_editor = dir.path().join("create-artifact.sh");
    write_executable(
        &create_editor,
        "#!/bin/sh\nprintf 'first artifact body\\n' > \"$1\"\n",
    );
    cmd::Edit::try_parse_from([
        "edit",
        "--editor",
        &editor_path(&create_editor),
        "artifact",
        "note.txt",
        "--target",
        "/etc/note.txt",
        "--mode",
        "0640",
        "--only-arch",
        "amd64",
        "--stage",
    ])
    .expect("parse create artifact")
    .exec(&conf)
    .expect("create artifact");

    let doc = read_manifest_doc(&manifest_path);
    assert_eq!(
        doc["spec"]["stage"]
            .as_array()
            .expect("stage array")
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["note.txt"]
    );

    let (_, has_valid_lock) =
        smol::block_on(Manifest::from_file("Manifest.toml", ARCH)).expect("reload manifest");
    assert!(has_valid_lock);
    let doc = read_manifest_doc(&manifest_path);
    let artifact = doc["artifact"]["note.txt"]
        .as_table()
        .expect("artifact table");
    assert_eq!(
        artifact.get("text").and_then(|item| item.as_str()),
        Some("first artifact body\n")
    );
    assert_eq!(
        artifact.get("mode").and_then(|item| item.as_integer()),
        Some(0o640)
    );
    assert_eq!(
        artifact.get("arch").and_then(|item| item.as_str()),
        Some("amd64")
    );

    let update_editor = dir.path().join("update-artifact.sh");
    write_executable(
        &update_editor,
        "#!/bin/sh\nprintf 'updated artifact body\\n' > \"$1\"\n",
    );
    cmd::Edit::try_parse_from([
        "edit",
        "--editor",
        &editor_path(&update_editor),
        "artifact",
        "note.txt",
        "--target",
        "/etc/note.txt",
    ])
    .expect("parse update artifact")
    .exec(&conf)
    .expect("update artifact");

    let (_, has_valid_lock) =
        smol::block_on(Manifest::from_file("Manifest.toml", ARCH)).expect("reload manifest");
    assert!(has_valid_lock);
    let doc = read_manifest_doc(&manifest_path);
    let artifact = doc["artifact"]["note.txt"]
        .as_table()
        .expect("artifact table");
    assert_eq!(
        artifact.get("text").and_then(|item| item.as_str()),
        Some("updated artifact body\n")
    );
    assert_eq!(
        artifact.get("mode").and_then(|item| item.as_integer()),
        Some(0o640)
    );
    assert_eq!(
        artifact.get("arch").and_then(|item| item.as_str()),
        Some("amd64")
    );

    cmd::ArtifactAdd::try_parse_from(["artifact-add", "payload.bin", "/opt/payload.bin"])
        .expect("parse artifact add")
        .exec(&conf)
        .expect("add binary artifact");
    let err = cmd::Edit::try_parse_from([
        "edit",
        "--editor",
        &editor_path(&update_editor),
        "artifact",
        "payload.bin",
        "--target",
        "/opt/payload.bin",
    ])
    .expect("parse edit binary artifact")
    .exec(&conf)
    .expect_err("editing non-text artifact must fail");
    assert!(err
        .to_string()
        .contains("artifact payload.bin exists but is not text"));
}

#[test]
fn edit_manifest_refreshes_stale_lock_and_reports_editor_failures() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    smol::block_on(create_locked_edit_manifest(&manifest_path));
    let conf = TestConfig::new(manifest_path.clone(), TestProvider::new());

    update_manifest_file(&manifest_path, |doc| {
        let mut meta = toml_edit::Array::default();
        meta.push("owner:stale");
        doc["spec"]["meta"] = toml_edit::Item::Value(toml_edit::Value::Array(meta));
    });

    let noop_editor = dir.path().join("noop-editor.sh");
    write_executable(&noop_editor, "#!/bin/sh\nexit 0\n");
    cmd::Edit::try_parse_from(["edit", "--editor", &editor_path(&noop_editor)])
        .expect("parse manifest edit")
        .exec(&conf)
        .expect("edit manifest");

    let (_, has_valid_lock) =
        smol::block_on(Manifest::from_file(&manifest_path, ARCH)).expect("reload manifest");
    assert!(
        has_valid_lock,
        "manifest edit should refresh the stale lock"
    );

    let failing_editor = dir.path().join("fail-editor.sh");
    write_executable(&failing_editor, "#!/bin/sh\nexit 7\n");
    let err = cmd::Edit::try_parse_from(["edit", "--editor", &editor_path(&failing_editor), "env"])
        .expect("parse failing edit")
        .exec(&conf)
        .expect_err("failing editor must bubble up");
    assert!(err.to_string().contains("editor exited with status"));
}

#[test]
fn edit_subcommands_reject_unlocked_manifests() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    std::fs::write(&manifest_path, "").expect("write unlocked manifest");
    let conf = TestConfig::new(manifest_path, TestProvider::new());

    for argv in [
        vec!["edit", "--editor", " ", "env"],
        vec!["edit", "--editor", " ", "script"],
        vec![
            "edit",
            "--editor",
            " ",
            "artifact",
            "note.txt",
            "--target",
            "/etc/note.txt",
        ],
    ] {
        let err = cmd::Edit::try_parse_from(argv)
            .expect("parse edit command")
            .exec(&conf)
            .expect_err("unlocked manifest must fail");
        assert!(err
            .to_string()
            .contains("manifest lock is not live; run update first"));
    }
}
