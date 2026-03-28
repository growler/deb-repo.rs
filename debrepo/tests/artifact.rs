mod common;

use {
    clap::Parser,
    common::{TestProvider, ARCH},
    debrepo::{
        artifact::{Artifact, ArtifactArg},
        auth::AuthProvider,
        cli::Command,
        content::HostCache,
        hash::Hash,
        CompressionLevel, HostFileSystem, Manifest, Stage,
    },
    smol::io::AsyncWriteExt,
    std::{
        fs, io,
        num::NonZero,
        os::unix::{
            ffi::OsStringExt,
            fs::{symlink, MetadataExt, PermissionsExt},
        },
        path::{Path, PathBuf},
    },
};

#[derive(Parser)]
struct ArtifactArgCli {
    #[command(flatten)]
    artifact: ArtifactArg,
}

fn artifact_manifest_text(key: &str, body: &str) -> String {
    format!("[artifact.\"{key}\"]\n{body}\n")
}

fn load_artifact(path: &Path, key: &str, body: &str) -> Artifact {
    fs::write(path, artifact_manifest_text(key, body)).expect("write manifest");
    let (manifest, _) = smol::block_on(Manifest::from_file(path, ARCH)).expect("load manifest");
    manifest.artifact(key).expect("artifact").clone()
}

fn file_url(path: &Path) -> String {
    url::Url::from_file_path(path)
        .expect("file url")
        .to_string()
}

fn host_cache(cache: Option<&Path>) -> HostCache {
    HostCache::new(
        debrepo::HttpTransport::new(AuthProvider::new::<&str>(None).expect("auth"), false, false),
        cache,
    )
}

fn zero_sri() -> String {
    Hash::default().to_sri()
}

fn stage_boxed_to_root<T>(
    mut stage: Box<dyn Stage<Target = HostFileSystem, Output = T> + Send + 'static>,
    root: &Path,
) -> io::Result<T> {
    smol::block_on(async {
        let fs = HostFileSystem::new(root, false).await?;
        stage.stage(&fs).await
    })
}

async fn write_gzip(path: &Path, data: &[u8]) -> io::Result<Vec<u8>> {
    if let Some(parent) = path.parent() {
        smol::fs::create_dir_all(parent).await?;
    }
    let file = smol::fs::File::create(path).await?;
    let mut writer = debrepo::packer("payload.txt.gz", file, CompressionLevel::Default);
    writer.write_all(data).await?;
    writer.close().await?;
    smol::fs::read(path).await
}

enum TarFixtureEntry<'a> {
    Directory {
        path: &'a str,
        mode: u32,
    },
    File {
        path: &'a str,
        mode: u32,
        data: &'a [u8],
    },
    Symlink {
        path: &'a str,
        mode: u32,
        target: &'a str,
    },
    Hardlink {
        path: &'a str,
        mode: u32,
        target: &'a str,
    },
    Fifo {
        path: &'a str,
        mode: u32,
    },
}

fn write_tar_str(field: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    assert!(
        bytes.len() <= field.len(),
        "tar field too small for {value}"
    );
    field[..bytes.len()].copy_from_slice(bytes);
}

fn write_tar_octal(field: &mut [u8], value: u64) {
    let width = field.len();
    let text = format!("{value:0width$o}\0", width = width.saturating_sub(1));
    let bytes = text.as_bytes();
    let start = width.saturating_sub(bytes.len());
    field[start..start + bytes.len()].copy_from_slice(bytes);
}

fn append_tar_entry(out: &mut Vec<u8>, entry: TarFixtureEntry<'_>) {
    let mut header = [0u8; 512];
    let (path, mode, data_len, typeflag, linkname) = match entry {
        TarFixtureEntry::Directory { path, mode } => (path, mode, 0usize, b'5', ""),
        TarFixtureEntry::File { path, mode, data } => (path, mode, data.len(), b'0', ""),
        TarFixtureEntry::Symlink { path, mode, target } => (path, mode, 0usize, b'2', target),
        TarFixtureEntry::Hardlink { path, mode, target } => (path, mode, 0usize, b'1', target),
        TarFixtureEntry::Fifo { path, mode } => (path, mode, 0usize, b'6', ""),
    };

    write_tar_str(&mut header[0..100], path);
    write_tar_octal(&mut header[100..108], u64::from(mode));
    write_tar_octal(&mut header[108..116], 0);
    write_tar_octal(&mut header[116..124], 0);
    write_tar_octal(&mut header[124..136], data_len as u64);
    write_tar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    write_tar_str(&mut header[157..257], linkname);
    write_tar_str(&mut header[257..263], "ustar\0");
    write_tar_str(&mut header[263..265], "00");

    let checksum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    let checksum_text = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_text.as_bytes());
    out.extend_from_slice(&header);

    if let TarFixtureEntry::File { data, .. } = entry {
        out.extend_from_slice(data);
        let padding = (512 - (data.len() % 512)) % 512;
        out.resize(out.len() + padding, 0);
    }
}

fn build_tar(entries: impl IntoIterator<Item = TarFixtureEntry<'static>>) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        append_tar_entry(&mut out, entry);
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn spec_digest(artifact: &Artifact) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    artifact.update_spec_hash(&mut hasher);
    *hasher.finalize().as_bytes()
}

#[test]
fn artifact_arg_parser_accepts_and_rejects_modes() {
    let parsed = ArtifactArgCli::try_parse_from([
        "artifact",
        "--mode",
        "0o755",
        "--no-unpack",
        "--only-arch",
        "arm64",
        "https://example.invalid/file.txt",
        "/opt/out.txt",
    ])
    .expect("parse valid artifact arg")
    .artifact;
    assert_eq!(parsed.mode, NonZero::new(0o755));
    assert!(parsed.do_not_unpack);
    assert_eq!(parsed.target_arch.as_deref(), Some("arm64"));
    assert_eq!(parsed.url, "https://example.invalid/file.txt");
    assert_eq!(parsed.target.as_deref(), Some("/opt/out.txt"));

    let parsed = ArtifactArgCli::try_parse_from(["artifact", "--mode", "644", "file", "/out"])
        .expect("parse bare octal")
        .artifact;
    assert_eq!(parsed.mode, NonZero::new(0o644));

    for invalid in ["089", "abc", "0", "0o", " "] {
        let err =
            match ArtifactArgCli::try_parse_from(["artifact", "--mode", invalid, "file", "/out"]) {
                Ok(_) => panic!("invalid mode should fail"),
                Err(err) => err,
            };
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    let invalid_utf8 = vec![
        std::ffi::OsString::from("artifact"),
        std::ffi::OsString::from("--mode"),
        std::ffi::OsString::from_vec(vec![0xff, 0xfe]),
        std::ffi::OsString::from("file"),
        std::ffi::OsString::from("/out"),
    ];
    let err = match ArtifactArgCli::try_parse_from(invalid_utf8) {
        Ok(_) => panic!("invalid utf8 should fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidUtf8);
}

#[test]
fn manifest_add_artifact_classifies_local_inputs_and_validates_targets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let source_dir = dir.path().join("tree");
    let source_file = dir.path().join("plain.txt");
    let tar_path = dir.path().join("archive.tar");
    let raw_tar_path = dir.path().join("archive-raw.tar");
    fs::create_dir_all(&source_dir).expect("create tree");
    fs::write(source_dir.join("data.txt"), b"tree").expect("write tree file");
    fs::write(&source_file, b"plain").expect("write source file");
    let tar_bytes = build_tar([TarFixtureEntry::File {
        path: "entry.txt",
        mode: 0o644,
        data: b"tar-data",
    }]);
    fs::write(&tar_path, &tar_bytes).expect("write tar");
    fs::write(&raw_tar_path, &tar_bytes).expect("write raw tar");

    let mut manifest = Manifest::new(&path, ARCH, None);
    smol::block_on(async {
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: "tree".to_string(),
                    target: None,
                },
                None,
                &provider,
            )
            .await
            .expect("add directory artifact");
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: Some("amd64".to_string()),
                    url: "archive.tar".to_string(),
                    target: Some("/opt/root".to_string()),
                },
                None,
                &provider,
            )
            .await
            .expect("add tar artifact");
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: Some(NonZero::new(0o755).expect("mode")),
                    do_not_unpack: true,
                    target_arch: None,
                    url: "archive-raw.tar".to_string(),
                    target: Some("/opt/archive.tar".to_string()),
                },
                None,
                &provider,
            )
            .await
            .expect("add no-unpack file artifact");
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: "plain.txt".to_string(),
                    target: Some("srv/plain.txt".to_string()),
                },
                None,
                &provider,
            )
            .await
            .expect("add plain file artifact");
    });

    assert!(matches!(
        manifest.artifact("tree").expect("tree artifact"),
        Artifact::Dir(_)
    ));
    let tar = manifest.artifact("archive.tar").expect("tar artifact");
    assert!(matches!(tar, Artifact::Tar(_)));
    assert_eq!(tar.arch(), Some("amd64"));

    let raw_file = manifest
        .artifact("archive-raw.tar")
        .expect("raw tar artifact");
    assert!(matches!(raw_file, Artifact::File(_)));
    assert!(matches!(
        manifest.artifact("plain.txt").expect("plain artifact"),
        Artifact::File(_)
    ));

    let err = smol::block_on(async {
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: "plain.txt".to_string(),
                    target: None,
                },
                None,
                &provider,
            )
            .await
    })
    .expect_err("missing file target");
    assert!(err
        .to_string()
        .contains("target must be specified for a file"));

    let err = smol::block_on(async {
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: "plain.txt".to_string(),
                    target: Some(String::new()),
                },
                None,
                &provider,
            )
            .await
    })
    .expect_err("empty target");
    assert!(err.to_string().contains("target path cannot be empty"));
}

#[test]
fn manifest_add_artifact_classifies_remote_inputs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let remote_file = dir.path().join("remote.txt");
    let remote_tar = dir.path().join("remote.tar");
    fs::write(&remote_file, b"remote").expect("write remote file");
    fs::write(
        &remote_tar,
        build_tar([TarFixtureEntry::File {
            path: "payload.txt",
            mode: 0o644,
            data: b"payload",
        }]),
    )
    .expect("write remote tar");
    let remote_file_url = file_url(&remote_file);
    let tar_url = file_url(&remote_tar);
    let cache = host_cache(None);

    let mut manifest = Manifest::new(&path, ARCH, None);
    smol::block_on(async {
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: remote_file_url.clone(),
                    target: Some("/srv/remote.txt".to_string()),
                },
                None,
                &cache,
            )
            .await
            .expect("add remote file");
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: tar_url.clone(),
                    target: Some("/srv/tree".to_string()),
                },
                None,
                &cache,
            )
            .await
            .expect("add remote tar");
    });

    let remote_file_artifact = manifest
        .artifact(&remote_file_url)
        .expect("remote file artifact");
    assert!(matches!(remote_file_artifact, Artifact::File(_)));
    assert!(remote_file_artifact.is_remote());

    let remote_tar_artifact = manifest.artifact(&tar_url).expect("remote tar artifact");
    assert!(matches!(remote_tar_artifact, Artifact::Tar(_)));
    assert!(remote_tar_artifact.is_remote());

    let err = smol::block_on(async {
        manifest
            .add_artifact(
                None,
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: remote_file_url.clone(),
                    target: None,
                },
                None,
                &cache,
            )
            .await
    })
    .expect_err("remote file without target");
    assert!(err
        .to_string()
        .contains("target must be specified for a file"));
}

#[test]
fn text_artifact_public_api_and_staging_cover_targets_modes_and_remote_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let mut artifact = load_artifact(
        &manifest_path,
        "note",
        "type = \"text\"\ntext = \"hello from text\\n\"\ntarget = \"etc/messages/\"\nmode = 0o600\narch = \"arm64\"",
    );

    let (hash, size) = smol::block_on(artifact.hash_local("unused")).expect("hash text");
    assert_eq!(hash, artifact.hash());
    assert_eq!(size, artifact.size());
    assert_eq!(size, "hello from text\n".len() as u64);
    assert!(artifact.is_local());
    assert_eq!(artifact.target(), Some("etc/messages/"));
    assert_eq!(artifact.uri(), "note");
    assert_eq!(artifact.arch(), Some("arm64"));

    let fs = smol::block_on(HostFileSystem::new(dir.path(), false)).expect("host fs");
    let (staged_hash, staged_size) =
        smol::block_on(artifact.hash_stage_local("unused", &fs)).expect("hash stage text");
    assert_eq!(staged_hash, hash);
    assert_eq!(staged_size, size);

    let stage = smol::block_on(artifact.local::<_, HostFileSystem>("unused")).expect("text stage");
    stage_boxed_to_root(stage, dir.path()).expect("stage text");
    let staged_path = dir.path().join("etc/messages/note");
    assert_eq!(
        fs::read_to_string(&staged_path).expect("read staged text"),
        "hello from text\n"
    );
    assert_eq!(
        fs::metadata(&staged_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );

    let digest = spec_digest(&artifact);
    assert_ne!(digest, [0u8; 32]);

    let err = smol::block_on(artifact.hash_remote(smol::io::Cursor::new(b"ignored")))
        .expect_err("text remote hash should fail");
    assert!(err
        .to_string()
        .contains("inline text artifacts do not support remote readers"));

    let err = smol::block_on(artifact.hash_stage_remote(smol::io::Cursor::new(b"ignored"), &fs))
        .expect_err("text remote stage hash should fail");
    assert!(err
        .to_string()
        .contains("inline text artifacts do not support remote readers"));

    let err = match artifact.remote::<_, HostFileSystem>(smol::io::Cursor::new(b"ignored")) {
        Ok(_) => panic!("text remote stage should fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("inline text artifacts do not support remote readers"));
}

#[test]
fn file_artifact_local_hash_and_stage_cover_small_large_modes_and_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let small_path = dir.path().join("small.bin");
    let large_path = dir.path().join("large.bin");
    let mode_path = dir.path().join("exec.sh");
    let zero_mode_path = dir.path().join("zero.txt");
    let file_dir = dir.path().join("not-a-file");
    fs::write(&small_path, b"small file\n").expect("write small");
    fs::write(&large_path, vec![b'x'; 70_000]).expect("write large");
    fs::write(&mode_path, b"#!/bin/sh\nexit 0\n").expect("write exec");
    fs::write(&zero_mode_path, b"bad").expect("write zero");
    fs::create_dir_all(&file_dir).expect("create dir");
    fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o755)).expect("chmod exec");
    fs::set_permissions(&zero_mode_path, fs::Permissions::from_mode(0o0)).expect("chmod zero");

    let mut exec_artifact = load_artifact(
        &manifest_path,
        "./exec.sh",
        &format!(
            "type = \"file\"\ntarget = \"usr/local/bin/\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let exec_hash = smol::block_on(exec_artifact.hash_local(&mode_path)).expect("hash exec");
    assert_eq!(exec_hash.0, exec_artifact.hash());
    let stage = smol::block_on(exec_artifact.local::<_, HostFileSystem>(&mode_path))
        .expect("local file stage");
    stage_boxed_to_root(stage, dir.path()).expect("stage exec");
    let exec_target = dir.path().join("usr/local/bin/exec.sh");
    assert_eq!(
        fs::metadata(&exec_target)
            .expect("exec metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );

    let mut small_artifact = load_artifact(
        &manifest_path,
        "./small.bin",
        &format!(
            "type = \"file\"\ntarget = \"/srv/small.bin\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let (small_hash, small_size) =
        smol::block_on(small_artifact.hash_local(&small_path)).expect("hash small file");
    assert_eq!(small_hash, small_artifact.hash());
    assert_eq!(small_size, b"small file\n".len() as u64);

    let mut large_artifact = load_artifact(
        &manifest_path,
        "./large.bin",
        &format!(
            "type = \"file\"\ntarget = \"/srv/large.bin\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let (large_hash, large_size) =
        smol::block_on(large_artifact.hash_local(&large_path)).expect("hash large file");
    assert_eq!(large_hash, large_artifact.hash());
    assert_eq!(large_size, 70_000);

    let fs = smol::block_on(HostFileSystem::new(dir.path(), false)).expect("host fs");
    let (staged_hash, staged_size) =
        smol::block_on(exec_artifact.hash_stage_local(&mode_path, &fs))
            .expect("hash stage local file");
    assert_eq!(staged_hash, exec_artifact.hash());
    assert_eq!(staged_size, exec_artifact.size());

    let err = smol::block_on(small_artifact.hash_local(&file_dir)).expect_err("directory as file");
    assert!(err.to_string().contains("is not a regular file"));

    let err =
        smol::block_on(large_artifact.hash_local(&zero_mode_path)).expect_err("zero perms file");
    assert!(
        err.to_string().contains("has invalid permissions set 0")
            || err
                .to_string()
                .contains("failed to open local artifact file")
    );
}

#[test]
fn file_artifact_remote_hash_and_stage_cover_plain_compressed_and_target_derivation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let payload = b"plain remote payload\n";
    let mut remote_plain = load_artifact(
        &manifest_path,
        "https://example.invalid/files/payload.txt?download=1#frag",
        &format!(
            "type = \"file\"\ntarget = \"var/cache/\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let (hash, size) =
        smol::block_on(remote_plain.hash_remote(smol::io::Cursor::new(payload))).expect("hash");
    assert_eq!(hash, remote_plain.hash());
    assert_eq!(size, payload.len() as u64);
    let stage = remote_plain
        .remote::<_, HostFileSystem>(smol::io::Cursor::new(payload))
        .expect("remote file stage");
    stage_boxed_to_root(stage, dir.path()).expect("stage plain remote file");
    assert_eq!(
        fs::read(dir.path().join("var/cache/payload.txt")).expect("read staged plain file"),
        payload
    );

    let gzip_source = dir.path().join("payload.txt.gz");
    let compressed =
        smol::block_on(write_gzip(&gzip_source, b"compressed payload\n")).expect("write gzip");
    let mut remote_gzip = load_artifact(
        &manifest_path,
        "https://example.invalid/files/payload.txt.gz",
        &format!(
            "type = \"file\"\ntarget = \"/srv/unpacked.txt\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let fs = smol::block_on(HostFileSystem::new(dir.path(), false)).expect("host fs");
    smol::block_on(remote_gzip.hash_stage_remote(smol::io::Cursor::new(compressed.clone()), &fs))
        .expect("hash stage gzip");
    assert_eq!(
        fs::read_to_string(dir.path().join("srv/unpacked.txt")).expect("read unpacked"),
        "compressed payload\n"
    );
    let (remote_hash, remote_size) =
        smol::block_on(remote_gzip.hash_remote(smol::io::Cursor::new(compressed.clone())))
            .expect("hash remote gzip");
    assert_eq!(remote_hash, remote_gzip.hash());
    assert_eq!(remote_size, compressed.len() as u64);
    let gzip_stage_root = tempfile::tempdir().expect("gzip remote stage root");
    let stage = remote_gzip
        .remote::<_, HostFileSystem>(smol::io::Cursor::new(compressed.clone()))
        .expect("remote gzip stage");
    stage_boxed_to_root(stage, gzip_stage_root.path()).expect("stage remote gzip");
    assert_eq!(
        fs::read_to_string(gzip_stage_root.path().join("srv/unpacked.txt"))
            .expect("read remotely staged unpacked"),
        "compressed payload\n"
    );

    let mut remote_raw = load_artifact(
        &manifest_path,
        "https://example.invalid/files/raw.txt.gz",
        &format!(
            "type = \"file\"\ntarget = \"/srv/raw.txt.gz\"\nunpack = false\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    smol::block_on(remote_raw.hash_stage_remote(smol::io::Cursor::new(compressed.clone()), &fs))
        .expect("hash stage raw gzip");
    assert_eq!(
        fs::read(dir.path().join("srv/raw.txt.gz")).expect("read raw gzip"),
        compressed
    );

    let mut bad_target = load_artifact(
        &manifest_path,
        "file://",
        &format!(
            "type = \"file\"\ntarget = \"/srv/out/\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let err = smol::block_on(bad_target.hash_stage_remote(smol::io::Cursor::new(b"ignored"), &fs))
        .expect_err("file without derivable filename");
    assert!(err
        .to_string()
        .contains("cannot derive file name from artifact URI"));
}

#[test]
fn tar_artifact_hash_and_stage_cover_links_targets_and_validation_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let tar_bytes = build_tar([
        TarFixtureEntry::Directory {
            path: "bin",
            mode: 0o755,
        },
        TarFixtureEntry::File {
            path: "bin/tool",
            mode: 0o755,
            data: b"tool\n",
        },
        TarFixtureEntry::Symlink {
            path: "bin/tool-link",
            mode: 0o777,
            target: "tool",
        },
        TarFixtureEntry::Hardlink {
            path: "bin/tool-hard",
            mode: 0o755,
            target: "bin/tool",
        },
    ]);
    let tar_path = dir.path().join("artifact.tar");
    fs::write(&tar_path, &tar_bytes).expect("write tar");

    let mut artifact = load_artifact(
        &manifest_path,
        "artifact.tar",
        &format!(
            "type = \"tar\"\ntarget = \"opt/root\"\nsize = 0\nhash = \"{}\"\narch = \"amd64\"",
            zero_sri()
        ),
    );
    let (hash, size) = smol::block_on(artifact.hash_local(&tar_path)).expect("hash tar");
    assert_eq!(hash, artifact.hash());
    assert_eq!(size, tar_bytes.len() as u64);
    assert_eq!(artifact.arch(), Some("amd64"));
    assert_eq!(artifact.target(), Some("opt/root"));
    let stage = smol::block_on(artifact.local::<_, HostFileSystem>(&tar_path)).expect("local tar");
    let local_root = tempfile::tempdir().expect("local tar root");
    stage_boxed_to_root(stage, local_root.path()).expect("stage local tar");
    assert_eq!(
        fs::read_to_string(local_root.path().join("opt/root/bin/tool")).expect("read tool"),
        "tool\n"
    );
    assert_eq!(
        fs::read_link(local_root.path().join("opt/root/bin/tool-link")).expect("read symlink"),
        PathBuf::from("tool")
    );
    let tool_meta =
        fs::metadata(local_root.path().join("opt/root/bin/tool")).expect("tool metadata");
    let hard_meta =
        fs::metadata(local_root.path().join("opt/root/bin/tool-hard")).expect("hardlink metadata");
    assert_eq!(tool_meta.ino(), hard_meta.ino());

    let remote_root = tempfile::tempdir().expect("remote tar root");
    let fs = smol::block_on(HostFileSystem::new(remote_root.path(), false)).expect("host fs");
    let local_stage_root = tempfile::tempdir().expect("tar local hash-stage root");
    let local_fs =
        smol::block_on(HostFileSystem::new(local_stage_root.path(), false)).expect("local host fs");
    smol::block_on(artifact.hash_stage_local(&tar_path, &local_fs)).expect("hash stage local tar");
    smol::block_on(artifact.hash_stage_remote(smol::io::Cursor::new(tar_bytes.clone()), &fs))
        .expect("hash stage remote tar");
    let remote_stage_root = tempfile::tempdir().expect("tar remote stage root");
    let stage = artifact
        .remote::<_, HostFileSystem>(smol::io::Cursor::new(tar_bytes.clone()))
        .expect("remote tar stage");
    stage_boxed_to_root(stage, remote_stage_root.path()).expect("stage remote tar");

    let mut absolute = load_artifact(
        &manifest_path,
        "abs.tar",
        &format!("type = \"tar\"\nsize = 0\nhash = \"{}\"", zero_sri()),
    );
    let err = smol::block_on(absolute.hash_remote(smol::io::Cursor::new(build_tar([
        TarFixtureEntry::File {
            path: "/absolute.txt",
            mode: 0o644,
            data: b"bad",
        },
    ]))))
    .expect_err("absolute tar path");
    assert!(err
        .to_string()
        .contains("archive entry path must be relative"));

    let mut parent = load_artifact(
        &manifest_path,
        "parent.tar",
        &format!("type = \"tar\"\nsize = 0\nhash = \"{}\"", zero_sri()),
    );
    let err = smol::block_on(parent.hash_remote(smol::io::Cursor::new(build_tar([
        TarFixtureEntry::File {
            path: "../escape.txt",
            mode: 0o644,
            data: b"bad",
        },
    ]))))
    .expect_err("parent dir tar path");
    assert!(err
        .to_string()
        .contains("archive entry path must not contain '..'"));

    let mut unsupported = load_artifact(
        &manifest_path,
        "unsupported.tar",
        &format!("type = \"tar\"\nsize = 0\nhash = \"{}\"", zero_sri()),
    );
    let err = smol::block_on(unsupported.hash_remote(smol::io::Cursor::new(build_tar([
        TarFixtureEntry::Fifo {
            path: "pipe",
            mode: 0o644,
        },
    ]))))
    .expect_err("unsupported tar entry");
    assert!(err.to_string().contains("unsupported tar entry"));
}

#[test]
fn directory_artifact_hash_stage_and_copy_cover_tree_processing_and_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let source = dir.path().join("tree");
    fs::create_dir_all(source.join("nested")).expect("create nested dir");
    fs::write(source.join("nested/small.txt"), b"small").expect("write small file");
    fs::write(source.join("nested/large.bin"), vec![b'z'; 20_000]).expect("write large file");
    symlink("small.txt", source.join("nested/link.txt")).expect("create symlink");

    let mut artifact = load_artifact(
        &manifest_path,
        "tree",
        &format!(
            "type = \"dir\"\ntarget = \"/staged/tree\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let (hash, size) = smol::block_on(artifact.hash_local(&source)).expect("hash directory");
    assert_eq!(hash, artifact.hash());
    assert!(size >= 20_001);
    assert!(artifact.is_local());

    let first_root = tempfile::tempdir().expect("first stage root");
    let fs = smol::block_on(HostFileSystem::new(first_root.path(), false)).expect("host fs");
    let (stage_hash, stage_size) =
        smol::block_on(artifact.hash_stage_local(&source, &fs)).expect("hash stage directory");
    assert_eq!(stage_hash, artifact.hash());
    assert_eq!(stage_size, artifact.size());
    assert_eq!(
        fs::read_to_string(first_root.path().join("staged/tree/nested/small.txt"))
            .expect("read staged"),
        "small"
    );
    assert_eq!(
        fs::read_link(first_root.path().join("staged/tree/nested/link.txt")).expect("read symlink"),
        PathBuf::from("small.txt")
    );

    let verified_root = tempfile::tempdir().expect("verified root");
    let stage = smol::block_on(artifact.local::<_, HostFileSystem>(&source)).expect("local tree");
    stage_boxed_to_root(stage, verified_root.path()).expect("stage verified tree");

    fs::write(source.join("nested/small.txt"), b"changed").expect("mutate source");
    let mismatch_root = tempfile::tempdir().expect("mismatch root");
    let stage =
        smol::block_on(artifact.local::<_, HostFileSystem>(&source)).expect("stale local stage");
    let err = stage_boxed_to_root(stage, mismatch_root.path()).expect_err("hash mismatch");
    assert!(err
        .to_string()
        .contains("hash mismatch after copying local tree"));

    let err = smol::block_on(artifact.hash_remote(smol::io::Cursor::new(b"ignored")))
        .expect_err("dir remote hash");
    assert!(err
        .to_string()
        .contains("directory artifacts do not support remote readers"));
    let dir_fs = smol::block_on(HostFileSystem::new(dir.path(), false)).expect("dir host fs");
    let err =
        smol::block_on(artifact.hash_stage_remote(smol::io::Cursor::new(b"ignored"), &dir_fs))
            .expect_err("dir remote hash-stage");
    assert!(err
        .to_string()
        .contains("directory artifacts do not support remote readers"));
    let err = match artifact.remote::<_, HostFileSystem>(smol::io::Cursor::new(b"ignored")) {
        Ok(_) => panic!("dir remote stage should fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("directory artifacts do not support remote readers"));
}

#[test]
fn artifact_update_spec_hash_changes_with_kind_and_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let text_a = load_artifact(
        &manifest_path,
        "note-a",
        "type = \"text\"\ntext = \"hello\"\ntarget = \"/etc/note\"\nmode = 0o644",
    );
    let text_b = load_artifact(
        &manifest_path,
        "note-b",
        "type = \"text\"\ntext = \"hello\"\ntarget = \"/etc/note\"\nmode = 0o600",
    );
    let file = load_artifact(
        &manifest_path,
        "plain.txt",
        &format!(
            "type = \"file\"\ntarget = \"/opt/plain.txt\"\nunpack = false\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let tree = load_artifact(
        &manifest_path,
        "tree",
        &format!(
            "type = \"dir\"\ntarget = \"/opt/tree\"\narch = \"amd64\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );
    let tar = load_artifact(
        &manifest_path,
        "archive.tar",
        &format!(
            "type = \"tar\"\ntarget = \"/opt/archive\"\nsize = 0\nhash = \"{}\"",
            zero_sri()
        ),
    );

    assert_ne!(spec_digest(&text_a), spec_digest(&text_b));
    assert_ne!(spec_digest(&text_a), spec_digest(&file));
    assert_ne!(spec_digest(&file), spec_digest(&tree));
    assert_ne!(spec_digest(&tree), spec_digest(&tar));
}

#[test]
fn directory_hash_cli_path_supports_all_algorithms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tree = dir.path().join("tree");
    fs::create_dir_all(tree.join("nested")).expect("create nested");
    fs::write(tree.join("nested/file.txt"), b"data").expect("write file");

    let conf = common::TestConfig::new(PathBuf::from("unused.toml"), TestProvider::new());
    for algo in ["md5", "sha1", "sha256", "sha512", "blake3"] {
        debrepo::cli::cmd::Tool::try_parse_from([
            "tool",
            "hash",
            algo,
            tree.to_str().expect("utf8 path"),
        ])
        .expect("parse tool hash")
        .exec(&conf)
        .expect("hash directory");
    }
}
