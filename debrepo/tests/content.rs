mod common;

use {
    common::{one, ARCH},
    debrepo::{
        artifact::Artifact,
        auth::AuthProvider,
        content::{ContentProvider, ContentProviderGuard, DebLocation, HostCache},
        hash::Hash,
        Archive, HostFileSystem, Manifest, Stage,
    },
    sha2::{Digest, Sha256},
    smol::io::AsyncWriteExt,
    std::{
        fs, io,
        path::{Path, PathBuf},
    },
};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/deb")
        .join(name)
}

fn host_cache(cache: Option<&Path>) -> HostCache {
    HostCache::new(
        debrepo::HttpTransport::new(AuthProvider::new::<&str>(None).expect("auth"), false, false),
        cache,
    )
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn sha256_sri(data: &[u8]) -> String {
    Hash::from_hex("SHA256", sha256_hex(data))
        .expect("hash from hex")
        .to_sri()
}

fn zero_sha256_sri() -> String {
    Hash::default().to_sri()
}

fn file_url(path: &Path) -> String {
    url::Url::from_file_path(path)
        .expect("file url")
        .to_string()
}

fn dir_url(path: &Path) -> String {
    url::Url::from_directory_path(path)
        .expect("dir url")
        .to_string()
}

async fn write_compressed(path: &Path, ext: &str, data: &[u8]) -> io::Result<(String, u64)> {
    if let Some(parent) = path.parent() {
        smol::fs::create_dir_all(parent).await?;
    }
    let file = smol::fs::File::create(path).await?;
    let mut writer = debrepo::packer(ext, file, debrepo::CompressionLevel::Default);
    writer.write_all(data).await?;
    writer.close().await?;
    let bytes = smol::fs::read(path).await?;
    Ok((sha256_hex(&bytes), bytes.len() as u64))
}

async fn stage_boxed_to_root<T>(
    mut stage: Box<dyn Stage<Target = HostFileSystem, Output = T> + Send + 'static>,
    root: &Path,
) -> io::Result<T> {
    let fs = HostFileSystem::new(root, false).await?;
    stage.stage(&fs).await
}

fn artifact_manifest_text(key: &str, body: &str) -> String {
    format!("[artifact.\"{key}\"]\n{body}\n")
}

fn load_artifact(path: &Path, key: &str, body: &str) -> Artifact {
    fs::write(path, artifact_manifest_text(key, body)).expect("write manifest");
    let (manifest, _) = smol::block_on(Manifest::from_file(path, ARCH)).expect("load manifest");
    manifest.artifact(key).expect("artifact").clone()
}

fn package_source_from(
    file_path: &str,
    size: u64,
    hash: &Hash,
    package: &str,
    version: &str,
) -> String {
    format!(
        "\
Package: {package}
Architecture: {ARCH}
Version: {version}
Filename: {file_path}
Size: {size}
SHA256: {hash}
Description: content test package
",
        hash = hash.to_hex(),
    )
}

fn source_text(package: &str, binary: &str, version: &str, directory: &str, file: &str) -> String {
    format!(
        "\
Package: {package}
Binary: {binary}
Version: {version}
Maintainer: Example Maintainer <example@example.invalid>
Format: 3.0 (quilt)
Checksums-Sha256:
 {hash} {size} {file}
Directory: {directory}
Section: misc
Priority: optional
",
        hash = "2".repeat(64),
        size = 10,
    )
}

async fn build_archive_repo(
    pkg_index: &str,
    src_index: &str,
) -> io::Result<(tempfile::TempDir, Archive, String)> {
    let repo = tempfile::tempdir().expect("repo tempdir");
    let pool_dir = repo.path().join("pool/main/f");
    fs::create_dir_all(&pool_dir)?;
    fs::copy(
        fixture_path("rich-xz.deb"),
        pool_dir.join("fixture-rich.deb"),
    )?;

    let packages_path = repo
        .path()
        .join("dists/stable/main/binary-amd64/Packages.xz");
    let sources_path = repo.path().join("dists/stable/main/source/Sources.gz");
    let (packages_hash, packages_size) =
        write_compressed(&packages_path, "Packages.xz", pkg_index.as_bytes()).await?;
    let (sources_hash, sources_size) =
        write_compressed(&sources_path, "Sources.gz", src_index.as_bytes()).await?;

    let release_text = format!(
        "\
Origin: test
Label: test
Suite: stable
Codename: stable
Architectures: amd64
Components: main
No-Support-for-Architecture-all: Packages
SHA256:
 {packages_hash} {packages_size} main/binary-amd64/Packages.xz
 {sources_hash} {sources_size} main/source/Sources.gz
"
    );
    let release_path = repo.path().join("dists/stable/Release");
    fs::create_dir_all(release_path.parent().expect("release parent"))?;
    fs::write(&release_path, release_text)?;

    let mut archive = Archive::default();
    archive.url = dir_url(repo.path());
    archive.allow_insecure = true;
    archive.suites = vec!["stable".to_string()];
    archive.components = vec!["main".to_string()];
    Ok((repo, archive, "fixture-rich".to_string()))
}

#[test]
fn deblocation_display_and_hostcache_init_commit_cover_public_helpers() {
    let local_path = fixture_path("rich-xz.deb");
    let local = DebLocation::Local {
        path: "pool/main/f/fixture-rich.deb",
        base: &local_path,
    };
    let repo = DebLocation::Repository {
        url: "https://example.invalid/debian",
        path: "pool/main/f/fixture-rich.deb",
    };
    assert_eq!(local.to_string(), "local:pool/main/f/fixture-rich.deb");
    assert_eq!(
        repo.to_string(),
        "https://example.invalid/debian/pool/main/f/fixture-rich.deb"
    );

    let cache_dir = tempfile::tempdir().expect("cache tempdir");
    let cached = host_cache(Some(cache_dir.path()));
    let uncached = host_cache(None);

    smol::block_on(async {
        let guard = cached.init().await.expect("init cached");
        assert!(cache_dir.path().exists());
        guard.commit().await.expect("commit cached");

        let guard = uncached.init().await.expect("init uncached");
        guard.commit().await.expect("commit uncached");
    });
}

#[test]
fn ensure_deb_and_fetch_deb_cover_local_remote_and_cache_paths() {
    let fixture = fixture_path("rich-xz.deb");
    let fixture_dir = fixture.parent().expect("fixture dir");
    let fixture_name = fixture
        .file_name()
        .and_then(|name| name.to_str())
        .expect("fixture file name");
    let cache = host_cache(None);

    let (repo_file, ctrl) =
        smol::block_on(cache.ensure_deb("pool/main/f/fixture-rich.deb", &fixture))
            .expect("ensure deb");
    assert_eq!(repo_file.path(), "pool/main/f/fixture-rich.deb");
    assert_eq!(ctrl.field("Filename"), Some("pool/main/f/fixture-rich.deb"));
    assert_eq!(ctrl.field("Package"), Some("fixture-rich"));
    assert_eq!(
        ctrl.field("SHA256"),
        Some(repo_file.hash().to_hex().as_str())
    );

    let local_root = tempfile::tempdir().expect("local root");
    smol::block_on(async {
        let stage = cache
            .fetch_deb(
                repo_file.hash().clone(),
                repo_file.size(),
                &DebLocation::Local {
                    path: fixture_name,
                    base: &fixture,
                },
            )
            .await
            .expect("fetch local deb");
        let ctrl = stage_boxed_to_root(stage, local_root.path())
            .await
            .expect("stage local deb");
        assert_eq!(ctrl.field("Package"), Some("fixture-rich"));
    });
    assert!(local_root.path().join("usr/bin/fixture-rich").exists());

    let remote_root = tempfile::tempdir().expect("remote root");
    let remote_base = dir_url(fixture_dir);
    smol::block_on(async {
        let stage = cache
            .fetch_deb(
                repo_file.hash().clone(),
                repo_file.size(),
                &DebLocation::Repository {
                    url: &remote_base,
                    path: fixture_name,
                },
            )
            .await
            .expect("fetch remote deb");
        let ctrl = stage_boxed_to_root(stage, remote_root.path())
            .await
            .expect("stage remote deb");
        assert_eq!(ctrl.field("Package"), Some("fixture-rich"));
    });
    assert!(remote_root.path().join("usr/bin/fixture-rich").exists());

    let cache_dir = tempfile::tempdir().expect("deb cache");
    let cached = host_cache(Some(cache_dir.path()));
    let cached_root = tempfile::tempdir().expect("cached root");
    smol::block_on(async {
        let stage = cached
            .fetch_deb(
                repo_file.hash().clone(),
                repo_file.size(),
                &DebLocation::Repository {
                    url: &remote_base,
                    path: fixture_name,
                },
            )
            .await
            .expect("fetch cached remote deb");
        stage_boxed_to_root(stage, cached_root.path())
            .await
            .expect("stage cached remote deb");
    });
    let deb_cache_path = repo_file
        .hash()
        .store_name(Some(cache_dir.path()), Some("deb"), 1);
    assert!(deb_cache_path.exists());

    let removed = fixture_dir.join(fixture_name);
    let backup = fixture_dir.join("rich-xz.deb.content-backup");
    fs::rename(&removed, &backup).expect("backup fixture");
    let cache_hit_root = tempfile::tempdir().expect("cache hit root");
    smol::block_on(async {
        let stage = cached
            .fetch_deb(
                repo_file.hash().clone(),
                repo_file.size(),
                &DebLocation::Repository {
                    url: &remote_base,
                    path: fixture_name,
                },
            )
            .await
            .expect("fetch deb from cache");
        stage_boxed_to_root(stage, cache_hit_root.path())
            .await
            .expect("stage cached deb");
    });
    fs::rename(&backup, &removed).expect("restore fixture");
    assert!(cache_hit_root.path().join("usr/bin/fixture-rich").exists());
}

#[test]
fn ensure_and_fetch_artifact_cover_text_and_local_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let local_path = dir.path().join("local.txt");
    fs::write(&local_path, b"local artifact\n").expect("write local artifact");

    let text_artifact = load_artifact(
        &manifest_path,
        "inline",
        "type = \"text\"\ntext = \"hello from text\\n\"\ntarget = \"/etc/message.txt\"",
    );
    let mut local_artifact = load_artifact(
        &manifest_path,
        "./local.txt",
        &format!(
            "type = \"file\"\ntarget = \"/opt/local.txt\"\nsize = 0\nhash = \"{}\"",
            zero_sha256_sri()
        ),
    );
    let cache = host_cache(None);

    smol::block_on(async {
        cache
            .ensure_artifact(&mut text_artifact.clone(), None)
            .await
            .expect("ensure text artifact");

        cache
            .ensure_artifact(&mut local_artifact, Some(&local_path))
            .await
            .expect("ensure local artifact");
        assert_eq!(local_artifact.size(), b"local artifact\n".len() as u64);

        let err = cache
            .ensure_artifact(&mut local_artifact.clone(), None)
            .await
            .expect_err("missing local base path");
        assert!(err.to_string().contains("missing local base path"));

        let text_stage = cache
            .fetch_artifact(&text_artifact, None)
            .await
            .expect("fetch text artifact");
        stage_boxed_to_root(text_stage, dir.path())
            .await
            .expect("stage text artifact");

        let local_stage = cache
            .fetch_artifact(&local_artifact, Some(&local_path))
            .await
            .expect("fetch local artifact");
        stage_boxed_to_root(local_stage, dir.path())
            .await
            .expect("stage local artifact");

        let err = match cache.fetch_artifact(&local_artifact, None).await {
            Ok(_) => panic!("missing local base path for fetch"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("missing local base path"));
    });

    assert_eq!(
        fs::read_to_string(dir.path().join("etc/message.txt")).expect("read text target"),
        "hello from text\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("opt/local.txt")).expect("read local target"),
        "local artifact\n"
    );
}

#[test]
fn ensure_and_fetch_artifact_cover_remote_paths_and_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let remote_source = dir.path().join("remote.txt");
    let remote_bytes = b"remote artifact\n";
    fs::write(&remote_source, remote_bytes).expect("write remote source");
    let remote_url = file_url(&remote_source);

    let mut remote_artifact = load_artifact(
        &manifest_path,
        &remote_url,
        &format!(
            "type = \"file\"\ntarget = \"/srv/remote.txt\"\nsize = 0\nhash = \"{}\"",
            zero_sha256_sri()
        ),
    );
    let cache = host_cache(None);

    smol::block_on(async {
        cache
            .ensure_artifact(&mut remote_artifact, None)
            .await
            .expect("ensure remote artifact");
        assert_eq!(remote_artifact.size(), remote_bytes.len() as u64);
        assert_ne!(remote_artifact.hash(), Hash::default());

        let stage = cache
            .fetch_artifact(&remote_artifact, None)
            .await
            .expect("fetch remote artifact without cache");
        stage_boxed_to_root(stage, dir.path())
            .await
            .expect("stage remote artifact without cache");
    });
    assert_eq!(
        fs::read_to_string(dir.path().join("srv/remote.txt")).expect("read remote target"),
        "remote artifact\n"
    );

    let cache_dir = tempfile::tempdir().expect("artifact cache");
    let cached = host_cache(Some(cache_dir.path()));
    let cached_manifest_path = dir.path().join("CachedManifest.toml");
    let cached_artifact = load_artifact(
        &cached_manifest_path,
        &remote_url,
        &format!(
            "type = \"file\"\ntarget = \"/srv/cached.txt\"\nsize = {}\nhash = \"{}\"",
            remote_bytes.len(),
            sha256_sri(remote_bytes)
        ),
    );

    smol::block_on(async {
        let stage = cached
            .fetch_artifact(&cached_artifact, None)
            .await
            .expect("fetch remote artifact with cache");
        stage_boxed_to_root(stage, dir.path())
            .await
            .expect("stage remote artifact with cache");
    });
    let artifact_cache_path =
        cached_artifact
            .hash()
            .store_name(Some(cache_dir.path()), Some("file"), 1);
    assert!(artifact_cache_path.exists());

    fs::remove_file(&remote_source).expect("remove remote source");
    smol::block_on(async {
        let stage = cached
            .fetch_artifact(&cached_artifact, None)
            .await
            .expect("fetch remote artifact from cache");
        stage_boxed_to_root(stage, dir.path())
            .await
            .expect("stage remote artifact from cache");
    });
    assert_eq!(
        fs::read_to_string(dir.path().join("srv/cached.txt")).expect("read cached target"),
        "remote artifact\n"
    );
}

#[test]
fn fetch_artifact_reports_remote_open_errors_with_context() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing.txt");
    let missing_url = file_url(&missing);
    let manifest_path = dir.path().join("Manifest.toml");
    let artifact = load_artifact(
        &manifest_path,
        &missing_url,
        &format!(
            "type = \"file\"\ntarget = \"/srv/missing.txt\"\nsize = 0\nhash = \"{}\"",
            zero_sha256_sri()
        ),
    );
    let cache = host_cache(None);

    let err = match smol::block_on(cache.fetch_artifact(&artifact, None)) {
        Ok(_) => panic!("fetch should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("failed to open remote artifact"));
    assert!(err.to_string().contains(&missing_url));
}

#[test]
fn fetch_index_and_release_files_cover_cache_and_plain_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let release_text = "Origin: test\nSuite: stable\n";
    let release_path = dir.path().join("Release");
    fs::write(&release_path, release_text).expect("write release");

    let index_text = "Package: demo\nVersion: 1\nArchitecture: amd64\n\n";
    let index_path = dir.path().join("Packages.xz");
    let (index_hash_hex, index_size) = smol::block_on(write_compressed(
        &index_path,
        "Packages.xz",
        index_text.as_bytes(),
    ))
    .expect("write compressed index");
    let index_hash = Hash::from_hex("SHA256", &index_hash_hex).expect("index hash");
    let index_url = file_url(&index_path);

    let uncached = host_cache(None);
    let index = smol::block_on(uncached.fetch_index_file(
        index_hash.clone(),
        index_size,
        &index_url,
        "Packages.xz",
    ))
    .expect("fetch index without cache");
    assert_eq!(index.as_str(), index_text);

    let release = smol::block_on(uncached.fetch_release_file(&file_url(&release_path)))
        .expect("fetch release");
    assert_eq!(release.as_str(), release_text);

    let cache_dir = tempfile::tempdir().expect("index cache");
    let cached = host_cache(Some(cache_dir.path()));
    let first = smol::block_on(cached.fetch_index_file(
        index_hash.clone(),
        index_size,
        &index_url,
        "Packages.xz",
    ))
    .expect("fetch cached index");
    assert_eq!(first.as_str(), index_text);
    let cached_path = index_hash.store_name(Some(cache_dir.path()), Some("idx"), 1);
    assert!(cached_path.exists());

    fs::remove_file(&index_path).expect("remove source index");
    let second =
        smol::block_on(cached.fetch_index_file(index_hash, index_size, &index_url, "Packages.xz"))
            .expect("fetch index from cache");
    assert_eq!(second.as_str(), index_text);
}

#[test]
fn manifest_archive_flow_stages_apt_lists_when_opted_in() {
    let fixture = fixture_path("rich-xz.deb");
    let cache = host_cache(None);
    let (repo_file, ctrl) =
        smol::block_on(cache.ensure_deb("pool/main/f/fixture-rich.deb", &fixture))
            .expect("ensure fixture deb");
    let package_name = ctrl.field("Package").expect("package").to_string();
    let version = ctrl.field("Version").expect("version").to_string();
    let pkg_index = package_source_from(
        repo_file.path(),
        repo_file.size(),
        repo_file.hash(),
        &package_name,
        &version,
    );
    let src_index = source_text(
        "fixture-src",
        &package_name,
        &version,
        "pool/main/f/fixture-src",
        "fixture-src.dsc",
    );
    let (_repo, archive, _) =
        smol::block_on(build_archive_repo(&pkg_index, &src_index)).expect("build archive repo");

    let dir = tempfile::tempdir().expect("manifest dir");
    let manifest_path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::from_archives(&manifest_path, ARCH, [archive], None);
    manifest
        .add_requirements(None, [package_name.as_str()], None)
        .expect("add requirements");

    manifest
        .set_spec_meta(None, "apt-lists", "stage")
        .expect("set apt-lists meta");

    let stage_root = tempfile::tempdir().expect("stage root");
    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &cache)
            .await
            .expect("update manifest");
        manifest
            .load_source_universe(one(), &cache)
            .await
            .expect("load source universe");
        manifest
            .load_source_universe(one(), &cache)
            .await
            .expect("load source universe from cache");

        let fs = HostFileSystem::new(stage_root.path(), false)
            .await
            .expect("host fs");
        manifest
            .stage(
                None,
                None,
                &fs,
                one(),
                &cache,
                Option::<fn(u64) -> debrepo::cli::StageProgress>::None,
            )
            .await
            .expect("stage manifest");
    });

    let packages = manifest
        .universe_packages()
        .expect("packages iterator")
        .map(|pkg| pkg.name().to_string())
        .collect::<Vec<_>>();
    assert!(packages.contains(&package_name));
    assert!(stage_root.path().join("usr/bin/fixture-rich").exists());
    assert!(stage_root
        .path()
        .join("etc/apt/sources.list.d/manifest.sources")
        .exists());
    assert!(stage_root
        .path()
        .join("var/lib/apt/lists")
        .read_dir()
        .expect("read apt lists")
        .next()
        .is_some());
}

#[test]
fn manifest_archive_flow_skips_staging_apt_lists_without_opt_in() {
    let fixture = fixture_path("rich-xz.deb");
    let cache = host_cache(None);
    let (repo_file, ctrl) =
        smol::block_on(cache.ensure_deb("pool/main/f/fixture-rich.deb", &fixture))
            .expect("ensure fixture deb");
    let package_name = ctrl.field("Package").expect("package").to_string();
    let version = ctrl.field("Version").expect("version").to_string();
    let pkg_index = package_source_from(
        repo_file.path(),
        repo_file.size(),
        repo_file.hash(),
        &package_name,
        &version,
    );
    let src_index = source_text(
        "fixture-src",
        &package_name,
        &version,
        "pool/main/f/fixture-src",
        "fixture-src.dsc",
    );
    let (_repo, archive, _) =
        smol::block_on(build_archive_repo(&pkg_index, &src_index)).expect("build archive repo");

    let dir = tempfile::tempdir().expect("manifest dir");
    let manifest_path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::from_archives(&manifest_path, ARCH, [archive], None);
    manifest
        .add_requirements(None, [package_name.as_str()], None)
        .expect("add requirements");

    let stage_root = tempfile::tempdir().expect("stage root");
    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &cache)
            .await
            .expect("update manifest");

        let fs = HostFileSystem::new(stage_root.path(), false)
            .await
            .expect("host fs");
        manifest
            .stage(
                None,
                None,
                &fs,
                one(),
                &cache,
                Option::<fn(u64) -> debrepo::cli::StageProgress>::None,
            )
            .await
            .expect("stage manifest");
    });

    let packages = manifest
        .universe_packages()
        .expect("packages iterator")
        .map(|pkg| pkg.name().to_string())
        .collect::<Vec<_>>();
    assert!(packages.contains(&package_name));
    assert!(stage_root.path().join("usr/bin/fixture-rich").exists());
    assert!(!stage_root
        .path()
        .join("etc/apt/sources.list.d/manifest.sources")
        .exists());

    let apt_lists = stage_root.path().join("var/lib/apt/lists");
    assert!(
        !apt_lists.exists()
            || apt_lists
                .read_dir()
                .expect("read apt lists")
                .next()
                .is_none()
    );
}

#[test]
fn manifest_archive_flow_reports_invalid_packages_and_sources() {
    let cache = host_cache(None);

    let (_bad_repo, bad_archive, package_name) = smol::block_on(build_archive_repo(
        "not a packages index\n",
        "Package: ok\n",
    ))
    .expect("build bad package repo");
    let dir = tempfile::tempdir().expect("manifest dir");
    let manifest_path = dir.path().join("Manifest.toml");
    let mut bad_pkg_manifest = Manifest::from_archives(&manifest_path, ARCH, [bad_archive], None);
    bad_pkg_manifest
        .add_requirements(None, [package_name.as_str()], None)
        .expect("add requirements");
    let err = smol::block_on(bad_pkg_manifest.update(false, false, true, one(), &cache))
        .expect_err("invalid packages should fail");
    assert!(err.to_string().contains("failed to parse Packages file"));

    let fixture = fixture_path("rich-xz.deb");
    let (repo_file, ctrl) =
        smol::block_on(cache.ensure_deb("pool/main/f/fixture-rich.deb", &fixture))
            .expect("ensure fixture deb");
    let pkg_index = package_source_from(
        repo_file.path(),
        repo_file.size(),
        repo_file.hash(),
        ctrl.field("Package").expect("package"),
        ctrl.field("Version").expect("version"),
    );
    let (_bad_src_repo, bad_src_archive, package_name) =
        smol::block_on(build_archive_repo(&pkg_index, "not a sources index\n"))
            .expect("build bad source repo");
    let bad_src_path = dir.path().join("BadSources.toml");
    let mut bad_src_manifest =
        Manifest::from_archives(&bad_src_path, ARCH, [bad_src_archive], None);
    bad_src_manifest
        .add_requirements(None, [package_name.as_str()], None)
        .expect("add requirements");
    smol::block_on(bad_src_manifest.update(false, false, true, one(), &cache))
        .expect("update manifest with valid packages");
    let err = smol::block_on(bad_src_manifest.load_source_universe(one(), &cache))
        .expect_err("invalid sources should fail");
    assert!(err.to_string().contains("failed to parse Sources file"));
}
