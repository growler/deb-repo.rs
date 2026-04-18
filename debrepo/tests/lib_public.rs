use {
    clap::Parser,
    debrepo::{
        auth::AuthProvider,
        cli::{Command, Config},
        content::HostCache,
        HostFileSystem, HttpTransport, Packages,
    },
    smol::io::{AsyncReadExt, AsyncWriteExt, Cursor},
    std::{
        io,
        num::NonZero,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    },
};

const SHA256_DEMO: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

async fn roundtrip_with_public_helpers(ext: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(ext.replace('/', "_"));
    let file = smol::fs::File::create(&path).await?;
    let mut writer = debrepo::packer(ext, file, debrepo::CompressionLevel::Default);
    writer.write_all(payload).await?;
    writer.close().await?;

    let encoded = smol::fs::read(&path).await?;
    let mut reader = debrepo::unpacker(ext, Cursor::new(encoded));
    let mut decoded = Vec::new();
    reader.read_to_end(&mut decoded).await?;
    Ok(decoded)
}

struct TestConfig {
    manifest: PathBuf,
    cache: HostCache,
    concurrency: NonZero<usize>,
}

impl TestConfig {
    fn new() -> Self {
        Self {
            manifest: PathBuf::from("Manifest.toml"),
            cache: HostCache::new(
                HttpTransport::new(
                    AuthProvider::new::<&str>(None).expect("auth"),
                    false,
                    false,
                    None,
                ),
                None::<&Path>,
            ),
            concurrency: NonZero::new(1).expect("nonzero"),
        }
    }
}

impl Config for TestConfig {
    type FS = HostFileSystem;
    type Cache = HostCache;

    fn arch(&self) -> &str {
        "amd64"
    }

    fn manifest(&self) -> &Path {
        &self.manifest
    }

    fn concurrency(&self) -> NonZero<usize> {
        self.concurrency
    }

    fn fetcher(&self) -> io::Result<&Self::Cache> {
        Ok(&self.cache)
    }
}

#[derive(Parser)]
struct TypedAppTrailing {
    #[command(subcommand)]
    cmd: TypedCommandsTrailing,
}

#[derive(Parser)]
struct TypedAppFinal {
    #[command(subcommand)]
    cmd: TypedCommandsFinal,
}

#[derive(Parser)]
struct BareAppTrailing {
    #[command(subcommand)]
    cmd: BareCommandsTrailing,
}

#[derive(Parser)]
struct BareAppFinal {
    #[command(subcommand)]
    cmd: BareCommandsFinal,
}

#[derive(Parser)]
struct TypedEcho {
    #[arg(long)]
    label: String,
    #[arg(skip)]
    seen: Arc<AtomicUsize>,
}

impl Command<TestConfig> for TypedEcho {
    fn exec(&self, conf: &TestConfig) -> anyhow::Result<()> {
        assert_eq!(conf.arch(), "amd64");
        self.seen.fetch_add(self.label.len(), Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Parser)]
struct TypedFinal {
    #[arg(long)]
    label: String,
    #[arg(skip)]
    seen: Arc<AtomicUsize>,
}

impl Command<TestConfig> for TypedFinal {
    fn exec(&self, conf: &TestConfig) -> anyhow::Result<()> {
        assert_eq!(conf.manifest(), Path::new("Manifest.toml"));
        self.seen.fetch_add(self.label.len(), Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Parser)]
struct BareLocal {
    #[arg(skip)]
    seen: Arc<AtomicUsize>,
}

impl Command<TestConfig> for BareLocal {
    fn exec(&self, conf: &TestConfig) -> anyhow::Result<()> {
        assert_eq!(conf.concurrency().get(), 1);
        self.seen.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Parser)]
struct BareFinal {
    #[arg(skip)]
    seen: Arc<AtomicUsize>,
}

impl Command<TestConfig> for BareFinal {
    fn exec(&self, conf: &TestConfig) -> anyhow::Result<()> {
        conf.fetcher()?;
        self.seen.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

debrepo::cli_commands! {
    pub enum TypedCommandsTrailing<TestConfig> {
        #[command(name = "typed-renamed")]
        TypedEcho(TypedEcho),
    }
}

debrepo::cli_commands! {
    pub enum TypedCommandsFinal<TestConfig> {
        TypedFinal(TypedFinal)
    }
}

debrepo::cli_commands! {
    pub enum BareCommandsTrailing<TestConfig> {
        BareLocal,
    }
}

debrepo::cli_commands! {
    pub enum BareCommandsFinal<TestConfig> {
        BareFinal
    }
}

#[test]
fn url_helpers_cover_short_valid_and_invalid_inputs() {
    for input in ["", "a", "ab", "abc", "1://bad", "_://bad"] {
        assert!(!debrepo::is_url(input), "{input}");
        assert_eq!(debrepo::strip_url_scheme(input), input, "{input}");
    }

    for input in ["mailto:test", "http:/one-slash", "http:missing-slashes"] {
        assert!(!debrepo::is_url(input), "{input}");
        assert_eq!(debrepo::strip_url_scheme(input), input, "{input}");
    }

    for (input, stripped) in [
        ("https://example.invalid/path", "example.invalid/path"),
        ("git+ssh://example.invalid/repo", "example.invalid/repo"),
        ("custom-scheme.1://host/path", "host/path"),
    ] {
        assert!(debrepo::is_url(input), "{input}");
        assert_eq!(debrepo::strip_url_scheme(input), stripped, "{input}");
    }
}

#[test]
fn compression_helpers_roundtrip_all_public_variants() {
    smol::block_on(async {
        let payload = b"public helper roundtrip payload\n";
        for ext in [
            "Packages.gz",
            "Packages.xz",
            "Packages.bz2",
            "Packages.lzma",
            "Packages.zstd",
            "Packages.zst",
            "Packages",
        ] {
            let decoded = roundtrip_with_public_helpers(ext, payload)
                .await
                .expect("roundtrip payload");
            assert_eq!(decoded, payload, "{ext}");
        }
    });
}

#[test]
fn strip_compression_ext_covers_supported_suffixes_and_passthrough() {
    for (input, expected) in [
        ("Packages.gz", "Packages"),
        ("Packages.xz", "Packages"),
        ("Packages.bz2", "Packages"),
        ("Packages.lzma", "Packages"),
        ("Packages.zstd", "Packages"),
        ("Packages.zst", "Packages"),
        ("Packages", "Packages"),
        ("Packages.GZ", "Packages.GZ"),
        ("Packages.lz4", "Packages.lz4"),
    ] {
        assert_eq!(debrepo::strip_compression_ext(input), expected, "{input}");
    }
}

#[test]
fn packages_repo_file_reports_size_overflow_via_public_api() {
    let src = format!(
        "\
Package: demo
Architecture: amd64
Version: 1.0
Filename: pool/main/d/demo_1.0_amd64.deb
Size: 184467440737095516160
SHA256: {SHA256_DEMO}
"
    );
    let packages = Packages::try_from(src.as_str()).expect("parse packages");
    let err = packages
        .package_by_name("demo")
        .expect("demo package")
        .repo_file("SHA256")
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("size overflow"));
}

#[test]
fn cli_commands_macro_dispatches_typed_and_bare_variants() {
    let conf = TestConfig::new();

    let typed_trailing_seen = Arc::new(AtomicUsize::new(0));
    let typed_trailing = TypedAppTrailing::parse_from(["app", "typed-renamed", "--label", "abc"]);
    match typed_trailing.cmd {
        TypedCommandsTrailing::TypedEcho(_) => {}
    }
    TypedCommandsTrailing::TypedEcho(TypedEcho {
        label: "abc".to_string(),
        seen: Arc::clone(&typed_trailing_seen),
    })
    .exec(&conf)
    .expect("typed trailing exec");
    assert_eq!(typed_trailing_seen.load(Ordering::SeqCst), 3);

    let typed_final_seen = Arc::new(AtomicUsize::new(0));
    let typed_final = TypedAppFinal::parse_from(["app", "typed-final", "--label", "rust"]);
    match typed_final.cmd {
        TypedCommandsFinal::TypedFinal(_) => {}
    }
    TypedCommandsFinal::TypedFinal(TypedFinal {
        label: "rust".to_string(),
        seen: Arc::clone(&typed_final_seen),
    })
    .exec(&conf)
    .expect("typed final exec");
    assert_eq!(typed_final_seen.load(Ordering::SeqCst), 4);

    let bare_trailing_seen = Arc::new(AtomicUsize::new(0));
    let bare_trailing = BareAppTrailing::parse_from(["app", "bare-local"]);
    match bare_trailing.cmd {
        BareCommandsTrailing::BareLocal(_) => {}
    }
    BareCommandsTrailing::BareLocal(BareLocal {
        seen: Arc::clone(&bare_trailing_seen),
    })
    .exec(&conf)
    .expect("bare trailing exec");
    assert_eq!(bare_trailing_seen.load(Ordering::SeqCst), 1);

    let bare_final_seen = Arc::new(AtomicUsize::new(0));
    let bare_final = BareAppFinal::parse_from(["app", "bare-final"]);
    match bare_final.cmd {
        BareCommandsFinal::BareFinal(_) => {}
    }
    BareCommandsFinal::BareFinal(BareFinal {
        seen: Arc::clone(&bare_final_seen),
    })
    .exec(&conf)
    .expect("bare final exec");
    assert_eq!(bare_final_seen.load(Ordering::SeqCst), 1);
}
