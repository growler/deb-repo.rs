use {
    async_compression::futures::write::{
        BzEncoder, GzipEncoder, Lz4Encoder, XzEncoder, ZstdEncoder,
    },
    debrepo::{
        comp::{comp_reader, is_comp_ext, is_tar_ext, strip_comp_ext, tar_reader},
        tar::TarEntry,
        CompressionLevel,
    },
    smol::io::{AsyncReadExt, AsyncWriteExt, Cursor},
    smol::stream::StreamExt,
    std::io,
};

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

fn build_tar(path: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut header = [0u8; 512];

    write_tar_str(&mut header[0..100], path);
    write_tar_octal(&mut header[100..108], 0o644);
    write_tar_octal(&mut header[108..116], 0);
    write_tar_octal(&mut header[116..124], 0);
    write_tar_octal(&mut header[124..136], data.len() as u64);
    write_tar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    write_tar_str(&mut header[257..263], "ustar\0");
    write_tar_str(&mut header[263..265], "00");

    let checksum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    let checksum_text = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_text.as_bytes());

    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    let padding = (512 - (data.len() % 512)) % 512;
    out.resize(out.len() + padding, 0);
    out.resize(out.len() + 1024, 0);
    out
}

async fn compress_bytes(kind: &str, data: &[u8]) -> io::Result<Vec<u8>> {
    match kind {
        "plain" => Ok(data.to_vec()),
        "gz" => {
            let mut writer =
                GzipEncoder::with_quality(Cursor::new(Vec::new()), CompressionLevel::Default);
            writer.write_all(data).await?;
            writer.close().await?;
            Ok(writer.into_inner().into_inner())
        }
        "xz" => {
            let mut writer =
                XzEncoder::with_quality(Cursor::new(Vec::new()), CompressionLevel::Default);
            writer.write_all(data).await?;
            writer.close().await?;
            Ok(writer.into_inner().into_inner())
        }
        "bz2" => {
            let mut writer =
                BzEncoder::with_quality(Cursor::new(Vec::new()), CompressionLevel::Default);
            writer.write_all(data).await?;
            writer.close().await?;
            Ok(writer.into_inner().into_inner())
        }
        "lz4" => {
            let mut writer =
                Lz4Encoder::with_quality(Cursor::new(Vec::new()), CompressionLevel::Default);
            writer.write_all(data).await?;
            writer.close().await?;
            Ok(writer.into_inner().into_inner())
        }
        "zst" | "zstd" => {
            let mut writer =
                ZstdEncoder::with_quality(Cursor::new(Vec::new()), CompressionLevel::Default);
            writer.write_all(data).await?;
            writer.close().await?;
            Ok(writer.into_inner().into_inner())
        }
        other => panic!("unsupported test compression kind {other}"),
    }
}

async fn read_file_entry(
    mut reader: debrepo::tar::TarReader<
        '_,
        std::pin::Pin<Box<dyn smol::io::AsyncRead + Send + '_>>,
    >,
) -> io::Result<(String, Vec<u8>)> {
    let entry = reader
        .next()
        .await
        .transpose()?
        .expect("expected tar entry");
    let mut body = Vec::new();
    match entry {
        TarEntry::File(mut file) => {
            file.read_to_end(&mut body).await?;
            let path = file.path().to_string();
            assert!(reader.next().await.is_none(), "expected single tar entry");
            Ok((path, body))
        }
        other => panic!("unexpected tar entry: {other:?}"),
    }
}

#[test]
fn strip_comp_ext_and_is_comp_ext_cover_supported_suffixes() {
    assert_eq!(strip_comp_ext("Packages.gz"), "Packages");
    assert_eq!(strip_comp_ext("Sources.XZ"), "Sources");
    assert_eq!(strip_comp_ext("Packages.BZ2"), "Packages");
    assert_eq!(strip_comp_ext("Packages.ZST"), "Packages");
    assert_eq!(strip_comp_ext("Packages.zstd"), "Packages");
    assert_eq!(strip_comp_ext("Packages.LZ4"), "Packages");
    assert_eq!(strip_comp_ext("plain"), "plain");
    assert_eq!(strip_comp_ext("a"), "a");

    assert!(is_comp_ext("Packages.gz"));
    assert!(is_comp_ext("Packages.XZ"));
    assert!(is_comp_ext("Packages.bz2"));
    assert!(is_comp_ext("Packages.zst"));
    assert!(is_comp_ext("Packages.ZSTD"));
    assert!(is_comp_ext("Packages.lz4"));
    assert!(!is_comp_ext("gz"));
    assert!(!is_comp_ext("archive.tar"));
}

#[test]
fn comp_reader_roundtrips_supported_algorithms_and_plain_passthrough() {
    smol::block_on(async {
        let payload = b"component payload\n";
        for (uri, kind) in [
            ("Packages.bz2", "bz2"),
            ("Packages.lz4", "lz4"),
            ("Packages.zst", "zst"),
            ("Packages.zstd", "zstd"),
            ("Packages", "plain"),
        ] {
            let encoded = compress_bytes(kind, payload)
                .await
                .expect("compress payload");
            let mut reader = comp_reader(uri, Cursor::new(encoded));
            let mut decoded = Vec::new();
            reader
                .read_to_end(&mut decoded)
                .await
                .expect("decode payload");
            assert_eq!(decoded, payload, "uri {uri}");
        }
    });
}

#[test]
fn is_tar_ext_covers_aliases_and_rejections() {
    for path in [
        "archive.tar",
        "archive.tar.gz",
        "archive.TGZ",
        "archive.tar.xz",
        "archive.txz",
        "archive.tar.bz2",
        "archive.tbz",
        "archive.tbz2",
        "archive.tar.zstd",
        "archive.tar.zst",
        "archive.tzst",
    ] {
        assert!(is_tar_ext(path), "expected tar extension for {path}");
    }

    assert!(!is_tar_ext("archive.tar.lz4"));
    assert!(!is_tar_ext("archive.zip"));
}

#[test]
fn tar_reader_reads_supported_compressed_tars_and_rejects_unknown_format() {
    smol::block_on(async {
        let tar_bytes = build_tar("entry.txt", b"tar payload");
        for (uri, kind) in [
            ("archive.tar.gz", "gz"),
            ("archive.txz", "xz"),
            ("archive.tbz2", "bz2"),
            ("archive.tzst", "zstd"),
        ] {
            let encoded = compress_bytes(kind, &tar_bytes)
                .await
                .expect("compress tar");
            let reader = tar_reader(uri, Cursor::new(encoded)).expect("open tar reader");
            let (path, body) = read_file_entry(reader).await.expect("read tar entry");
            assert_eq!(path, "entry.txt", "uri {uri}");
            assert_eq!(body, b"tar payload", "uri {uri}");
        }

        let err = match tar_reader("archive.zip", Cursor::new(tar_bytes)) {
            Ok(_) => panic!("unsupported archive should fail"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("unsupported archive format archive.zip"));
    });
}
