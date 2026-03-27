use {
    base64::Engine,
    debrepo::{
        deb::{DebEntry, DebReader, DebStage},
        FileList, HostFileSystem, Stage,
    },
    md5::{Digest, Md5},
    smol::{io::Cursor, stream::StreamExt},
    std::{
        fs, io,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    },
    tempfile::tempdir,
};

#[derive(Clone)]
enum TarMember {
    Directory {
        path: &'static str,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    File {
        path: &'static str,
        data: Vec<u8>,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Symlink {
        path: &'static str,
        target: &'static str,
        uid: u32,
        gid: u32,
    },
    Fifo {
        path: &'static str,
        mode: u32,
        uid: u32,
        gid: u32,
    },
}

struct DebFixture<'a> {
    version: &'a [u8],
    control_members: Vec<TarMember>,
    data_members: Option<Vec<TarMember>>,
    extra_members: Vec<(&'a str, Vec<u8>)>,
}

impl<'a> DebFixture<'a> {
    fn build(self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(b"!<arch>\n");
        append_ar_member(&mut out, "debian-binary", self.version);
        for (name, data) in self.extra_members {
            append_ar_member(&mut out, name, &data);
        }
        append_ar_member(&mut out, "control.tar", &build_tar(&self.control_members)?);
        if let Some(data_members) = self.data_members {
            append_ar_member(&mut out, "data.tar", &build_tar(&data_members)?);
        }
        Ok(out)
    }
}

fn base_control(package_field: bool) -> Vec<TarMember> {
    let mut control = String::new();
    if package_field {
        control.push_str("Package: demo\n");
    }
    control.push_str("Version: 1.0\nArchitecture: amd64\n");
    vec![
        TarMember::Directory {
            path: "./",
            mode: 0o755,
            uid: 0,
            gid: 0,
        },
        TarMember::File {
            path: "./control",
            data: control.into_bytes(),
            mode: 0o644,
            uid: 0,
            gid: 0,
        },
    ]
}

fn base_data() -> Vec<TarMember> {
    vec![
        TarMember::Directory {
            path: "./usr/",
            mode: 0o755,
            uid: 0,
            gid: 0,
        },
        TarMember::File {
            path: "./usr/bin/demo",
            data: b"#!/bin/sh\necho demo\n".to_vec(),
            mode: 0o755,
            uid: 0,
            gid: 0,
        },
    ]
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/deb")
        .join(name)
}

fn fixture_bytes(name: &str) -> io::Result<Vec<u8>> {
    fs::read(fixture_path(name))
}

fn append_ar_member(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut header = [b' '; 60];
    write_field(&mut header[0..16], name);
    write_field(&mut header[16..28], "0");
    write_field(&mut header[28..34], "0");
    write_field(&mut header[34..40], "0");
    write_field(&mut header[40..48], "100644");
    write_field(&mut header[48..58], &data.len().to_string());
    header[58] = b'`';
    header[59] = b'\n';
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(b'\n');
    }
}

fn write_field(dst: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    dst[..bytes.len()].copy_from_slice(bytes);
}

fn build_tar(entries: &[TarMember]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for entry in entries {
        let (path, mode, uid, gid, link, kind, data) = match entry {
            TarMember::Directory {
                path,
                mode,
                uid,
                gid,
            } => (*path, *mode, *uid, *gid, None, b'5', &[][..]),
            TarMember::File {
                path,
                data,
                mode,
                uid,
                gid,
            } => (*path, *mode, *uid, *gid, None, b'0', data.as_slice()),
            TarMember::Symlink {
                path,
                target,
                uid,
                gid,
            } => (*path, 0o777, *uid, *gid, Some(*target), b'2', &[][..]),
            TarMember::Fifo {
                path,
                mode,
                uid,
                gid,
            } => (*path, *mode, *uid, *gid, None, b'6', &[][..]),
        };
        append_tar_header(
            &mut out,
            path,
            mode,
            uid,
            gid,
            data.len() as u64,
            kind,
            link,
        )?;
        out.extend_from_slice(data);
        let padding = (512 - (data.len() % 512)) % 512;
        out.resize(out.len() + padding, 0);
    }
    out.resize(out.len() + 1024, 0);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn append_tar_header(
    out: &mut Vec<u8>,
    path: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    kind: u8,
    link: Option<&str>,
) -> io::Result<()> {
    if path.len() > 100 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path too long for test tar header: {path}"),
        ));
    }
    let mut header = [0u8; 512];
    write_tar_bytes(&mut header[0..100], path.as_bytes());
    write_tar_octal(&mut header[100..108], mode as u64);
    write_tar_octal(&mut header[108..116], uid as u64);
    write_tar_octal(&mut header[116..124], gid as u64);
    write_tar_octal(&mut header[124..136], size);
    write_tar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = kind;
    if let Some(link) = link {
        write_tar_bytes(&mut header[157..257], link.as_bytes());
    }
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|b| *b as u32).sum();
    write_tar_checksum(&mut header[148..156], checksum as u64);
    out.extend_from_slice(&header);
    Ok(())
}

fn write_tar_bytes(dst: &mut [u8], src: &[u8]) {
    dst[..src.len()].copy_from_slice(src);
}

fn write_tar_octal(dst: &mut [u8], value: u64) {
    let width = dst.len() - 1;
    let formatted = format!("{value:0width$o}");
    let bytes = formatted.as_bytes();
    let start = width.saturating_sub(bytes.len());
    dst[..width].fill(b'0');
    dst[start..start + bytes.len()].copy_from_slice(bytes);
    dst[width] = 0;
}

fn write_tar_checksum(dst: &mut [u8], value: u64) {
    let formatted = format!("{value:06o}\0 ");
    dst.copy_from_slice(formatted.as_bytes());
}

fn md5_sri(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    format!(
        "md5-{}",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    )
}

fn expect_io_error<T>(result: io::Result<T>) -> io::Error {
    match result {
        Ok(_) => panic!("expected io::Error"),
        Err(err) => err,
    }
}

#[test]
fn extract_control_supports_packaged_compression_variants() -> io::Result<()> {
    for name in [
        "minimal-none.deb",
        "minimal-gzip.deb",
        "minimal-xz.deb",
        "minimal-zstd.deb",
    ] {
        let ctrl = smol::block_on(async {
            let mut deb = DebReader::new(Cursor::new(fixture_bytes(name)?));
            deb.extract_control().await
        })?;
        assert_eq!(ctrl.field("Package"), Some("fixture-minimal"));
        assert_eq!(ctrl.field("Architecture"), Some("amd64"));
    }
    Ok(())
}

#[test]
fn reader_skips_unconsumed_control_payload_before_reading_data() -> io::Result<()> {
    smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(fixture_bytes("minimal-gzip.deb")?));
        let control = deb
            .next()
            .await
            .expect("control entry")
            .expect("control success");
        assert!(matches!(control, DebEntry::Control(_)));
        drop(control);

        let mut data = match deb.next().await.expect("data entry").expect("data success") {
            DebEntry::Data(data) => data,
            DebEntry::Control(_) => panic!("expected data entry"),
        };

        let mut paths = Vec::new();
        while let Some(entry) = data.next().await {
            paths.push(entry?.path().to_string());
        }
        assert!(paths.contains(&"./usr/".to_string()));
        assert!(paths.contains(&"./usr/bin/".to_string()));
        assert!(paths.contains(&"./usr/bin/fixture-minimal".to_string()));
        assert!(deb.next().await.is_none());
        Ok(())
    })
}

#[test]
fn extract_to_populates_control_metadata_from_packaged_fixture() -> io::Result<()> {
    let ctrl = smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(fixture_bytes("rich-xz.deb")?));
        deb.extract_to(&FileList::new()).await
    })?;

    assert_eq!(ctrl.field("Package"), Some("fixture-rich"));
    assert_eq!(ctrl.field("Architecture"), Some("amd64"));
    assert_eq!(ctrl.field("Multi-Arch"), Some("same"));
    assert_eq!(
        ctrl.field("Conffiles").expect("Conffiles"),
        format!(
            "\n ./etc/fixture-rich.conf {}",
            md5_sri(b"fixture-rich=1\n")
        )
    );
    let controlfiles = ctrl.field("Controlfiles").expect("Controlfiles");
    assert!(controlfiles.contains("./conffiles"));
    assert!(controlfiles.contains("./postinst"));
    Ok(())
}

#[test]
fn deb_stage_extracts_packaged_fixture_to_host_filesystem() -> io::Result<()> {
    let root = tempdir()?;
    let ctrl = smol::block_on(async {
        let fs = HostFileSystem::new(root.path(), false).await?;
        let mut stage =
            DebStage::<_, HostFileSystem>::new(Cursor::new(fixture_bytes("rich-xz.deb")?));
        stage.stage(&fs).await
    })?;

    assert_eq!(ctrl.field("Package"), Some("fixture-rich"));

    let demo = root.path().join("usr/bin/fixture-rich");
    let hard = root.path().join("usr/bin/fixture-rich-hard");
    let symlink = root.path().join("usr/bin/fixture-rich-link");
    let list = root
        .path()
        .join("var/lib/dpkg/info/fixture-rich:amd64.list");
    let postinst = root
        .path()
        .join("var/lib/dpkg/info/fixture-rich:amd64.postinst");
    let conffiles = root
        .path()
        .join("var/lib/dpkg/info/fixture-rich:amd64.conffiles");

    assert_eq!(fs::read(&demo)?, b"#!/bin/sh\necho fixture-rich\n");
    assert_eq!(fs::read(&conffiles)?, b"./etc/fixture-rich.conf\n");
    assert_eq!(fs::read(&postinst)?, b"#!/bin/sh\nexit 0\n");
    assert_eq!(
        fs::read(root.path().join("etc/fixture-rich.conf"))?,
        b"fixture-rich=1\n"
    );
    assert_eq!(
        fs::read_link(&symlink)?,
        PathBuf::from("./usr/bin/fixture-rich")
    );
    let demo_meta = fs::metadata(&demo)?;
    let hard_meta = fs::metadata(&hard)?;
    assert_eq!(demo_meta.ino(), hard_meta.ino());
    assert_eq!(
        fs::read_to_string(list)?,
        "./\n./etc/\n./etc/fixture-rich.conf\n./usr/\n./usr/bin/\n./usr/bin/fixture-rich\n./usr/bin/fixture-rich-hard\n./usr/bin/fixture-rich-link\n"
    );
    Ok(())
}

#[test]
fn extract_control_rejects_missing_control_file() -> io::Result<()> {
    let bytes = DebFixture {
        version: b"2.0\n",
        control_members: vec![TarMember::Directory {
            path: "./",
            mode: 0o755,
            uid: 0,
            gid: 0,
        }],
        data_members: Some(base_data()),
        extra_members: vec![],
    }
    .build()?;

    let err = expect_io_error(smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(bytes));
        deb.extract_control().await
    }));
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("no control file"));
    Ok(())
}

#[test]
fn extract_control_rejects_invalid_control_entry() -> io::Result<()> {
    let bytes = DebFixture {
        version: b"2.0\n",
        control_members: vec![
            TarMember::Directory {
                path: "./",
                mode: 0o755,
                uid: 0,
                gid: 0,
            },
            TarMember::Symlink {
                path: "./control",
                target: "./elsewhere",
                uid: 0,
                gid: 0,
            },
        ],
        data_members: Some(base_data()),
        extra_members: vec![],
    }
    .build()?;

    let err = expect_io_error(smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(bytes));
        deb.extract_control().await
    }));
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid entry in control.tar"));
    Ok(())
}

#[test]
fn reader_rejects_invalid_magic() {
    let err = smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(b"not-a-deb".to_vec()));
        expect_io_error(deb.next().await.expect("reader result"))
    });
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid debian package magic"));
}

#[test]
fn reader_rejects_unsupported_debian_binary_version() -> io::Result<()> {
    let bytes = DebFixture {
        version: b"1.0\n",
        control_members: base_control(true),
        data_members: Some(base_data()),
        extra_members: vec![],
    }
    .build()?;

    let err = smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(bytes));
        expect_io_error(deb.next().await.expect("reader result"))
    });
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err
        .to_string()
        .contains("unsupported debian binary package version"));
    Ok(())
}

#[test]
fn reader_rejects_oversized_debian_binary_member() -> io::Result<()> {
    let bytes = DebFixture {
        version: &[b'2'; 61],
        control_members: base_control(true),
        data_members: Some(base_data()),
        extra_members: vec![],
    }
    .build()?;

    let err = smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(bytes));
        expect_io_error(deb.next().await.expect("reader result"))
    });
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid debian binary entry size"));
    Ok(())
}

#[test]
fn reader_rejects_unexpected_top_level_member() -> io::Result<()> {
    let bytes = DebFixture {
        version: b"2.0\n",
        control_members: base_control(true),
        data_members: Some(base_data()),
        extra_members: vec![("weird-entry", b"ignored".to_vec())],
    }
    .build()?;

    let err = smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(bytes));
        expect_io_error(deb.next().await.expect("reader result"))
    });
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("unexpected debian package entry"));
    Ok(())
}

#[test]
fn extract_to_reports_missing_package_field() -> io::Result<()> {
    let bytes = DebFixture {
        version: b"2.0\n",
        control_members: base_control(false),
        data_members: Some(base_data()),
        extra_members: vec![],
    }
    .build()?;

    let err = expect_io_error(smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(bytes));
        deb.extract_to(&FileList::new()).await
    }));
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("no Package field"));
    Ok(())
}

#[test]
fn extract_to_reports_missing_data_entry() -> io::Result<()> {
    let bytes = DebFixture {
        version: b"2.0\n",
        control_members: base_control(true),
        data_members: None,
        extra_members: vec![],
    }
    .build()?;

    let err = expect_io_error(smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(bytes));
        deb.extract_to(&FileList::new()).await
    }));
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("no data.tar entry"));
    Ok(())
}

#[test]
fn extract_to_rejects_unsupported_data_tar_entry() -> io::Result<()> {
    let bytes = DebFixture {
        version: b"2.0\n",
        control_members: base_control(true),
        data_members: Some(vec![TarMember::Fifo {
            path: "./run/demo.fifo",
            mode: 0o644,
            uid: 0,
            gid: 0,
        }]),
        extra_members: vec![],
    }
    .build()?;

    let err = expect_io_error(smol::block_on(async {
        let mut deb = DebReader::new(Cursor::new(bytes));
        deb.extract_to(&FileList::new()).await
    }));
    assert!(err
        .to_string()
        .contains("unsupported tar entry in debian package"));
    Ok(())
}
