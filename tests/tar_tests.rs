use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use anyhow::Result;
use debrepo::tar::{
    TarDevice, TarDirectory, TarEntry, TarReader, TarRegularFile, TarSymlink, TarWriter,
};
use futures::SinkExt;
use futures_lite::{
    io::{AsyncReadExt, AsyncWrite, Cursor},
    StreamExt,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name)
}

#[test]
fn read_simple_archive() -> Result<()> {
    smol::block_on(async {
        let archive = smol::fs::File::open(fixture("simple.tar")).await?;
        let reader = TarReader::new(archive);
        let mut seen = Vec::new();
        let mut stream = Box::pin(reader);
        while let Some(entry) = stream.next().await {
            let entry = entry?;
            match entry {
                TarEntry::Directory(dir) => {
                    seen.push(("dir".to_string(), dir.path().to_string()));
                    assert_eq!(dir.mode(), 0o755);
                }
                TarEntry::File(mut file) => {
                    let mut buf = Vec::new();
                    file.read_to_end(&mut buf).await?;
                    seen.push(("file".to_string(), file.path().to_string()));
                    assert_eq!(buf, b"hello world\n");
                }
                TarEntry::Symlink(link) => {
                    seen.push(("symlink".to_string(), link.path().to_string()));
                    assert_eq!(link.link(), "hello.txt");
                }
                TarEntry::Link(link) => {
                    seen.push(("hardlink".to_string(), link.path().to_string()));
                    assert_eq!(link.link(), "root/hello.txt");
                }
                other => panic!("unexpected entry: {:?}", other),
            }
        }
        assert_eq!(
            seen,
            vec![
                ("dir".into(), "root/".into()),
                ("file".into(), "root/hello.txt".into()),
                ("symlink".into(), "root/hello-link".into()),
                ("hardlink".into(), "root/hello-hard".into())
            ]
        );
        Ok(())
    })
}

#[test]
fn read_gnu_long_name_archive() -> Result<()> {
    smol::block_on(async {
        let archive = smol::fs::File::open(fixture("gnu_long_name.tar")).await?;
        let reader = TarReader::new(archive);
        let long_name = format!("nested/{}{}", "a".repeat(120), "/file.txt");
        let long_link = format!("nested/{}{}", "b".repeat(130), "/target.txt");
        let mut paths = Vec::new();
        let mut stream = Box::pin(reader);
        while let Some(entry) = stream.next().await {
            let entry = entry?;
            match entry {
                TarEntry::File(mut file) => {
                    let mut buf = Vec::new();
                    file.read_to_end(&mut buf).await?;
                    assert_eq!(buf, b"long data");
                    paths.push(file.path().to_string());
                }
                TarEntry::Symlink(link) => {
                    assert_eq!(link.link(), long_name);
                    paths.push(link.path().to_string());
                }
                other => panic!("unexpected entry {:?}", other),
            }
        }
        assert_eq!(paths, vec![long_name, long_link]);
        Ok(())
    })
}

#[test]
fn read_pax_archive() -> Result<()> {
    smol::block_on(async {
        let archive = smol::fs::File::open(fixture("pax.tar")).await?;
        let reader = TarReader::new(archive);
        let pax_path = format!(
            "pax/{}/{}.txt",
            std::iter::repeat("deep")
                .take(10)
                .collect::<Vec<_>>()
                .join("/"),
            "c".repeat(200)
        );
        let pax_link = format!("pax/link-{}", "d".repeat(190));
        let mut paths = Vec::new();
        let mut stream = Box::pin(reader);
        while let Some(entry) = stream.next().await {
            let entry = entry?;
            match entry {
                TarEntry::File(file) => {
                    assert_eq!(file.path(), pax_path);
                    paths.push(file.path().to_string());
                }
                TarEntry::Symlink(link) => {
                    assert_eq!(link.link(), pax_path);
                    assert_eq!(link.path(), pax_link);
                    paths.push(link.path().to_string());
                }
                other => panic!("unexpected entry {:?}", other),
            }
        }
        assert_eq!(paths, vec![pax_path, pax_link]);
        Ok(())
    })
}

struct VecAsyncWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl VecAsyncWriter {
    fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
        let inner = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inner: inner.clone(),
            },
            inner,
        )
    }
}

impl AsyncWrite for VecAsyncWriter {
    fn poll_write(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn tar_writer_round_trip() -> Result<()> {
    smol::block_on(async {
        let (writer_sink, shared) = VecAsyncWriter::new();
        let mut writer = TarWriter::<'static, 'static, _, Cursor<&'static [u8]>>::new(writer_sink);
        writer
            .send(TarEntry::Directory(TarDirectory::new(
                "dir/",
                0,
                0,
                0o755,
                1,
            )))
            .await?;
        const DATA: &[u8] = b"writer round trip";
        writer
            .send(TarEntry::File(TarRegularFile::new(
                "dir/file.txt",
                DATA.len() as u64,
                1000,
                1001,
                0o640,
                2,
                Cursor::new(DATA),
            )))
            .await?;
        writer
            .send(TarEntry::Device(TarDevice::new_char(
                "dir/dev",
                1,
                3,
                0,
                0,
                0o600,
                3,
            )))
            .await?;
        writer
            .send(TarEntry::Symlink(TarSymlink::new(
                "dir/link",
                "file.txt",
                0,
                0,
                0o777,
                4,
            )))
            .await?;
        writer.close().await?;

        let buffer = shared.lock().unwrap().clone();
        let cursor = Cursor::new(buffer);
        let reader = TarReader::new(cursor);
        let mut stream = Box::pin(reader);
        let mut order = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry?;
            match entry {
                TarEntry::Directory(dir) => {
                    order.push(dir.path().to_string());
                    assert_eq!(dir.mode(), 0o755);
                }
                TarEntry::File(mut file) => {
                    let mut buf = Vec::new();
                    file.read_to_end(&mut buf).await?;
                    assert_eq!(buf, DATA);
                    order.push(file.path().to_string());
                }
                TarEntry::Device(device) => {
                    assert!(device.is_char());
                    assert_eq!(device.major(), 1);
                    assert_eq!(device.minor(), 3);
                    order.push(device.path().to_string());
                }
                TarEntry::Symlink(link) => {
                    assert_eq!(link.link(), "file.txt");
                    order.push(link.path().to_string());
                }
                other => panic!("unexpected entry {:?}", other),
            }
        }
        assert_eq!(
            order,
            vec![
                String::from("dir/"),
                String::from("dir/file.txt"),
                String::from("dir/dev"),
                String::from("dir/link")
            ]
        );
        Ok(())
    })
}

#[test]
fn tar_writer_round_trip_long_names() -> Result<()> {
    smol::block_on(async {
        let (writer_sink, shared) = VecAsyncWriter::new();
        let mut writer = TarWriter::<'static, 'static, _, Cursor<&'static [u8]>>::new(writer_sink);
        let long_file_path = format!("root/{}/{}", "nested".repeat(5), "a".repeat(180));
        let long_symlink_path = format!("root/link-{}", "b".repeat(170));
        let long_symlink_target = format!("target/{}", "c".repeat(175));
        const DATA: &[u8] = b"long names payload";

        writer
            .send(TarEntry::File(TarRegularFile::new(
                long_file_path.clone(),
                DATA.len() as u64,
                0,
                0,
                0o644,
                1,
                Cursor::new(DATA),
            )))
            .await?;
        writer
            .send(TarEntry::Symlink(TarSymlink::new(
                long_symlink_path.clone(),
                long_symlink_target.clone(),
                0,
                0,
                0o777,
                2,
            )))
            .await?;
        writer.close().await?;

        let buffer = shared.lock().unwrap().clone();
        let cursor = Cursor::new(buffer);
        let reader = TarReader::new(cursor);
        let mut stream = Box::pin(reader);

        // First entry: long path file.
        match stream.next().await.unwrap()? {
            TarEntry::File(mut file) => {
                assert_eq!(file.path(), long_file_path);
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).await?;
                assert_eq!(buf, DATA);
            }
            other => panic!("expected file entry, got {:?}", other),
        }
        // Second entry: symlink with long metadata.
        match stream.next().await.unwrap()? {
            TarEntry::Symlink(link) => {
                assert_eq!(link.path(), long_symlink_path);
                assert_eq!(link.link(), long_symlink_target);
            }
            other => panic!("expected symlink entry, got {:?}", other),
        }
        assert!(stream.next().await.is_none());
        Ok(())
    })
}

#[test]
fn dropping_regular_file_reader_skips_entry() -> Result<()> {
    smol::block_on(async {
        let archive = smol::fs::File::open(fixture("simple.tar")).await?;
        let reader = TarReader::new(archive);
        let mut stream = Box::pin(reader);

        // First entry should be the directory.
        assert!(matches!(
            stream.next().await.unwrap()?,
            TarEntry::Directory(_)
        ));

        // Next entry is the file; read a single byte then drop without finishing.
        if let TarEntry::File(mut file) = stream.next().await.unwrap()? {
            let mut buf = [0u8; 1];
            file.read_exact(&mut buf).await?;
        } else {
            panic!("expected file entry");
        }

        // Stream should continue with the symlink even though we didn't drain the file.
        match stream.next().await.unwrap()? {
            TarEntry::Symlink(link) => assert_eq!(link.path(), "root/hello-link"),
            other => panic!("expected symlink, got {:?}", other),
        }
        Ok(())
    })
}
