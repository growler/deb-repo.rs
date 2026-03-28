use {
    debrepo::{FileList, HostFileSystem, Stage, StagingFile, StagingFileSystem},
    smol::io::Cursor,
    std::{
        future::Future,
        io,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::Path,
        pin::Pin,
        time::Duration,
    },
    tempfile::tempdir,
};

struct HostStage;

impl Stage for HostStage {
    type Output = &'static str;
    type Target = HostFileSystem;

    fn stage<'a>(
        &'a mut self,
        fs: &'a HostFileSystem,
    ) -> Pin<Box<dyn Future<Output = io::Result<&'static str>> + 'a>> {
        Box::pin(async move {
            fs.create_dir_all("stage-output", 0, 0, 0o755).await?;
            Ok("host-stage")
        })
    }
}

struct FileListStage;

impl Stage for FileListStage {
    type Output = usize;
    type Target = FileList;

    fn stage<'a>(
        &'a mut self,
        fs: &'a FileList,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + 'a>> {
        Box::pin(async move {
            fs.create_dir("from-stage", 7, 8, 0o700).await?;
            Ok(42)
        })
    }
}

fn mode_bits(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o7777
}

async fn read_lines_with_retry(path: &Path) -> io::Result<Vec<String>> {
    for _ in 0..200 {
        let written = smol::fs::read_to_string(path).await?;
        if !written.is_empty() {
            return Ok(written.lines().map(str::to_string).collect());
        }
        smol::Timer::after(Duration::from_millis(10)).await;
    }
    Ok(Vec::new())
}

#[test]
fn host_filesystem_rebases_paths_and_rejects_parent_traversal() -> io::Result<()> {
    smol::block_on(async {
        let dir = tempdir()?;
        let invalid_root = dir.path().join("not-a-directory");
        std::fs::write(&invalid_root, b"root file")?;
        let err = match HostFileSystem::new(&invalid_root, false).await {
            Ok(_) => panic!("file root should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        let root = dir.path().join("root");
        let fs = HostFileSystem::new(&root, false).await?;

        fs.create_dir("single", 111, 222, 0o7777).await?;
        assert!(root.join("single").is_dir());
        assert_eq!(mode_bits(&root.join("single")) & 0o7000, 0);

        fs.create_dir_all("/nested/child", 333, 444, 0o755).await?;
        assert!(root.join("nested/child").is_dir());

        let err = match fs.create_dir("../escape", 0, 0, 0o755).await {
            Ok(()) => panic!("parent traversal should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let err = match fs.create_dir_all("../escape/tree", 0, 0, 0o755).await {
            Ok(()) => panic!("parent traversal should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        Ok(())
    })
}

#[test]
fn host_filesystem_stages_files_links_and_dispatches_stage() -> io::Result<()> {
    smol::block_on(async {
        let dir = tempdir()?;
        let root = dir.path().join("root");
        let fs = HostFileSystem::new(&root, false).await?;
        fs.create_dir_all("dir", 0, 0, 0o755).await?;

        let file = fs
            .create_file_from_bytes(b"payload", 10, 20, 0o6755)
            .await?;
        file.persist("/dir/file.txt").await?;
        assert_eq!(std::fs::read(root.join("dir/file.txt"))?, b"payload");
        assert_eq!(mode_bits(&root.join("dir/file.txt")) & 0o7000, 0);

        let empty = fs
            .create_file(Cursor::new(Vec::<u8>::new()), 0, 0, 0o600, Some(0))
            .await?;
        empty.persist("dir/empty.txt").await?;
        assert_eq!(std::fs::metadata(root.join("dir/empty.txt"))?.len(), 0);

        let no_hint = fs
            .create_file(Cursor::new(b"abc".to_vec()), 0, 0, 0o600, None)
            .await?;
        no_hint.persist("dir/no-hint.txt").await?;
        assert_eq!(std::fs::read(root.join("dir/no-hint.txt"))?, b"abc");

        fs.symlink("file.txt", "dir/link.txt", 0, 0).await?;
        assert_eq!(
            std::fs::read_link(root.join("dir/link.txt"))?,
            Path::new("file.txt")
        );

        fs.hardlink("dir/file.txt", "dir/hard.txt").await?;
        assert_eq!(
            std::fs::metadata(root.join("dir/file.txt"))?.ino(),
            std::fs::metadata(root.join("dir/hard.txt"))?.ino()
        );

        fs.remove_file("dir/hard.txt").await?;
        assert!(!root.join("dir/hard.txt").exists());

        let err = match fs.symlink("file.txt", "../bad-link", 0, 0).await {
            Ok(()) => panic!("parent traversal should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let invalid = fs.create_file_from_bytes(b"x", 0, 0, 0o644).await?;
        let err = match invalid.persist("../bad-file").await {
            Ok(()) => panic!("parent traversal should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let err = match fs.remove_file("../bad-file").await {
            Ok(()) => panic!("parent traversal should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let stage_result = fs.stage(Box::new(HostStage)).await?;
        assert_eq!(stage_result, "host-stage");
        assert!(root.join("stage-output").is_dir());

        Ok(())
    })
}

#[test]
fn file_list_records_and_keeps_sorted_entries() -> io::Result<()> {
    smol::block_on(async {
        let dir = tempdir()?;
        let output = dir.path().join("file-list.txt");
        let drained = dir.path().join("drained.txt");

        let list = FileList::default();
        let mirror = list.clone();

        list.create_dir("usr", 1, 2, 0o755).await?;
        list.create_dir_all("var/lib", 3, 4, 0o750).await?;
        list.symlink("target/file", "link", 5, 6).await?;
        list.hardlink("from", "to").await?;
        list.remove_file("obsolete").await?;
        let file = list
            .create_file(Cursor::new(b"abc".to_vec()), 7, 8, 0o640, None)
            .await?;
        file.persist("payload").await?;

        let stage_result = list.stage(Box::new(FileListStage)).await?;
        assert_eq!(stage_result, 42);

        list.keep(&output).await?;
        let written = read_lines_with_retry(&output).await?;
        assert_eq!(
            written,
            vec![
                "!obsolete".to_string(),
                "from -> to".to_string(),
                "from-stage 700 7 8".to_string(),
                "link -> target/file 5 6".to_string(),
                "payload 640 7 8 3".to_string(),
                "usr 755 1 2".to_string(),
                "var/lib 750 3 4".to_string(),
            ]
        );

        mirror.keep(&drained).await?;
        assert_eq!(smol::fs::read_to_string(&drained).await?, "");

        Ok(())
    })
}
