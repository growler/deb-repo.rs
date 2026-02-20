use {
    debrepo::tar::{AttrList, TarEntry, TarRegularFile, TarWriter},
    futures::SinkExt,
    futures_lite::io::Cursor,
    smol::Async,
};

fn main() -> std::io::Result<()> {
    smol::block_on(async {
        let stdout = Async::new(std::io::stdout())?;
        let mut writer = TarWriter::<'static, 'static, _, Cursor<&'static [u8]>>::new(stdout);
        let data: &[u8] = b"xattr test\n";
        let attrs = AttrList::new().with("user.ostreemeta", b"example".as_slice());
        let file = TarRegularFile::new(
            "xattr.txt",
            data.len() as u64,
            0,
            0,
            0o644,
            0,
            Cursor::new(data),
        )
        .with_attrs(attrs);
        writer.send(TarEntry::File(file)).await?;
        writer.close().await?;
        Ok(())
    })
}
