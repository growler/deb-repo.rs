//! Debian repository client

use {
    crate::repo::TransportProvider,
    async_trait::async_trait,
    smol::{fs, io, prelude::*},
    std::path::{Path, PathBuf},
    std::pin::Pin,
};

#[derive(Clone)]
pub struct FSTransportProvider {
    base: PathBuf,
}

impl FSTransportProvider {
    pub async fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let base = path.as_ref().to_path_buf();
        if {
            let meta = fs::metadata(&base).await?;
            meta.is_dir()
        } {
            Ok(FSTransportProvider { base: base })
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{:#?}", path.as_ref()),
            ))
        }
    }
}

#[async_trait]
impl TransportProvider for FSTransportProvider {
    async fn reader(&self, path: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        let path = self.base.join(path);
        Ok(Box::pin(fs::File::open(path).await?) as Pin<Box<dyn AsyncRead + Send>>)
    }
}
