//! Digest verification

pub use digest::{FixedOutputReset as Digester, Output as DigesterOutput};
use {
    async_std::{
        io::prelude::*,
        task::{ready, Context, Poll},
    },
    pin_project::pin_project,
    std::pin::Pin,
};

pub type Sha256 = Digest<sha2::Sha256>;

#[derive(Default, Debug)]
pub struct Digest<D: Digester + Send> {
    inner: DigesterOutput<D>,
}

impl<D: Digester + Send> Clone for Digest<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<This: Digester + Send, That: Digester + Send> PartialEq<Digest<That>> for Digest<This> {
    fn eq(&self, other: &Digest<That>) -> bool {
        This::output_size() == That::output_size()
            && self.inner.as_slice() == other.inner.as_slice()
    }
}

impl<D: Digester + Send> PartialEq<str> for Digest<D> {
    fn eq(&self, other: &str) -> bool {
        let mut digest = DigesterOutput::<D>::default();
        match hex::decode_to_slice(other, digest.as_mut_slice()) {
            Ok(_) => self.inner.eq(&digest),
            Err(_) => false,
        }
    }
}

impl<D: Digester + Send> Digest<D> {
    pub fn into_inner(self) -> DigesterOutput<D> {
        self.inner
    }
}

impl<D: Digester + Send> TryFrom<&str> for Digest<D> {
    type Error = std::io::Error;
    fn try_from(value: &str) -> std::io::Result<Self> {
        let mut inner = DigesterOutput::<D>::default();
        hex::decode_to_slice(value, inner.as_mut_slice()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid digest: {}", e),
            )
        })?;
        Ok(Digest { inner })
    }
}

impl<D: Digester + Send> TryFrom<&[u8]> for Digest<D> {
    type Error = std::io::Error;
    fn try_from(value: &[u8]) -> std::io::Result<Self> {
        if value.len() == D::output_size() {
            Ok(Digest {
                inner: DigesterOutput::<D>::from_slice(value).clone(),
            })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid digest, expected exactly {} bytes",
                    D::output_size()
                ),
            ))
        }
    }
}

impl<D: Digester + Send> From<Digest<D>> for String {
    fn from(value: Digest<D>) -> Self {
        hex::encode(&value.inner)
    }
}

impl<D: Digester + Send> From<Digest<D>> for DigesterOutput<D> {
    fn from(value: Digest<D>) -> Self {
        value.inner
    }
}

impl<D: Digester + Send> From<DigesterOutput<D>> for Digest<D> {
    fn from(value: DigesterOutput<D>) -> Self {
        Self { inner: value }
    }
}

impl<D: Digester + Send> std::fmt::LowerHex for Digest<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", hex::encode(&self.inner))
    }
}

#[pin_project]
pub struct DigestingReader<D: Digester + Send, R: Read + Unpin + Send> {
    digester: D,
    #[pin]
    inner: R,
}
impl<D: Digester + Default + Send, R: Read + Unpin + Send> DigestingReader<D, R> {
    pub fn new(reader: R) -> Self {
        Self {
            digester: D::default(),
            inner: reader,
        }
    }
    pub fn finalize(self) -> Digest<D> {
        Digest {
            inner: self.digester.finalize_fixed(),
        }
    }
}

impl<D: Digester + Send, R: Read + Unpin + Send> Read for DigestingReader<D, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        Poll::Ready(match ready!(this.inner.as_mut().poll_read(cx, buf)) {
            Ok(0) => Ok(0),
            Ok(size) => {
                this.digester.update(&buf[0..size]);
                Ok(size)
            }
            Err(err) => Err(err),
        })
    }
}

#[pin_project]
pub struct VerifyingReader<D: Digester + Default + Send, R: Read + Unpin + Send> {
    digester: D,
    digest: DigesterOutput<D>,
    size: usize,
    read: usize,
    #[pin]
    inner: R,
}

impl<D: Digester + Default + Send, R: Read + Unpin + Send> VerifyingReader<D, R> {
    pub fn new(reader: R, size: usize, digest: Digest<D>) -> Self {
        Self {
            digester: D::default(),
            digest: digest.into(),
            size,
            read: 0,
            inner: reader,
        }
    }
}

impl<D: Digester + Default + Send, R: Read + Unpin + Send> Read for VerifyingReader<D, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_read(cx, buf) {
            Poll::Ready(Ok(size)) => Poll::Ready(if size > 0 {
                this.digester.update(&buf[0..size]);
                *this.read += size;
                if this.read > this.size {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "unexpected stream size {} (expected {})",
                            this.read, this.size
                        ),
                    ))
                } else {
                    Ok(size)
                }
            } else if this.read < this.size {
                // size == 0, EOF
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "unexpected stream size {} (expected {})",
                        this.read, this.size
                    ),
                ))
            } else if this.read == this.size {
                // size == 0, EOF
                *this.read += 1;
                let digest = this.digester.finalize_fixed_reset();
                if this.digest == &digest {
                    Ok(0)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "unexpected stream digest `{}` (expected `{}`)",
                            hex::encode(&digest),
                            hex::encode(&this.digest),
                        ),
                    ))
                }
            } else {
                // size = 0, EOF
                Ok(0)
            }),
            st => st,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::io::{Cursor, ReadExt};
    use sha2::{Digest, Sha256};

    #[async_std::test]
    async fn test_verifying_reader() {
        let data = b"hello world";
        let size = data.len();
        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected_digest = hasher.finalize();

        let mut hasher1 = Sha256::default();
        hasher1.update(data);
        let expected_digest1 = hasher1.finalize_fixed_reset();

        assert_eq!(expected_digest, expected_digest1);

        let expected_digest2 = expected_digest.clone();
        assert_eq!(expected_digest, expected_digest2);

        let cursor = Cursor::new(data);
        let mut reader =
            VerifyingReader::<Sha256, _>::new(cursor, size, expected_digest.clone().into());

        let mut buf = vec![0; size];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, size);
        assert_eq!(&buf, data);

        // Check that reading to the end verifies the digest
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        // Check that reading past the end returns 0 but no error
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[async_std::test]
    async fn test_verifying_reader_incorrect_digest() {
        let data = b"hello world";
        let size = data.len();
        let incorrect_digest = Sha256::digest(b"incorrect");

        let cursor = Cursor::new(data);
        let mut reader =
            VerifyingReader::<Sha256, _>::new(cursor, size, incorrect_digest.clone().into());

        let mut buf = vec![0; size];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, size);
        assert_eq!(&buf, data);

        // Reading to the end should result in a digest verification error
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("unexpected stream digest"));
    }

    #[async_std::test]
    async fn test_verifying_reader_incorrect_size() {
        let data = b"hello world";
        let size = data.len() + 1; // incorrect size
        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected_digest = hasher.finalize();

        let cursor = Cursor::new(data);
        let mut reader =
            VerifyingReader::<Sha256, _>::new(cursor, size, expected_digest.clone().into());

        let mut buf = vec![0; data.len()];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf, data);

        // Reading to the end should result in a size mismatch error
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("unexpected stream size"));
    }
}
