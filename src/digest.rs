//! Digest verification

pub use digest::{FixedOutputReset, Output as DigesterOutput};
use {
    ::serde::{
        de::{self, Visitor},
        Deserialize, Deserializer, Serialize, Serializer,
    },
    async_std::{
        io::prelude::*,
        task::{ready, Context, Poll},
    },
    pin_project::pin_project,
    std::{fmt, pin::Pin},
};

pub trait Digester: FixedOutputReset + Default + Send {}
impl<T: FixedOutputReset + Default + Send> Digester for T {}

pub trait DigestFieldName {
    const DIGEST_FIELD_NAME: &'static str;
}
impl DigestFieldName for sha2::Sha256 {
    const DIGEST_FIELD_NAME: &'static str = "SHA256";
}
impl DigestFieldName for md5::Md5 {
    const DIGEST_FIELD_NAME: &'static str = "MD5sum";
}

#[derive(Default, Debug)]
pub struct Digest<D: Digester> {
    inner: DigesterOutput<D>,
}

pub trait DigestUser {
    type Digester;
}
pub(crate) type DigestOf<T> = Digest<<T as DigestUser>::Digester>;
pub(crate) type DigesterOf<T> = <T as DigestUser>::Digester;
pub(crate) const fn digest_field_name<T: DigestUser>() -> &'static str 
where 
    T::Digester: DigestFieldName,
{
    <T::Digester as DigestFieldName>::DIGEST_FIELD_NAME
}

impl<D: Digester> Serialize for Digest<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self::serde::hex::serialize(self, serializer)
    }
}

impl<'de, D: Digester> Deserialize<'de> for Digest<D> {
    fn deserialize<DE>(deserializer: DE) -> Result<Self, DE::Error>
    where
        DE: Deserializer<'de>,
    {
        struct DigestVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Digester> Visitor<'de> for DigestVisitor<T> {
            type Value = Digest<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hex encoded string representing the digest")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut inner = DigesterOutput::<T>::default();
                hex::decode_to_slice(value, inner.as_mut_slice())
                    .map_err(|e| de::Error::custom(format!("error decoding hash: {}", e)))?;
                Ok(Digest { inner })
            }
        }
        deserializer.deserialize_str(DigestVisitor(std::marker::PhantomData))
    }
}

pub mod serde {
    // Hexadecimal encoding (default). Accepts mixed case, outputs only lowercase.
    pub mod hex {
        use crate::digest::{Digest, Digester, DigesterOutput};
        use serde::{
            de::{self, Visitor},
            Deserializer, Serializer,
        };
        use std::{fmt, marker::PhantomData};

        pub fn serialize<D, S>(value: &Digest<D>, serializer: S) -> Result<S::Ok, S::Error>
        where
            D: Digester,
            S: Serializer,
        {
            let s = ::hex::encode(value.inner.as_slice());
            serializer.serialize_str(&s)
        }

        pub fn deserialize<'de, D, DE>(deserializer: DE) -> Result<Digest<D>, DE::Error>
        where
            D: Digester,
            DE: Deserializer<'de>,
        {
            struct HexVisitor<T>(PhantomData<T>);

            impl<'de, T: Digester> Visitor<'de> for HexVisitor<T> {
                type Value = Digest<T>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(
                        f,
                        "a string with hex-encoded digest ({} hex chars)",
                        T::output_size() * 2
                    )
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    let mut inner = DigesterOutput::<T>::default();
                    ::hex::decode_to_slice(v, inner.as_mut_slice())
                        .map_err(|e| E::custom(format!("error decoding hex digest: {}", e)))?;
                    Ok(Digest { inner })
                }
            }

            deserializer.deserialize_str(HexVisitor::<D>(PhantomData))
        }
    }

    // base64 URL-safe encoding
    pub mod base64 {
        use crate::digest::{Digest, Digester, DigesterOutput};
        use ::base64::prelude::*;
        use serde::{
            de::{self, Visitor},
            Deserializer, Serializer,
        };
        use std::{fmt, marker::PhantomData};

        pub fn serialize<D, S>(value: &Digest<D>, serializer: S) -> Result<S::Ok, S::Error>
        where
            D: Digester,
            S: Serializer,
        {
            let s = ::base64::engine::general_purpose::URL_SAFE.encode(value.inner.as_slice());
            serializer.serialize_str(&s)
        }

        pub fn deserialize<'de, D, DE>(deserializer: DE) -> Result<Digest<D>, DE::Error>
        where
            D: Digester,
            DE: Deserializer<'de>,
        {
            struct B64Visitor<T>(PhantomData<T>);

            impl<'de, T: Digester> Visitor<'de> for B64Visitor<T> {
                type Value = Digest<T>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a base64url encoded digest")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    let bytes = ::base64::engine::general_purpose::URL_SAFE
                        .decode(v.as_bytes())
                        .map_err(|e| {
                            E::custom(format!("error decoding base64-url digest: {}", e))
                        })?;

                    if bytes.len() != T::output_size() {
                        return Err(E::custom(format!(
                            "invalid digest length {} (expected {})",
                            bytes.len(),
                            T::output_size()
                        )));
                    }

                    let mut inner = DigesterOutput::<T>::default();
                    inner.as_mut_slice().copy_from_slice(&bytes);
                    Ok(Digest { inner })
                }
            }

            deserializer.deserialize_str(B64Visitor::<D>(PhantomData))
        }
    }
}

impl<D: Digester> std::ops::Deref for Digest<D> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub(crate) trait GetDigest<D: Digester> {
    fn get_digest(&mut self) -> Digest<D>;
}

impl<D: Digester> Clone for Digest<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<This: Digester, That: Digester> PartialEq<Digest<That>> for Digest<This> {
    fn eq(&self, other: &Digest<That>) -> bool {
        This::output_size() == That::output_size()
            && self.inner.as_slice() == other.inner.as_slice()
    }
}

impl<D: Digester> PartialEq<str> for Digest<D> {
    fn eq(&self, other: &str) -> bool {
        let mut digest = DigesterOutput::<D>::default();
        match hex::decode_to_slice(other, digest.as_mut_slice()) {
            Ok(_) => self.inner.eq(&digest),
            Err(_) => false,
        }
    }
}

impl<D: Digester> Digest<D> {
    pub fn into_inner(self) -> DigesterOutput<D> {
        self.inner
    }
}

impl<D: Digester> TryFrom<&str> for Digest<D> {
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

impl<D: Digester> TryFrom<&[u8]> for Digest<D> {
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

impl<D: Digester> From<Digest<D>> for String {
    fn from(value: Digest<D>) -> Self {
        hex::encode(&value.inner)
    }
}

impl<D: Digester> From<Digest<D>> for DigesterOutput<D> {
    fn from(value: Digest<D>) -> Self {
        value.inner
    }
}

impl<D: Digester> From<DigesterOutput<D>> for Digest<D> {
    fn from(value: DigesterOutput<D>) -> Self {
        Self { inner: value }
    }
}

impl<D: Digester> std::fmt::LowerHex for Digest<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", hex::encode(&self.inner))
    }
}

#[pin_project]
pub struct DigestingReader<D: Digester, R: Read + Unpin + Send> {
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
}

impl<D: Digester, R: Read + Unpin + Send> GetDigest<D> for DigestingReader<D, R> {
    fn get_digest(&mut self) -> Digest<D> {
        Digest {
            inner: self.digester.finalize_fixed_reset(),
        }
    }
}

impl<D: Digester, R: Read + Unpin + Send> Read for DigestingReader<D, R> {
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
pub struct VerifyingReader<D: Digester, R: Read + Unpin + Send> {
    digester: D,
    digest: DigesterOutput<D>,
    size: u64,
    read: u64,
    #[pin]
    inner: R,
}

impl<D: Digester + Default + Send, R: Read + Unpin + Send> GetDigest<D> for VerifyingReader<D, R> {
    fn get_digest(&mut self) -> Digest<D> {
        Digest {
            inner: self.digest.clone(),
        }
    }
}

impl<D: Digester + Default + Send, R: Read + Unpin + Send> VerifyingReader<D, R> {
    pub fn new(reader: R, size: u64, digest: Digest<D>) -> Self {
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
                *this.read += size as u64;
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
        let size = data.len() as u64;
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

        let mut buf = vec![0; size.try_into().unwrap()];
        let n = reader.read(&mut buf).await.unwrap() as u64;
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
        let size = data.len() as u64;
        let incorrect_digest = Sha256::digest(b"incorrect");

        let cursor = Cursor::new(data);
        let mut reader =
            VerifyingReader::<Sha256, _>::new(cursor, size, incorrect_digest.clone().into());

        let mut buf = vec![0; size.try_into().unwrap()];
        let n = reader.read(&mut buf).await.unwrap() as u64;
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
        let size = data.len() as u64 + 1; // incorrect size
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
