//! Digest verification

pub use digest::Output as HashOutput;
use {
    ::serde::{
        de::{self, Visitor},
        Deserialize, Deserializer, Serialize, Serializer,
    },
    digest::FixedOutputReset,
    futures_lite::ready,
    pin_project::pin_project,
    smol::io::{AsyncRead, AsyncWrite},
    std::task::{Context, Poll},
    std::{fmt, pin::Pin},
};

// pub enum HashRef<'a, H: HashAlgo> {
//     Borrowed(&'a Hash<H>),
//     Boxed(Box<Hash<H>>),
// }
//
// impl<'a, H: HashAlgo> std::fmt::Debug for HashRef<'a, H> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "\"{}\"", hex::encode(self.as_ref()))
//     }
// }
//
// impl<'a, H: HashAlgo> AsRef<Hash<H>> for HashRef<'a, H> {
//     fn as_ref(&self) -> &Hash<H> {
//         match self {
//             HashRef::Borrowed(b) => b,
//             HashRef::Boxed(b) => b.as_ref(),
//         }
//     }
// }
//
// impl<'a, H: HashAlgo> std::ops::Deref for HashRef<'a, H> {
//     type Target = Hash<H>;
//     fn deref(&self) -> &Self::Target {
//         match self {
//             HashRef::Borrowed(b) => b,
//             HashRef::Boxed(b) => b.as_ref(),
//         }
//     }
// }
//
// impl<'a, H: HashAlgo> From<&'a Hash<H>> for HashRef<'a, H> {
//     fn from(value: &'a Hash<H>) -> Self {
//         HashRef::Borrowed(value)
//     }
// }
//
// impl<'a, H: HashAlgo> From<Box<Hash<H>>> for HashRef<'a, H> {
//     fn from(value: Box<Hash<H>>) -> Self {
//         HashRef::Boxed(value)
//     }
// }
//
// impl<'a, H: HashAlgo> From<Hash<H>> for HashRef<'a, H> {
//     fn from(value: Hash<H>) -> Self {
//         HashRef::Boxed(Box::new(value))
//     }
// }
//
// impl<'a, H: HashAlgo> Clone for HashRef<'a, H> {
//     fn clone(&self) -> Self {
//         match self {
//             HashRef::Borrowed(b) => HashRef::Borrowed(b),
//             HashRef::Boxed(b) => HashRef::Boxed(b.clone()),
//         }
//     }
// }
//
// impl<'a, H: HashAlgo> From<&HashRef<'a, H>> for Hash<H> {
//     fn from(hashref: &HashRef<'a, H>) -> Self {
//         Hash {
//             inner: match hashref {
//                 HashRef::Borrowed(b) => b.inner.clone(),
//                 HashRef::Boxed(b) => b.inner.clone(),
//             },
//         }
//     }
// }
//
// impl<'a, H: HashAlgo> Eq for HashRef<'a, H> {}
// impl<'a, H: HashAlgo> PartialEq for HashRef<'a, H> {
//     fn eq(&self, other: &Self) -> bool {
//         use std::ops::Deref;
//         self.deref().eq(other.deref())
//     }
// }
//
// impl<'a, H: HashAlgo> HashRef<'a, H> {
//     pub fn verifying_reader<R: Read + Unpin + Send>(
//         &self,
//         size: u64,
//         reader: R,
//     ) -> VerifyingReader<H, R> {
//         VerifyingReader::new(reader, size, self.into())
//     }
//     pub fn hash(data: &[u8]) -> Self {
//         let mut hasher = H::default();
//         hasher.update(data);
//         HashRef::Boxed(Box::new(Hash {
//             inner: hasher.finalize_fixed(),
//         }))
//     }
// }

#[derive(Debug, Clone)]
pub enum FileHash {
    MD5sum(Hash<md5::Md5>),
    SHA256(Hash<sha2::Sha256>),
    SHA512(Hash<sha2::Sha512>),
}
impl AsRef<[u8]> for FileHash {
    fn as_ref(&self) -> &[u8] {
        match self {
            FileHash::MD5sum(h) => h.as_ref(),
            FileHash::SHA256(h) => h.as_ref(),
            FileHash::SHA512(h) => h.as_ref(),
        }
    }
}
impl From<Hash<sha2::Sha512>> for FileHash {
    fn from(value: Hash<sha2::Sha512>) -> Self {
        FileHash::SHA512(value)
    }
}
impl From<Hash<sha2::Sha256>> for FileHash {
    fn from(value: Hash<sha2::Sha256>) -> Self {
        FileHash::SHA256(value)
    }
}
impl From<Hash<md5::Md5>> for FileHash {
    fn from(value: Hash<md5::Md5>) -> Self {
        FileHash::MD5sum(value)
    }
}
impl std::ops::Deref for FileHash {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        match self {
            FileHash::MD5sum(h) => h.as_ref(),
            FileHash::SHA256(h) => h.as_ref(),
            FileHash::SHA512(h) => h.as_ref(),
        }
    }
}
impl FileHash {
    pub fn verifying_reader<'b, R: AsyncRead + Unpin + Send + 'b>(
        &self,
        size: u64,
        reader: R,
    ) -> Pin<Box<dyn AsyncRead + Send + 'b>> {
        match self {
            FileHash::MD5sum(h) => Box::pin(VerifyingReader::new(reader, size, h.clone())),
            FileHash::SHA256(h) => Box::pin(VerifyingReader::new(reader, size, h.clone())),
            FileHash::SHA512(h) => Box::pin(VerifyingReader::new(reader, size, h.clone())),
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            FileHash::MD5sum(_) => "MD5sum",
            FileHash::SHA256(_) => "SHA256",
            FileHash::SHA512(_) => "SHA512",
        }
    }
    pub fn hash(kind: &str, data: &[u8]) -> Option<Self> {
        match kind {
            "MD5sum" => Some(Hash::<md5::Md5>::hash(data).into()),
            "SHA256" => Some(Hash::<sha2::Sha256>::hash(data).into()),
            "SHA512" => Some(Hash::<sha2::Sha512>::hash(data).into()),
            _ => None,
        }
    }
}

impl TryFrom<&str> for FileHash {
    type Error = std::io::Error;
    fn try_from(value: &str) -> std::io::Result<Self> {
        use digest::OutputSizeUser;
        match value.len() {
            c if c == md5::Md5::output_size() * 2 => {
                Ok(FileHash::from(Hash::<md5::Md5>::try_from(value)?))
            }
            c if c == sha2::Sha256::output_size() * 2 => {
                Ok(FileHash::from(Hash::<sha2::Sha256>::try_from(value)?))
            }
            c if c == sha2::Sha512::output_size() * 2 => {
                Ok(FileHash::from(Hash::<sha2::Sha512>::try_from(value)?))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid digest length {}", value.len()),
            )),
        }
    }
}

impl Serialize for FileHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = ::hex::encode(self.as_ref());
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for FileHash {
    fn deserialize<DE>(deserializer: DE) -> Result<Self, DE::Error>
    where
        DE: Deserializer<'de>,
    {
        struct DigestVisitor;

        impl<'de> Visitor<'de> for DigestVisitor {
            type Value = FileHash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hex encoded string representing the digest")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                TryFrom::<&str>::try_from(value)
                    .map_err(|e| de::Error::custom(format!("error decoding hash: {}", e)))
            }
        }
        deserializer.deserialize_str(DigestVisitor)
    }
}

pub trait HashAlgo: FixedOutputReset + Default + Send {}

impl HashAlgo for sha2::Sha256 {}
impl HashAlgo for sha2::Sha512 {}
impl HashAlgo for md5::Md5 {}

#[derive(Default, Debug)]
pub struct Hash<D: HashAlgo> {
    inner: HashOutput<D>,
}

impl<D: HashAlgo> Hash<D> {
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = D::default();
        hasher.update(data);
        Hash {
            inner: hasher.finalize_fixed(),
        }
    }
}

impl<H: HashAlgo> AsRef<[u8]> for Hash<H> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl<D: HashAlgo> Serialize for Hash<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self::serde::hex::serialize(self, serializer)
    }
}

impl<'de, D: HashAlgo> Deserialize<'de> for Hash<D> {
    fn deserialize<DE>(deserializer: DE) -> Result<Self, DE::Error>
    where
        DE: Deserializer<'de>,
    {
        struct DigestVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: HashAlgo> Visitor<'de> for DigestVisitor<T> {
            type Value = Hash<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hex encoded string representing the digest")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut inner = HashOutput::<T>::default();
                hex::decode_to_slice(value, inner.as_mut_slice())
                    .map_err(|e| de::Error::custom(format!("error decoding hash: {}", e)))?;
                Ok(Hash { inner })
            }
        }
        deserializer.deserialize_str(DigestVisitor(std::marker::PhantomData))
    }
}

pub mod serde {
    // Hexadecimal encoding (default). Accepts mixed case, outputs only lowercase.
    pub mod hex {
        use crate::hash::{Hash, HashAlgo, HashOutput};
        use serde::{
            de::{self, Visitor},
            Deserializer, Serializer,
        };
        use std::{fmt, marker::PhantomData};

        pub fn serialize<D, S>(value: &Hash<D>, serializer: S) -> Result<S::Ok, S::Error>
        where
            D: HashAlgo,
            S: Serializer,
        {
            let s = ::hex::encode(value.inner.as_slice());
            serializer.serialize_str(&s)
        }

        pub fn deserialize<'de, D, DE>(deserializer: DE) -> Result<Hash<D>, DE::Error>
        where
            D: HashAlgo,
            DE: Deserializer<'de>,
        {
            struct HexVisitor<T>(PhantomData<T>);

            impl<'de, T: HashAlgo> Visitor<'de> for HexVisitor<T> {
                type Value = Hash<T>;

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
                    let mut inner = HashOutput::<T>::default();
                    ::hex::decode_to_slice(v, inner.as_mut_slice())
                        .map_err(|e| E::custom(format!("error decoding hex digest: {}", e)))?;
                    Ok(Hash { inner })
                }
            }

            deserializer.deserialize_str(HexVisitor::<D>(PhantomData))
        }
    }

    // base64 URL-safe encoding
    pub mod base64 {
        use crate::hash::{Hash, HashAlgo, HashOutput};
        use ::base64::prelude::*;
        use serde::{
            de::{self, Visitor},
            Deserializer, Serializer,
        };
        use std::{fmt, marker::PhantomData};

        pub fn serialize<D, S>(value: &Hash<D>, serializer: S) -> Result<S::Ok, S::Error>
        where
            D: HashAlgo,
            S: Serializer,
        {
            let s = ::base64::engine::general_purpose::URL_SAFE.encode(value.inner.as_slice());
            serializer.serialize_str(&s)
        }

        pub fn deserialize<'de, D, DE>(deserializer: DE) -> Result<Hash<D>, DE::Error>
        where
            D: HashAlgo,
            DE: Deserializer<'de>,
        {
            struct B64Visitor<T>(PhantomData<T>);

            impl<'de, T: HashAlgo> Visitor<'de> for B64Visitor<T> {
                type Value = Hash<T>;

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

                    let mut inner = HashOutput::<T>::default();
                    inner.as_mut_slice().copy_from_slice(&bytes);
                    Ok(Hash { inner })
                }
            }

            deserializer.deserialize_str(B64Visitor::<D>(PhantomData))
        }
    }
}

impl<D: HashAlgo> std::ops::Deref for Hash<D> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D: HashAlgo> Clone for Hash<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<This: HashAlgo, That: HashAlgo> PartialEq<Hash<That>> for Hash<This> {
    fn eq(&self, other: &Hash<That>) -> bool {
        This::output_size() == That::output_size()
            && self.inner.as_slice() == other.inner.as_slice()
    }
}

impl<D: HashAlgo> PartialEq<str> for Hash<D> {
    fn eq(&self, other: &str) -> bool {
        let mut digest = HashOutput::<D>::default();
        match hex::decode_to_slice(other, digest.as_mut_slice()) {
            Ok(_) => self.inner.eq(&digest),
            Err(_) => false,
        }
    }
}

impl<D: HashAlgo> Hash<D> {
    pub fn into_inner(self) -> HashOutput<D> {
        self.inner
    }
}

impl<D: HashAlgo> TryFrom<&str> for Hash<D> {
    type Error = std::io::Error;
    fn try_from(value: &str) -> std::io::Result<Self> {
        let mut inner = HashOutput::<D>::default();
        hex::decode_to_slice(value, inner.as_mut_slice()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid digest: {}", e),
            )
        })?;
        Ok(Hash { inner })
    }
}

impl<D: HashAlgo> TryFrom<&[u8]> for Hash<D> {
    type Error = std::io::Error;
    fn try_from(value: &[u8]) -> std::io::Result<Self> {
        if value.len() == D::output_size() {
            Ok(Hash {
                inner: HashOutput::<D>::from_slice(value).clone(),
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

fn path_for_hash(bytes: &[u8]) -> std::path::PathBuf {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let needs_sep = bytes.len() > 1;
    let total_len = 2 * bytes.len() + usize::from(needs_sep);
    let mut os = std::ffi::OsString::with_capacity(total_len);

    let b0 = bytes[0];
    let mut pair = [0u8; 2];
    pair[0] = HEX[(b0 >> 4) as usize];
    pair[1] = HEX[(b0 & 0x0f) as usize];
    // Safety: HEX only contains ASCII; pair is always valid UTF-8
    unsafe {
        os.push(std::str::from_utf8_unchecked(&pair));
    }

    if needs_sep {
        os.push(std::ffi::OsStr::new("/"));
        for &b in &bytes[1..] {
            pair[0] = HEX[(b >> 4) as usize];
            pair[1] = HEX[(b & 0x0f) as usize];
            // Safety: HEX only contains ASCII; pair is always valid UTF-8
            unsafe {
                os.push(std::str::from_utf8_unchecked(&pair));
            }
        }
    }

    std::path::PathBuf::from(os)
}

impl From<&FileHash> for std::path::PathBuf {
    fn from(value: &FileHash) -> Self {
        path_for_hash(value.as_ref())
    }
}

impl<D: HashAlgo> From<&Hash<D>> for std::path::PathBuf {
    fn from(value: &Hash<D>) -> Self {
        path_for_hash(&value.inner)
    }
}

impl<D: HashAlgo> From<Hash<D>> for Box<[u8]> {
    fn from(value: Hash<D>) -> Self {
        Vec::from(value.inner.as_slice()).into_boxed_slice()
    }
}

impl<D: HashAlgo> From<Hash<D>> for String {
    fn from(value: Hash<D>) -> Self {
        hex::encode(&value.inner)
    }
}

impl<D: HashAlgo> From<Hash<D>> for HashOutput<D> {
    fn from(value: Hash<D>) -> Self {
        value.inner
    }
}

impl<D: HashAlgo> From<HashOutput<D>> for Hash<D> {
    fn from(value: HashOutput<D>) -> Self {
        Self { inner: value }
    }
}

impl<D: HashAlgo> std::fmt::LowerHex for Hash<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", hex::encode(&self.inner))
    }
}

#[pin_project]
pub struct HashingReader<D: HashAlgo, R: AsyncRead + Unpin + Send> {
    digester: D,
    counter: u64,
    #[pin]
    inner: R,
}

pub trait HashingRead: AsyncRead + Unpin {
    fn into_hash_and_size(&mut self) -> (Box<[u8]>, u64);
}

impl<D: HashAlgo + Default + Send, R: AsyncRead + Unpin + Send> HashingReader<D, R> {
    pub fn new(reader: R) -> Self {
        Self {
            counter: 0,
            digester: D::default(),
            inner: reader,
        }
    }
    pub fn into_hash(self) -> Hash<D> {
        Hash {
            inner: self.digester.finalize_fixed(),
        }
    }
}
impl<D: HashAlgo + Default + Send, R: AsyncRead + Unpin + Send> HashingRead
    for HashingReader<D, R>
{
    fn into_hash_and_size(&mut self) -> (Box<[u8]>, u64) {
        (
            self.digester
                .finalize_fixed_reset()
                .to_vec()
                .into_boxed_slice(),
            self.counter,
        )
    }
}

impl<D: HashAlgo, R: AsyncRead + Unpin + Send> AsyncRead for HashingReader<D, R> {
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
                *this.counter += size as u64;
                Ok(size)
            }
            Err(err) => Err(err),
        })
    }
}

pub struct SyncHashingWriter<D: HashAlgo, W: std::io::Write> {
    digester: D,
    inner: W,
}

impl<D: HashAlgo + Default, W: std::io::Write> SyncHashingWriter<D, W> {
    pub fn new(writer: W) -> Self {
        Self {
            digester: D::default(),
            inner: writer,
        }
    }
    pub fn into_hash(self) -> Hash<D> {
        Hash {
            inner: self.digester.finalize_fixed(),
        }
    }
}

impl<D: HashAlgo, W: std::io::Write> std::io::Write for SyncHashingWriter<D, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.inner.write(buf) {
            Ok(0) => Ok(0),
            Ok(size) => {
                self.digester.update(&buf[0..size]);
                Ok(size)
            }
            Err(err) => Err(err),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[pin_project]
pub struct HashingWriter<D: HashAlgo, W: AsyncWrite + Unpin + Send> {
    digester: D,
    #[pin]
    inner: W,
}

impl<D: HashAlgo + Default + Send, W: AsyncWrite + Unpin + Send> HashingWriter<D, W> {
    pub fn new(writer: W) -> Self {
        Self {
            digester: D::default(),
            inner: writer,
        }
    }

    pub fn into_hash(self) -> Hash<D> {
        Hash {
            inner: self.digester.finalize_fixed(),
        }
    }
}

impl<D: HashAlgo, W: AsyncWrite + Unpin + Send> AsyncWrite for HashingWriter<D, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_write(cx, buf) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(size)) => {
                this.digester.update(&buf[..size]);
                Poll::Ready(Ok(size))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}

#[pin_project]
pub struct VerifyingReader<D: HashAlgo, R: AsyncRead + Unpin + Send> {
    digester: D,
    digest: HashOutput<D>,
    size: u64,
    read: u64,
    #[pin]
    inner: R,
}

impl<D: HashAlgo + Default + Send, R: AsyncRead + Unpin + Send> VerifyingReader<D, R> {
    pub fn new(reader: R, size: u64, digest: Hash<D>) -> Self {
        Self {
            digester: D::default(),
            digest: digest.into(),
            size,
            read: 0,
            inner: reader,
        }
    }
}

impl<D: HashAlgo + Default + Send, R: AsyncRead + Unpin + Send> AsyncRead
    for VerifyingReader<D, R>
{
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
    use macro_rules_attribute::apply;
    use sha2::{Digest, Sha256};
    use smol::io::{AsyncReadExt, Cursor};
    use smol_macros::test;

    #[apply(test!)]
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

    #[apply(test!)]
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

    #[apply(test!)]
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
