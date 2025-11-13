//! Digest verification

pub use digest::Output as HashOutput;
use {
    ::serde::{Deserialize, Deserializer, Serialize, Serializer},
    base64::Engine,
    digest::{FixedOutput, FixedOutputReset, OutputSizeUser},
    pin_project_lite::pin_project,
    smol::{
        io::{AsyncRead, AsyncWrite},
        ready,
    },
    std::{
        ffi::{OsStr, OsString},
        fmt,
        path::{Path, PathBuf},
        pin::Pin,
        task::{Context, Poll},
    },
};

pub trait HashAlgo: FixedOutput + FixedOutputReset + Default + Send {
    const NAME: &'static str;
    const SRI_NAME: &'static str;
    fn hash(hash: HashOutput<Self>) -> Hash;
    fn into_hash(mut self) -> Hash {
        Self::hash(self.finalize_fixed_reset())
    }
}

impl HashAlgo for sha2::Sha256 {
    const NAME: &'static str = "SHA256";
    const SRI_NAME: &'static str = "sha256";
    fn hash(hash: HashOutput<Self>) -> Hash {
        Hash::SHA256(InnerHash { inner: hash })
    }
}
impl HashAlgo for sha2::Sha512 {
    const NAME: &'static str = "SHA512";
    const SRI_NAME: &'static str = "sha512";
    fn hash(hash: HashOutput<Self>) -> Hash {
        Hash::SHA512(InnerHash { inner: hash })
    }
}
impl HashAlgo for md5::Md5 {
    const NAME: &'static str = "MD5sum";
    const SRI_NAME: &'static str = "md5";
    fn hash(hash: HashOutput<Self>) -> Hash {
        Hash::MD5sum(InnerHash { inner: hash })
    }
}
impl HashAlgo for blake3::Hasher {
    const NAME: &'static str = "Blake3";
    const SRI_NAME: &'static str = "blake3";
    fn hash(hash: HashOutput<Self>) -> Hash {
        Hash::Blake3(InnerHash { inner: hash })
    }
}

#[derive(Clone, Default)]
pub struct InnerHash<D: HashAlgo> {
    inner: HashOutput<D>,
}

impl<D: HashAlgo> std::fmt::Debug for InnerHash<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", D::NAME, hex::encode(&self.inner))
    }
}

impl<D: HashAlgo> PartialEq for InnerHash<D> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

#[allow(dead_code)]
impl<D: HashAlgo> InnerHash<D> {
    const fn sri_hash_name() -> &'static str {
        D::SRI_NAME
    }
    const fn hash_name() -> &'static str {
        D::NAME
    }
    const fn sri_name(&self) -> &'static str {
        D::SRI_NAME
    }
    const fn name(&self) -> &'static str {
        D::NAME
    }
    fn size(&self) -> usize {
        <D as OutputSizeUser>::output_size()
    }
    fn hash_size() -> usize {
        <D as OutputSizeUser>::output_size()
    }
    fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
    fn hash(&self) -> Hash {
        D::hash(self.inner.clone())
    }
    fn reader<'b, R: AsyncRead + Send + 'b>(
        &self,
        size: u64,
        reader: R,
    ) -> Pin<Box<dyn AsyncRead + Send + 'b>>
    where
        D: 'b,
    {
        Box::pin(VerifyingReader::<D, _>::new(
            reader,
            size,
            self.inner.clone(),
        ))
    }
    fn verifying_reader<'b, R: AsyncRead + Send + 'b>(
        &self,
        size: u64,
        reader: R,
    ) -> Pin<Box<dyn AsyncHashingRead + Send + 'b>>
    where
        D: 'b,
    {
        Box::pin(VerifyingReader::<D, _>::new(
            reader,
            size,
            self.inner.clone(),
        ))
    }
    fn hashing_reader<'b, R: AsyncRead + Send + 'b>(
        reader: R,
    ) -> Pin<Box<dyn AsyncHashingRead + Send + 'b>>
    where
        D: 'b,
    {
        Box::pin(HashingReader::<D, _>::new(reader))
    }
    fn hex_size() -> usize {
        <D as OutputSizeUser>::output_size() * 2
    }
    fn from_hex(value: &str) -> std::io::Result<Self> {
        if value.len() != Self::hex_size() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid hex digest length {}, expected {}",
                    value.len(),
                    Self::hex_size()
                ),
            ));
        }
        let mut inner = HashOutput::<D>::default();
        hex::decode_to_slice(value, &mut inner).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("error decoding hex digest: {}", err),
            )
        })?;
        Ok(InnerHash { inner })
    }
    fn to_hex(&self) -> String {
        hex::encode(&self.inner)
    }
    fn base64_size() -> usize {
        base64::encoded_len(<D as OutputSizeUser>::output_size(), false).unwrap()
    }
    fn from_base64(value: &str) -> Result<Self, std::io::Error> {
        let mut inner = HashOutput::<D>::default();
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode_slice(value, &mut inner) {
            Ok(n) if n == <D as OutputSizeUser>::output_size() => Ok(InnerHash { inner }),
            Ok(n) => Err(base64::DecodeSliceError::DecodeError(
                base64::DecodeError::InvalidLength(n),
            )),
            Err(err) => Err(err),
        }
        .map_err(|err| std::io::Error::other(format!("error decoding base64 digest: {}", err)))
    }
    fn to_base64(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.inner)
    }
    fn from_sri(value: &str) -> std::io::Result<Self> {
        let mut parts = value.splitn(2, '-');
        let name = parts
            .next()
            .ok_or_else(|| std::io::Error::other("missing hash name"))?;
        let b64 = parts
            .next()
            .ok_or_else(|| std::io::Error::other("missing base64 digest"))?;
        if name != D::SRI_NAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid hash name {}, expected {}", name, D::SRI_NAME),
            ));
        }
        let mut inner = HashOutput::<D>::default();
        match base64::engine::general_purpose::STANDARD.decode_slice(b64, &mut inner) {
            Ok(n) if n == <D as OutputSizeUser>::output_size() => Ok(InnerHash { inner }),
            Ok(n) => Err(base64::DecodeSliceError::DecodeError(
                base64::DecodeError::InvalidLength(n),
            )),
            Err(err) => Err(err),
        }
        .map_err(|err| std::io::Error::other(format!("error decoding base64 digest: {}", err)))
    }
    fn to_sri(&self) -> String {
        format!(
            "{}-{}",
            D::SRI_NAME,
            base64::engine::general_purpose::STANDARD.encode(&self.inner)
        )
    }
}
impl<D: HashAlgo> AsRef<[u8]> for InnerHash<D> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl<D: HashAlgo> From<HashOutput<D>> for InnerHash<D> {
    fn from(value: HashOutput<D>) -> Self {
        Self { inner: value }
    }
}
impl<D: HashAlgo> From<InnerHash<D>> for HashOutput<D> {
    fn from(value: InnerHash<D>) -> Self {
        value.inner
    }
}

#[derive(Clone, PartialEq)]
pub enum Hash {
    MD5sum(InnerHash<md5::Md5>),
    SHA256(InnerHash<sha2::Sha256>),
    SHA512(InnerHash<sha2::Sha512>),
    Blake3(InnerHash<blake3::Hasher>),
}

impl Default for Hash {
    fn default() -> Self {
        Hash::SHA256(InnerHash::<sha2::Sha256>::default())
    }
}

macro_rules! delegate {
    ( $vis:vis fn $name:ident $(< $($gen:tt),* $(,)? >)?
        (&self $(, $p:ident : $ty:ty)* $(,)?) -> $ret:ty $(where $($where:tt)* )? ) => {
        $vis fn $name $(< $($gen),* >)? (&self $(, $p : $ty)*) -> $ret $(where $($where)* )? {
            match self {
                Self::MD5sum(h) => h.$name($($p),*),
                Self::SHA256(h) => h.$name($($p),*),
                Self::SHA512(h) => h.$name($($p),*),
                Self::Blake3(h) => h.$name($($p),*),
            }
        }
    };
}

macro_rules! delegate_block {
    ( $var:expr => $test:ident $block:block or $err:expr ) => {
        match $var {
            val if val == InnerHash::<md5::Md5>::$test() => {
                type D = ::md5::Md5;
                $block
            }
            val if val == InnerHash::<sha2::Sha256>::$test() => {
                type D = ::sha2::Sha256;
                $block
            }
            val if val == InnerHash::<sha2::Sha512>::$test() => {
                type D = ::sha2::Sha512;
                $block
            }
            val if val == InnerHash::<blake3::Hasher>::$test() => {
                type D = ::blake3::Hasher;
                $block
            }
            err => $err(err),
        }
    };
}

impl Hash {
    delegate! { pub fn size(&self) -> usize }
    delegate! { pub fn name(&self) -> &'static str }
    delegate! { pub fn sri_name(&self) -> &'static str }
    delegate! { pub fn as_bytes(&self) -> &[u8] }
    delegate! { pub fn to_hex(&self) -> String }
    delegate! { pub fn to_base64(&self) -> String }
    delegate! { pub fn to_sri(&self) -> String }
    delegate! { pub fn reader<'b, R>(
            &self,
            size: u64,
            reader: R,
        ) -> Pin<Box<dyn AsyncRead + Send + 'b>>
        where
            R: AsyncRead + Send + 'b
    }
    delegate! { pub fn verifying_reader<'b, R>(
            &self,
            size: u64,
            reader: R,
        ) -> Pin<Box<dyn AsyncHashingRead + Send + 'b>>
        where
            R: AsyncRead + Send + 'b
    }
    pub fn hashing_reader_for<'b, R: AsyncRead + Send + 'b>(
        hash: &str,
        reader: R,
    ) -> std::io::Result<Pin<Box<dyn AsyncHashingRead + Send + 'b>>> {
        delegate_block! { hash => hash_name {
                Ok(Self::hashing_reader::<D, _>(reader))
            } or |err| {
                Err(std::io::Error::other(format!("hash {} not supported", err)))
            }
        }
    }
    pub fn new_from_hash<D>(hash: HashOutput<D>) -> Self
    where
        D: HashAlgo,
    {
        D::hash(hash)
    }
    pub fn hashing_reader<'b, D, R>(reader: R) -> Pin<Box<dyn AsyncHashingRead + Send + 'b>>
    where
        D: HashAlgo + 'static,
        R: AsyncRead + Send + 'b,
    {
        InnerHash::<D>::hashing_reader(reader)
    }
    pub fn store_name<P: AsRef<Path>>(&self, prefix: Option<P>, mut levels: usize) -> PathBuf {
        let pref = prefix.as_ref().map(|p| p.as_ref().as_os_str());
        let total_len = pref.as_ref().map_or(0, |p| p.len() + 1)
            + self.sri_name().len()
            + 1
            + self.size() * 2
            + levels;
        let mut buffer = OsString::with_capacity(total_len);
        if let Some(p) = prefix {
            buffer.push(p.as_ref());
            buffer.push("/");
        }
        buffer.push(self.sri_name());
        buffer.push("/");
        const fn hexadecimal(c: u8) -> [u8; 2] {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            [HEX[(c >> 4) as usize], HEX[(c & 0x0f) as usize]]
        }
        let mut hash = self.as_ref();
        while !hash.is_empty() {
            let d = hexadecimal(hash[0]);
            buffer.push(unsafe { OsStr::from_encoded_bytes_unchecked(&d) });
            if levels > 0 {
                buffer.push("/");
                levels -= 1;
            }
            hash = &hash[1..];
        }
        buffer.into()
    }
    pub fn from_hex<S: AsRef<str>>(hash_name: &str, value: S) -> std::io::Result<Self> {
        let value = value.as_ref();
        delegate_block!(hash_name => hash_name {
            Ok(InnerHash::<D>::from_hex(value)?.hash())
        } or |err| {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid digest length {}", err),
            ))
        })
    }
    pub fn from_base64<S: AsRef<str>>(hash_name: &str, value: S) -> std::io::Result<Self> {
        let value = value.as_ref();
        delegate_block!(hash_name => hash_name {
            Ok(InnerHash::<D>::from_base64(value)?.hash())
        } or |err| {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid digest length {}", err),
            ))
        })
    }
    pub fn from_sri<S: AsRef<str>>(value: S) -> std::io::Result<Self> {
        let value = value.as_ref();
        let mut parts = value.splitn(2, '-');
        let name = parts
            .next()
            .ok_or_else(|| std::io::Error::other("missing hash name"))?;
        let b64 = parts
            .next()
            .ok_or_else(|| std::io::Error::other("missing base64 digest"))?;
        delegate_block!(name => sri_hash_name {
            let mut inner = HashOutput::<D>::default();
            let inner = match base64::engine::general_purpose::STANDARD.decode_slice(b64, &mut inner) {
                Ok(n) if n == <D as OutputSizeUser>::output_size() => Ok(InnerHash::<D>{ inner }),
                Ok(n) => Err(base64::DecodeSliceError::DecodeError(
                    base64::DecodeError::InvalidLength(n),
                )),
                Err(err) => Err(err),
            }
            .map_err(|err| std::io::Error::other(format!("error decoding base64 digest: {}", err)))?;
            Ok(inner.hash())
        } or |err| {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("hash {} not supported", err),
            ))
        })
    }
}
impl AsRef<[u8]> for Hash {
    delegate! { fn as_ref(&self) -> &[u8] }
}
impl std::fmt::Debug for Hash {
    delegate! { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result }
}
impl TryFrom<&str> for Hash {
    type Error = std::io::Error;
    fn try_from(value: &str) -> std::io::Result<Self> {
        Hash::from_sri(value)
    }
}
impl From<Hash> for String {
    fn from(value: Hash) -> Self {
        value.to_sri()
    }
}
impl From<&Hash> for String {
    fn from(value: &Hash) -> Self {
        value.to_sri()
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde::sri::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<DE>(deserializer: DE) -> Result<Self, DE::Error>
    where
        DE: Deserializer<'de>,
    {
        serde::sri::deserialize(deserializer)
    }
}

pub mod serde {
    use super::Hash;
    pub mod sri {
        use {
            super::Hash,
            ::serde::{
                de::{self, Visitor},
                Deserializer, Serializer,
            },
            std::fmt,
        };

        pub fn serialize<S>(value: &Hash, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&value.to_sri())
        }

        pub fn deserialize<'de, DE>(deserializer: DE) -> Result<Hash, DE::Error>
        where
            DE: Deserializer<'de>,
        {
            struct SriVisitor;

            impl Visitor<'_> for SriVisitor {
                type Value = Hash;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "an SRI digest",)
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    Hash::from_sri(v)
                        .map_err(|e| de::Error::custom(format!("error decoding SRI digest: {}", e)))
                }
            }

            deserializer.deserialize_str(SriVisitor)
        }
        pub mod opt {
            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            #[derive(Serialize, Deserialize)]
            #[serde(transparent)]
            struct WithSri(#[serde(with = "crate::hash::serde::sri")] super::Hash);

            pub fn serialize<S>(
                value: &Option<super::Hash>,
                serializer: S,
            ) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mapped = value.as_ref().cloned().map(WithSri);
                mapped.serialize(serializer)
            }

            pub fn deserialize<'de, De>(deserializer: De) -> Result<Option<super::Hash>, De::Error>
            where
                De: Deserializer<'de>,
            {
                let opt = Option::<WithSri>::deserialize(deserializer)?;
                Ok(opt.map(|w| w.0))
            }
        }
    }
    pub mod hex {
        use {super::Hash, ::serde::Serializer};

        pub fn serialize<S>(value: &Hash, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let s = ::hex::encode(value.as_ref());
            serializer.serialize_str(&s)
        }

        pub mod opt {
            use serde::{Serialize, Serializer};

            #[derive(Serialize)]
            #[serde(transparent)]
            struct WithHex(#[serde(with = "crate::hash::serde::hex")] super::Hash);

            pub fn serialize<S>(
                value: &Option<super::Hash>,
                serializer: S,
            ) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mapped = value.as_ref().cloned().map(WithHex);
                mapped.serialize(serializer)
            }
        }
    }

    pub mod base64 {
        use {super::Hash, ::base64::prelude::*, ::serde::Serializer};

        pub fn serialize<S>(value: &Hash, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let s = ::base64::engine::general_purpose::URL_SAFE.encode(value.as_ref());
            serializer.serialize_str(&s)
        }

        pub mod opt {
            use serde::{Serialize, Serializer};

            #[derive(Serialize)]
            #[serde(transparent)]
            struct WithB64(#[serde(with = "crate::hash::serde::base64")] super::Hash);

            pub fn serialize<S>(
                value: &Option<super::Hash>,
                serializer: S,
            ) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mapped = value.as_ref().cloned().map(WithB64);
                mapped.serialize(serializer)
            }
        }
    }
}

pin_project! {
    pub struct HashingReader<D, R> {
        digester: D,
        counter: u64,
        #[pin]
        inner: R,
    }
}

pub trait AsyncHashingRead: AsyncRead {
    fn hash(self: Pin<&mut Self>) -> Hash;
    fn size(self: Pin<&mut Self>) -> u64;
}

impl<D: HashAlgo, R: AsyncRead + Send> HashingReader<D, R> {
    pub fn new(reader: R) -> Self {
        Self {
            counter: 0,
            digester: D::default(),
            inner: reader,
        }
    }
    pub fn new_with_digester(digester: D, reader: R) -> Self {
        Self {
            counter: 0,
            digester,
            inner: reader,
        }
    }
    pub fn into_hash(self) -> Hash {
        D::hash(self.digester.finalize_fixed())
    }
    pub fn into_hash_output(self) -> HashOutput<D> {
        self.digester.finalize_fixed()
    }
    pub fn into_hash_and_size(self) -> (Hash, u64) {
        (D::hash(self.digester.finalize_fixed()), self.counter)
    }
}

impl<D: HashAlgo, R: AsyncRead + Send> AsyncHashingRead for HashingReader<D, R> {
    fn hash(self: Pin<&mut Self>) -> Hash {
        D::hash(self.project().digester.finalize_fixed_reset())
    }
    fn size(self: Pin<&mut Self>) -> u64 {
        *self.project().counter
    }
}
impl<D: HashAlgo, R: AsyncRead + Send> AsyncRead for HashingReader<D, R> {
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
    pub fn into_hash(self) -> Hash {
        D::hash(self.digester.finalize_fixed())
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

pin_project! {
    pub struct HashingWriter<D, W> {
        digester: D,
        #[pin]
        inner: W,
    }
}

impl<D: HashAlgo + Default + Send, W: AsyncWrite + Send> HashingWriter<D, W> {
    pub fn new(writer: W) -> Self {
        Self {
            digester: D::default(),
            inner: writer,
        }
    }

    pub fn into_hash(self) -> Hash {
        D::hash(self.digester.finalize_fixed())
    }
}

impl<D: HashAlgo, W: AsyncWrite + Send> AsyncWrite for HashingWriter<D, W> {
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

pin_project! {
    pub struct VerifyingReader<D: OutputSizeUser, R> {
        digester: D,
        digest: HashOutput<D>,
        size: u64,
        read: u64,
        #[pin]
        inner: R,
    }
}

impl<D: HashAlgo, R: AsyncRead + Send> VerifyingReader<D, R> {
    pub fn new(reader: R, size: u64, digest: HashOutput<D>) -> Self {
        Self {
            digester: D::default(),
            digest,
            size,
            read: 0,
            inner: reader,
        }
    }
}

impl<D: HashAlgo + Default + Send, R: AsyncRead + Send> AsyncRead for VerifyingReader<D, R> {
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
                    Err(std::io::Error::other(format!(
                        "unexpected stream size {} (expected {})",
                        this.read, this.size
                    )))
                } else {
                    Ok(size)
                }
            } else if this.read < this.size {
                // size == 0, EOF
                Err(std::io::Error::other(format!(
                    "unexpected stream size {} (expected {})",
                    this.read, this.size
                )))
            } else if this.read == this.size {
                // size == 0, EOF
                *this.read += 1;
                let digest = this.digester.finalize_fixed_reset();
                if this.digest == &digest {
                    Ok(0)
                } else {
                    Err(std::io::Error::other(format!(
                        "unexpected stream {} `{}` (expected `{}`)",
                        D::NAME,
                        hex::encode(&digest),
                        hex::encode(&this.digest),
                    )))
                }
            } else {
                // size = 0, EOF
                Ok(0)
            }),
            st => st,
        }
    }
}

impl<D: HashAlgo, R: AsyncRead + Send> AsyncHashingRead for VerifyingReader<D, R> {
    fn hash(self: Pin<&mut Self>) -> Hash {
        D::hash(self.project().digest.clone())
    }
    fn size(self: Pin<&mut Self>) -> u64 {
        *self.project().size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use smol::io::{AsyncReadExt, Cursor};
    use smol_macros::test;

    test! {
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

            let cursor = Cursor::new(data);
            let mut reader = VerifyingReader::<Sha256, _>::new(cursor, size, expected_digest);

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
    }

    test! {
        async fn test_verifying_reader_incorrect_digest() {
            let data = b"hello world";
            let size = data.len() as u64;
            let incorrect_digest = Sha256::digest(b"incorrect");

            let cursor = Cursor::new(data);
            let mut reader = VerifyingReader::<Sha256, _>::new(cursor, size, incorrect_digest);

            let mut buf = vec![0; size.try_into().unwrap()];
            let n = reader.read(&mut buf).await.unwrap() as u64;
            assert_eq!(n, size);
            assert_eq!(&buf, data);

            // Reading to the end should result in a digest verification error
            let err = reader.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::Other);
            assert!(err.to_string().contains("unexpected stream digest"));
        }
    }

    test! {
        async fn test_verifying_reader_incorrect_size() {
            let data = b"hello world";
            let size = data.len() as u64 + 1; // incorrect size
            let mut hasher = Sha256::new();
            hasher.update(data);
            let expected_digest = hasher.finalize();

            let cursor = Cursor::new(data);
            let mut reader = VerifyingReader::<Sha256, _>::new(cursor, size, expected_digest);

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
}
