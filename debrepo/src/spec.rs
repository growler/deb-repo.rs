use {
    crate::{
        content::{ContentProvider, IndexFile},
        hash::Hash,
        kvlist::KVList,
        version::{Constraint, Dependency},
        Archive, Release, RepositoryFile,
    },
    async_compression::{
        codecs::{DecodeV2, EncodeV2, ZstdDecoder, ZstdEncoder},
        core::util::{PartialBuffer, WriteBuffer},
    },
    base64::{engine::general_purpose::STANDARD, write::EncoderWriter, Engine},
    futures::{
        stream::{self, LocalBoxStream},
        StreamExt,
    },
    itertools::Itertools,
    serde::{ser::SerializeStruct, Deserialize, Serialize},
    std::{
        io::{self, Write},
        mem::MaybeUninit,
    },
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
/// Build specification for a repository suite.
pub struct Spec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<Dependency<String>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<Constraint<String>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stage: Vec<String>,

    #[serde(
        default,
        rename = "build-env",
        skip_serializing_if = "KVList::is_empty"
    )]
    pub build_env: KVList<String>,

    #[serde(
        default,
        rename = "build-script",
        skip_serializing_if = "Option::is_none"
    )]
    pub build_script: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub meta: Vec<String>,
}

impl Spec {
    pub fn new() -> Self {
        Self {
            extends: None,
            include: Vec::new(),
            exclude: Vec::new(),
            stage: Vec::new(),
            build_env: KVList::new(),
            meta: Vec::new(),
            build_script: None,
        }
    }
    pub fn locked_spec(&self) -> LockedSpec {
        LockedSpec {
            hash: None,
            installables: None,
        }
    }
}

pub(crate) const META_VALUE_MAX_BYTES: usize = 1024;

pub(crate) fn validate_meta_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let first = chars
        .next()
        .ok_or_else(|| "meta name is empty".to_string())?;
    if !first.is_ascii_alphabetic() {
        return Err("meta name must start with an ASCII letter".to_string());
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(
            "meta name may only contain ASCII alphanumerics, '_', '-', and '.'".to_string(),
        );
    }
    Ok(())
}

pub(crate) fn validate_meta_value(value: &str) -> Result<(), String> {
    if value.len() > META_VALUE_MAX_BYTES {
        return Err(format!("meta value exceeds {} bytes", META_VALUE_MAX_BYTES));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err("meta value contains non-printable characters".to_string());
    }
    Ok(())
}

pub(crate) fn parse_meta_entry(entry: &str) -> Result<(&str, &str), String> {
    let (name, value) = entry
        .split_once(':')
        .ok_or_else(|| "meta entry must be in \"name:value\" form".to_string())?;
    validate_meta_name(name)?;
    validate_meta_value(value)?;
    Ok((name, value))
}

#[derive(Clone)]
/// Locked suite metadata with resolved sources.
pub struct LockedSuite {
    pub path: String,
    pub file: IndexFile,
    pub rel: Release,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Locked archive metadata within a suite.
pub struct LockedArchive {
    pub suites: Vec<LockedSuite>,
}

impl LockedArchive {
    pub(crate) fn fetch_update<'a, C: ContentProvider>(
        locked: &'a Option<Self>,
        archive: &'a Archive,
        archive_idx: usize,
        skip_verify: bool,
        cache: &'a C,
    ) -> LocalBoxStream<'a, io::Result<(usize, usize, Option<LockedSuite>)>> {
        tracing::debug!(
            "Refreshing locked archive for {} {}",
            archive.url,
            archive.suites.iter().join(" "),
        );
        stream::iter(archive.suites.iter().enumerate())
            .then(move |(suite_idx, suite)| async move {
                tracing::debug!("Refreshing locked archive for {} {}", archive.url, suite);
                let path = archive.release_path(suite);
                let file = cache.fetch_release_file(&archive.file_url(&path)).await?;
                let rel = archive.release_from_file(file.clone(), skip_verify).await?;
                match locked.as_ref().and_then(|l| l.suites.get(suite_idx)) {
                    Some(suite) => {
                        if suite.path == path && suite.rel.as_bytes().eq(rel.as_bytes()) {
                            Ok((archive_idx, suite_idx, None))
                        } else {
                            Ok((
                                archive_idx,
                                suite_idx,
                                Some(LockedSuite { path, file, rel }),
                            ))
                        }
                    }
                    None => Ok((
                        archive_idx,
                        suite_idx,
                        Some(LockedSuite { path, file, rel }),
                    )),
                }
            })
            .boxed_local()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
/// Locked package entry with resolved version and hash.
pub struct LockedPackage {
    pub orig: Option<u32>,
    pub idx: u32,
    pub name: String,
    pub order: u32,
    #[serde(flatten)]
    pub file: RepositoryFile,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
/// Locked spec with resolved suites and packages.
pub struct LockedSpec {
    #[serde(with = "crate::hash::serde::sri::opt")]
    pub hash: Option<Hash>,
    pub installables: Option<Vec<LockedPackage>>,
}

impl LockedSpec {
    pub fn is_locked(&self) -> bool {
        self.hash.is_some() && self.installables.is_some()
    }
    pub fn as_locked(&self) -> Option<&'_ Self> {
        self.is_locked().then_some(self)
    }
    pub fn invalidate_solution(&mut self) {
        self.hash = None;
        self.installables = None;
    }
    pub fn installables(&self) -> impl Iterator<Item = &LockedPackage> {
        self.installables.iter().flat_map(|v| v.iter())
    }
}

impl serde::ser::Serialize for LockedSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut struc = serializer.serialize_struct("LockedSuite", 2)?;
        struc.serialize_field("path", self.path.as_str())?;
        let mut comp = ZstdEncoder::new(9);
        let mut buf = vec![MaybeUninit::<u8>::uninit(); 8 * 1024];
        let mut inp = PartialBuffer::new(self.file.as_bytes());
        let mut out = WriteBuffer::new_uninitialized(&mut buf);
        struct LineWrapWriter {
            out: Vec<u8>,
            col: usize,
            width: usize,
        }
        impl LineWrapWriter {
            fn new(width: usize, capacity: usize) -> Self {
                Self {
                    out: Vec::with_capacity(capacity),
                    col: 0,
                    width,
                }
            }
            fn into_string(mut self) -> String {
                if self.col == 0 && self.out.ends_with(b"\n") {
                    self.out.pop();
                }
                // SAFETY: base64 and newlines are valid UTF-8
                unsafe { String::from_utf8_unchecked(self.out) }
            }
        }
        impl Write for LineWrapWriter {
            fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
                let s = buf.len();
                while !buf.is_empty() {
                    let to_write = std::cmp::min(buf.len(), self.width - self.col);
                    if to_write == 0 {
                        self.out.push(b'\n');
                        self.col = 0;
                    } else {
                        let (line, rest) = buf.split_at(to_write);
                        self.out.extend_from_slice(line);
                        self.col += to_write;
                        buf = rest;
                    }
                }
                Ok(s)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut enc = EncoderWriter::new(LineWrapWriter::new(80, self.file.len()), &STANDARD);
        loop {
            let done = inp.written_len() == self.file.len();
            if !done {
                comp.encode(&mut inp, &mut out)
                    .map_err(serde::ser::Error::custom)?;
                enc.write_all(out.written())
                    .map_err(serde::ser::Error::custom)?;
                out.reset();
            } else if comp.finish(&mut out).map_err(serde::ser::Error::custom)? {
                enc.write_all(out.written())
                    .map_err(serde::ser::Error::custom)?;
                break;
            } else {
                enc.write_all(out.written())
                    .map_err(serde::ser::Error::custom)?;
                out.reset();
            }
        }
        let wrapped = enc
            .finish()
            .map_err(serde::ser::Error::custom)?
            .into_string();
        struc.serialize_field("text", wrapped.as_str())?;
        struc.end()
    }
}

impl<'de> serde::de::Deserialize<'de> for LockedSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EncodedReleaseFile {
            path: String,
            text: String,
        }

        let encoded = EncodedReleaseFile::deserialize(deserializer)?;
        let normalized: String = encoded.text.split_whitespace().collect();
        let compressed = STANDARD
            .decode(normalized.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let mut dec = ZstdDecoder::new();
        let mut inp = PartialBuffer::new(compressed.as_slice());
        let mut buf = vec![MaybeUninit::<u8>::uninit(); 8 * 1024];
        let mut out = WriteBuffer::new_uninitialized(&mut buf);
        let mut decoded = Vec::new();
        loop {
            let done = inp.written_len() == compressed.len();
            if !done {
                dec.decode(&mut inp, &mut out)
                    .map_err(serde::de::Error::custom)?;
                decoded.extend_from_slice(out.written());
                out.reset();
            } else if dec.finish(&mut out).map_err(serde::de::Error::custom)? {
                decoded.extend_from_slice(out.written());
                break;
            } else {
                decoded.extend_from_slice(out.written());
                out.reset();
            }
        }
        let file =
            IndexFile::from_string(String::from_utf8(decoded).map_err(serde::de::Error::custom)?);
        let rel = Release::new(file.clear_text()).map_err(serde::de::Error::custom)?;
        Ok(Self {
            path: encoded.path,
            file,
            rel,
        })
    }
}
