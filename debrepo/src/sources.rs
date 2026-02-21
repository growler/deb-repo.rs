use {
    crate::{
        control::{
            ControlField, ControlParser, ControlStanza, Field, MutableControlFile,
            MutableControlStanza, ParseError,
        },
        hash::Hash,
        indexfile::IndexFile,
        parse_size,
        version::{ProvidedName, Version},
        RepositoryFile,
    },
    ouroboros::self_referencing,
    serde::{Deserialize, Serialize},
    smol::io::{AsyncRead, AsyncReadExt},
    std::{io, sync::Arc},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileHash {
    Sha512,
    Sha256,
    Md5,
}
impl FileHash {
    fn name(self) -> &'static str {
        match self {
            FileHash::Sha512 => "SHA512",
            FileHash::Sha256 => "SHA256",
            FileHash::Md5 => "MD5sum",
        }
    }
    fn priority(self) -> u8 {
        match self {
            FileHash::Sha512 => 0,
            FileHash::Sha256 => 1,
            FileHash::Md5 => 2,
        }
    }
}

#[derive(Default, Clone, Debug)]
/// Source package entry parsed from Sources indices.
pub struct Source<'a> {
    src: &'a str,
    name: &'a str,
    binary: &'a str,
    version: &'a str,
    directory: Option<&'a str>,
    files: Option<(&'a str, FileHash)>,
    repo_files: Vec<RepositoryFile>,
}

impl std::fmt::Display for Source<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.name, self.version)
    }
}

impl AsRef<str> for Source<'_> {
    fn as_ref(&self) -> &str {
        self.src
    }
}

impl<'a> Source<'a> {
    pub fn name(&self) -> &'a str {
        self.name
    }
    pub fn binary(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.binary
            .split(',')
            .map(str::trim)
            .filter(|b| !b.is_empty())
    }
    pub fn version(&self) -> &'a str {
        self.version
    }
    pub fn parsed_version(&self) -> Result<Version<&'a str>, ParseError> {
        Version::try_from(self.version)
    }
    pub fn directory(&self) -> Option<&'a str> {
        self.directory
    }
    pub fn hash_field(&self) -> Option<&'static str> {
        self.files.as_ref().map(|(_, hash)| hash.name())
    }
    fn parse_file_list<F: Fn(&str) -> String>(
        dir: &str,
        field: &str,
        hash_field: &'static str,
        make_url: F,
    ) -> Result<Vec<RepositoryFile>, ParseError> {
        let with_sep = dir.ends_with('/');
        field
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|line| {
                let mut parts = line.split_ascii_whitespace();
                let digest = parts.next().ok_or_else(|| {
                    ParseError::from(format!("invalid file entry, missing digest: {}", line))
                })?;
                let size = parts.next().ok_or_else(|| {
                    ParseError::from(format!("invalid file entry, missing size: {}", line))
                })?;
                let path = parts.next().ok_or_else(|| {
                    ParseError::from(format!("invalid file entry, missing path: {}", line))
                })?;
                if parts.next().is_some() {
                    return Err(ParseError::from(format!(
                        "invalid file entry, too many columns: {}",
                        line
                    )));
                }
                let hash = Hash::from_hex(hash_field, digest).map_err(|err| {
                    ParseError::from(format!("invalid {} digest {}: {}", hash_field, digest, err))
                })?;
                let size = parse_size(size.as_bytes())
                    .map_err(|err| ParseError::from(format!("invalid size {}: {}", size, err)))?;
                let mut full_path =
                    String::with_capacity(dir.len() + path.len() + if with_sep { 0 } else { 1 });
                full_path.push_str(dir);
                if !with_sep {
                    full_path.push('/');
                }
                full_path.push_str(path);
                Ok(RepositoryFile {
                    path: make_url(&full_path),
                    size,
                    hash,
                })
            })
            .collect()
    }
    pub(crate) fn repo_files<F: Fn(&str) -> String>(
        &self,
        make_url: F,
    ) -> Result<Vec<RepositoryFile>, ParseError> {
        let dir = self.directory.ok_or_else(|| {
            ParseError::from(format!("Source {} lacks Directory field", self.name))
        })?;
        let (block, hash) = self.files.as_ref().ok_or_else(|| {
            ParseError::from(format!(
                "Source {} lacks Checksums-Sha512, Checksums-Sha256 or Files field",
                self.name
            ))
        })?;
        Self::parse_file_list(dir, block, hash.name(), make_url)
    }
    pub fn control(&self) -> Result<ControlStanza<'a>, ParseError> {
        ControlStanza::parse(self.src)
    }
    pub fn field(&self, name: &str) -> Option<&'a str> {
        ControlParser::new(self.src)
            .map(|f| f.unwrap())
            .find(|f| f.is_a(name))
            .map(|f| f.value())
    }
    pub fn ensure_field(&self, name: &str) -> Result<&'a str, ParseError> {
        self.field(name).ok_or_else(|| {
            ParseError::from(format!(
                "Source {} description lacks field {}",
                &self.name, name
            ))
        })
    }
    pub fn files(&self) -> impl Iterator<Item = &RepositoryFile> {
        self.repo_files.iter()
    }
    pub fn fields(&self) -> impl Iterator<Item = ControlField<'a>> {
        ControlParser::new(self.src).map(|f| f.unwrap())
    }
    pub(crate) fn clone_with_files<F: Fn(&str) -> String>(&self, f: F) -> Result<Self, ParseError> {
        let repo_files = self.repo_files(&f)?;
        Ok(Self {
            repo_files,
            ..self.clone()
        })
    }
    fn try_parse_from(parser: &mut ControlParser<'a>) -> Result<Option<Source<'a>>, ParseError> {
        let mut parsed = false;
        let snap = unsafe { parser.snap() };
        let mut source = Source::<'a>::default();
        let mut best: Option<(&'a str, FileHash)> = None;
        parser.try_fold(
            (),
            |(), field: Result<ControlField<'a>, ParseError>| -> Result<(), ParseError> {
                let field = field?;
                if !parsed {
                    parsed = true;
                }
                if field.is_a("Package") {
                    source.name = field.value().trim();
                } else if field.is_a("Binary") {
                    source.binary = field.value().trim();
                } else if field.is_a("Version") {
                    source.version = field.value().trim();
                } else if field.is_a("Directory") {
                    source.directory = Some(field.value().trim());
                } else if field.is_a("Checksums-Sha512") {
                    let cand = (field.value(), FileHash::Sha512);
                    if best
                        .as_ref()
                        .is_none_or(|(_, h)| cand.1.priority() < h.priority())
                    {
                        best = Some(cand);
                    }
                } else if field.is_a("Checksums-Sha256") {
                    let cand = (field.value(), FileHash::Sha256);
                    if best
                        .as_ref()
                        .is_none_or(|(_, h)| cand.1.priority() < h.priority())
                    {
                        best = Some(cand);
                    }
                } else if field.is_a("Files") {
                    let cand = (field.value(), FileHash::Md5);
                    if best
                        .as_ref()
                        .is_none_or(|(_, h)| cand.1.priority() < h.priority())
                    {
                        best = Some(cand);
                    }
                }
                Ok(())
            },
        )?;
        if !parsed {
            Ok(None)
        } else if source.name.is_empty() {
            Err(ParseError::from("Field Package not found"))
        } else if source.version.is_empty() {
            Err(ParseError::from("Field Version not found"))
        } else {
            source.src = unsafe { snap.into_slice(parser) };
            source.files = best;
            Ok(Some(source))
        }
    }
}

impl<'a> From<&Source<'a>> for MutableControlStanza {
    fn from(stanza: &Source<'a>) -> Self {
        MutableControlStanza::parse(stanza.src).unwrap()
    }
}

/// Collection of source package entries.
pub struct Sources {
    inner: Arc<SourcesInner>,
}

impl Clone for Sources {
    fn clone(&self) -> Self {
        Sources {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Sources {
    pub fn get(&self, index: usize) -> Option<&Source<'_>> {
        self.inner.with_sources(|sources| sources.get(index))
    }
    pub fn len(&self) -> usize {
        self.inner.with_sources(|sources| sources.len())
    }
    pub fn is_empty(&self) -> bool {
        self.inner.with_sources(|sources| sources.is_empty())
    }
    pub fn source_by_name(&self, name: &str) -> Option<&Source<'_>> {
        self.inner
            .with_sources(|sources| sources.iter().find(|src| src.name() == name))
    }
    pub fn archive_id(&self) -> u32 {
        self.inner.with_archive_id(|id| *id)
    }
    pub fn sources(&self) -> impl Iterator<Item = &Source<'_>> {
        self.inner.with_sources(|sources| sources.iter())
    }
    pub fn new(data: IndexFile, archive_id: u32) -> Result<Self, ParseError> {
        Ok(Sources {
            inner: Arc::new(
                SourcesInnerTryBuilder {
                    archive_id,
                    data,
                    sources_builder: |data: &'_ IndexFile| -> Result<Vec<Source<'_>>, ParseError> {
                        let mut parser = ControlParser::new(data.as_str());
                        let mut sources: Vec<Source<'_>> = vec![];
                        while let Some(source) = Source::try_parse_from(&mut parser)? {
                            sources.push(source);
                        }
                        Ok(sources)
                    },
                }
                .try_build()?,
            ),
        })
    }
    pub async fn read<R: AsyncRead + Unpin + Send>(r: &mut R) -> io::Result<Self> {
        let mut buf = String::new();
        r.read_to_string(&mut buf).await?;
        buf.try_into().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Error parsing sources file: {}", err),
            )
        })
    }
}

impl From<&Sources> for MutableControlFile {
    fn from(srcs: &Sources) -> Self {
        srcs.inner
            .with_sources(|srcs| srcs.iter())
            .map(MutableControlStanza::from)
            .collect()
    }
}

impl Serialize for Sources {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.inner.with_data(|d| d.as_str());
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for Sources {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Sources::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for Sources {
    type Error = ParseError;
    fn try_from(inp: &str) -> Result<Self, Self::Error> {
        Self::new(inp.to_owned().into(), 0)
    }
}

impl TryFrom<String> for Sources {
    type Error = ParseError;
    fn try_from(inp: String) -> Result<Self, Self::Error> {
        Self::new(inp.into(), 0)
    }
}

impl TryFrom<Vec<u8>> for Sources {
    type Error = ParseError;
    fn try_from(inp: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(
            String::from_utf8(inp)
                .map_err(|err| ParseError::from(format!("{}", err)))?
                .into(),
            0,
        )
    }
}

#[self_referencing]
struct SourcesInner {
    archive_id: u32,
    data: IndexFile,
    #[borrows(data)]
    #[covariant]
    sources: Vec<Source<'this>>,
}

#[derive(Default, Clone)]
/// Source package universe derived from archives.
pub struct SourceUniverse {
    sources: Vec<Sources>,
}

impl SourceUniverse {
    pub fn new() -> Self {
        Self { sources: vec![] }
    }
    pub fn from_sources(sources: Vec<Sources>) -> Self {
        Self { sources }
    }
    pub fn push(&mut self, sources: Sources) {
        self.sources.push(sources);
    }
    pub fn len(&self) -> usize {
        self.sources.iter().map(|s| s.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.sources.iter().all(|s| s.is_empty())
    }
    pub fn all(&self) -> impl Iterator<Item = &Sources> {
        self.sources.iter()
    }
    pub fn source<'a, 'b>(&'a self, name: &'b str) -> impl Iterator<Item = &'a Source<'a>> + 'a
    where
        'b: 'a,
    {
        self.sources
            .iter()
            .flat_map(move |sources| sources.sources().filter(move |src| src.name() == name))
    }
    pub(crate) fn find<R, N>(&self, name: N) -> Result<Vec<(&'_ Source<'_>, usize)>, ParseError>
    where
        R: AsRef<str>,
        N: AsRef<ProvidedName<R>>,
    {
        let name = name.as_ref();
        let target_name = name.name().as_ref();
        let target_version = name.version().map(|v| v.as_ref().as_ref());

        let mut found = Vec::new();
        for sources in &self.sources {
            for src in sources.sources() {
                if src.name() != target_name && src.binary().all(|b| b != target_name) {
                    continue;
                }
                if let Some(tv) = &target_version {
                    if let Ok(v) = src.parsed_version() {
                        if v != tv {
                            continue;
                        }
                    }
                }
                found.push((src, sources.archive_id() as usize));
            }
        }
        Ok(found)
    }
}

impl<R> AsRef<ProvidedName<R>> for ProvidedName<R> {
    fn as_ref(&self) -> &ProvidedName<R> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_source() -> &'static str {
        "Package: 1oom
Binary: 1oom
Version: 1.11.2-1
Maintainer: Debian Games Team <pkg-games-devel@lists.alioth.debian.org>
Uploaders: Joseph Nahmias <jello@debian.org>
Build-Depends: debhelper-compat (= 13), libsamplerate0-dev, libsdl2-dev, libsdl2-mixer-dev
Architecture: any
Standards-Version: 4.7.2
Format: 3.0 (quilt)
Checksums-Sha512:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 10 1oom_1.11.2-1.dsc
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 20 1oom_1.11.2.orig.tar.gz
Checksums-Sha256:
 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 42 1oom_1.11.2-1.dsc
 2222222222222222222222222222222222222222222222222222222222222222 1337 1oom_1.11.2.orig.tar.gz
Files:
 ffffffffffffffffffffffffffffffff 42 1oom_1.11.2-1.dsc
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1337 1oom_1.11.2.orig.tar.gz
Directory: pool/contrib/1/1oom
Priority: optional
Section: contrib/misc
"
    }

    #[test]
    fn parses_files_prefers_sha512_then_sha256() {
        let sources: Sources = sample_source().try_into().unwrap();
        let src = sources.get(0).unwrap();
        let files = src.repo_files(|s| s.to_string()).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "pool/contrib/1/1oom/1oom_1.11.2-1.dsc");
        assert_eq!(files[0].size, 10);
        assert_eq!(files[1].size, 20);
        assert_eq!(src.hash_field(), Some("SHA512"));
    }

    #[test]
    fn repo_files_join_directory() {
        let sources: Sources = sample_source().try_into().unwrap();
        let src = sources.get(0).unwrap();
        let files = src.repo_files(|s| s.to_string()).unwrap();
        assert_eq!(files[0].path, "pool/contrib/1/1oom/1oom_1.11.2-1.dsc");
    }

    #[test]
    fn universe_returns_first_match() {
        let s1: Sources = sample_source().try_into().unwrap();
        let s2: Sources = Sources::try_from(sample_source()).unwrap();
        let mut uni = SourceUniverse::new();
        uni.push(s1);
        uni.push(s2);
        let entry = uni.source("1oom").next().unwrap();
        assert_eq!(entry.name(), "1oom");
    }

    #[test]
    fn universe_find_matches_any_or_exact() {
        let srcs: Sources = sample_source().try_into().unwrap();
        let uni = SourceUniverse::from_sources(vec![srcs]);

        let any = ProvidedName::Any("1oom");
        assert_eq!(uni.find(&any).unwrap().len(), 1);

        let exact = ProvidedName::Exact("1oom", Version::new("1.11.2-1"));
        assert_eq!(uni.find(&exact).unwrap().len(), 1);

        let wrong = ProvidedName::Exact("1oom", Version::new("9.9.9"));
        assert!(uni.find(&wrong).unwrap().is_empty());
    }

    #[test]
    fn universe_find_collects_all_matches_when_no_version() {
        let s1: Sources = sample_source().try_into().unwrap();
        let s2: Sources = sample_source().try_into().unwrap();
        let uni = SourceUniverse::from_sources(vec![s1, s2]);

        let any = ProvidedName::Any("1oom");
        assert_eq!(uni.find(any).unwrap().len(), 2);
    }
}
