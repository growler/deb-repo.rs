use {
    crate::{
        control::{
            ControlField, ControlParser, ControlStanza, Field, FindFields, MutableControlFile,
            MutableControlStanza, ParseError,
        },
        hash::Hash,
        indexfile::IndexFile,
        version::{
            Constraint, Dependency, ParsedConstraintIterator, ParsedDependencyIterator,
            ParsedProvidedNameIterator, ProvidedName, Version,
        },
        SafeStoreFile,
    },
    futures::AsyncWriteExt,
    ouroboros::self_referencing,
    serde::{Deserialize, Serialize},
    smol::io::{AsyncRead, AsyncReadExt},
    std::{io, sync::Arc},
};

pub struct MemoryMappedUniverseFile {
    mmap: Arc<memmap2::Mmap>,
    begin: usize,
    end: usize,
}

impl AsRef<str> for MemoryMappedUniverseFile {
    fn as_ref(&self) -> &str {
        let slice = &self.mmap[self.begin..self.end];
        // Safety: The mmap is guaranteed to be valid UTF-8 as it was created from a file
        unsafe { std::str::from_utf8_unchecked(slice) }
    }
}
impl MemoryMappedUniverseFile {
    pub async fn store<P: AsRef<std::path::Path>>(
        path: P,
        arch: &str,
        packages: &[Packages],
    ) -> io::Result<()> {
        let count = packages.len() as u32;
        let mut index_off = 4;
        let mut off = index_off + (count as usize) * 12 + 1 + arch.len();
        let mut header = vec![0u8; off];
        header[0..4].copy_from_slice(&count.to_le_bytes());
        for pkg in packages.iter() {
            let begin = off as u32;
            let end = begin + (pkg.inner.with_data(|d| d.as_str().len()) as u32);
            let prio = pkg.prio;
            header[index_off..index_off + 4].copy_from_slice(&begin.to_le_bytes());
            header[index_off + 4..index_off + 8].copy_from_slice(&end.to_le_bytes());
            header[index_off + 8..index_off + 12].copy_from_slice(&prio.to_le_bytes());
            index_off += 12;
            off = end as usize;
        }
        header[index_off] = arch.len() as u8;
        header[index_off + 1..index_off + 1 + arch.len()].copy_from_slice(arch.as_bytes());
        let mut file = SafeStoreFile::new(path).await?;
        file.set_len(off as u64).await?;
        file.as_mut().write_all(&header).await?;
        for pkg in packages.iter() {
            let data = pkg.inner.with_data(|d| d.as_str().as_bytes());
            file.as_mut().write_all(data).await?;
        }
        Ok(())
    }
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> io::Result<(String, Vec<Packages>)> {
        let file = std::fs::File::open(path)?;
        let mmap = Arc::new(unsafe { memmap2::MmapOptions::new().map(&file)? });
        if mmap.len() < 4 {
            return Err(io::Error::other(
                "Universe file is too small to contain header",
            ));
        }
        let count = u32::from_le_bytes([mmap[0], mmap[1], mmap[2], mmap[3]]);
        let mut index_off = 4;
        let mut off = 4 + (count as usize) * 12;
        if mmap.len() < off {
            return Err(io::Error::other(
                "Universe file is too small to contain data",
            ));
        }
        let arch_len = mmap[off] as usize;
        if mmap.len() < off + 1 + arch_len {
            return Err(io::Error::other(
                "Universe file is too small to contain architecture",
            ));
        }
        let arch = std::str::from_utf8(&mmap[off + 1..off + 1 + arch_len])
            .map_err(|err| {
                io::Error::other(format!(
                    "Universe file architecture is not valid UTF-8: {}",
                    err
                ))
            })?
            .to_string();
        off += 1 + arch_len;
        std::str::from_utf8(&mmap[off..]).map_err(|err| {
            io::Error::other(format!("Packages file is not valid UTF-8: {}", err))
        })?;
        let mut files = Vec::with_capacity(count as usize);
        for i in 0..count {
            let begin = u32::from_le_bytes([
                mmap[index_off],
                mmap[index_off + 1],
                mmap[index_off + 2],
                mmap[index_off + 3],
            ]) as usize;
            if begin != off {
                return Err(io::Error::other(format!("Universe file has invalid index ({i}: count={count}, begin={begin}, off={off}, len={}", mmap.len())));
            }
            let end = u32::from_le_bytes([
                mmap[index_off + 4],
                mmap[index_off + 5],
                mmap[index_off + 6],
                mmap[index_off + 7],
            ]) as usize;
            if begin > end || end > mmap.len() {
                return Err(io::Error::other(format!("Universe file has invalid index ({i}: count={count}, begin={begin}, end={end}, len={}", mmap.len())));
            }
            let prio = u32::from_le_bytes([
                mmap[index_off + 8],
                mmap[index_off + 9],
                mmap[index_off + 10],
                mmap[index_off + 11],
            ]);
            off = end;
            files.push(
                Packages::new(
                    IndexFile::mmap_region(Arc::clone(&mmap), begin, end)?,
                    Some(prio),
                )
                .map_err(io::Error::other)?,
            );
            index_off += 12;
        }
        Ok((arch, files))
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum Priority {
    #[default]
    Unknown,
    Optional,
    Standard,
    Important,
    Required,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Priority::Required => write!(f, "required"),
            Priority::Important => write!(f, "important"),
            Priority::Standard => write!(f, "standard"),
            Priority::Optional => write!(f, "optional"),
            Priority::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<&str> for Priority {
    fn from(value: &str) -> Self {
        if value.eq_ignore_ascii_case("required") {
            Priority::Required
        } else if value.eq_ignore_ascii_case("important") {
            Priority::Important
        } else if value.eq_ignore_ascii_case("standard") {
            Priority::Standard
        } else if value.eq_ignore_ascii_case("optional") || value.eq_ignore_ascii_case("extra") {
            Priority::Optional
        } else {
            Priority::Unknown
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPriority {
    Essential,
    Required,
    Other,
}

impl InstallPriority {
    pub fn rank(&self) -> u8 {
        match self {
            InstallPriority::Essential => 0,
            InstallPriority::Required => 1,
            InstallPriority::Other => 2,
        }
    }
}

impl AsRef<str> for InstallPriority {
    fn as_ref(&self) -> &str {
        match self {
            InstallPriority::Essential => "essential",
            InstallPriority::Required => "required",
            InstallPriority::Other => "other",
        }
    }
}

impl std::fmt::Display for InstallPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            InstallPriority::Essential => write!(f, "essential"),
            InstallPriority::Required => write!(f, "required"),
            InstallPriority::Other => write!(f, "other"),
        }
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiArch {
    #[default]
    Same,
    Foreign,
    Allowed,
}

impl From<&str> for MultiArch {
    fn from(value: &str) -> Self {
        if value.eq_ignore_ascii_case("foreign") {
            Self::Foreign
        } else if value.eq_ignore_ascii_case("allowed") {
            Self::Allowed
        } else {
            Self::Same
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct Package<'a> {
    src: &'a str,
    name: &'a str,
    version: &'a str,
    arch: &'a str,
    provides: Option<&'a str>,
    depends: Option<&'a str>,
    pre_depends: Option<&'a str>,
    conflicts: Option<&'a str>,
    breaks: Option<&'a str>,
    essential: bool,
    priority: Priority,
    multi_arch: MultiArch,
}

impl std::fmt::Display for Package<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}={}", self.name, self.arch, self.version)
    }
}

impl<'a> Package<'a> {
    pub fn repo_file(&self, hash_field_name: &'static str) -> io::Result<(&'a str, u64, Hash)> {
        let (path, size, digest) = self
            .fields()
            .find_fields(("Filename", "Size", hash_field_name))
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("package {} lacks field {}", self, err),
                )
            })?;
        Ok((
            path,
            crate::parse_size(size.as_bytes())?,
            Hash::from_hex(hash_field_name, digest)?,
        ))
    }
    pub fn src(&self) -> &'a str {
        self.src
    }
    pub fn name(&self) -> &'a str {
        self.name
    }
    pub fn arch(&self) -> &'a str {
        self.arch
    }
    pub fn raw_full_name(&self) -> ProvidedName<&'a str> {
        ProvidedName::Exact(self.name, Version::new(self.version))
    }
    pub fn full_name(&self) -> std::result::Result<ProvidedName<&'a str>, ParseError> {
        Ok(ProvidedName::Exact(
            self.name,
            Version::try_from(self.version)?,
        ))
    }
    pub fn provides(
        &self,
    ) -> impl Iterator<Item = std::result::Result<ProvidedName<&'a str>, ParseError>> {
        ParsedProvidedNameIterator::new(self.provides.unwrap_or(""))
    }
    pub fn provides_name(&self, name: &str) -> bool {
        self.name == name
            || self.provides.is_some_and(|provides| {
                ParsedProvidedNameIterator::new(provides)
                    .filter_map(|n| n.ok())
                    .any(|pv| *pv.name() == name)
            })
    }
    pub fn essential(&self) -> bool {
        self.essential
    }
    pub fn priority(&self) -> Priority {
        self.priority
    }
    pub fn required(&self) -> bool {
        self.priority == Priority::Required
    }
    pub fn install_priority(&self) -> InstallPriority {
        if self.essential {
            InstallPriority::Essential
        } else if self.priority == Priority::Required {
            InstallPriority::Required
        } else {
            InstallPriority::Other
        }
    }
    pub fn multi_arch(&self) -> MultiArch {
        self.multi_arch
    }
    pub fn architecture(&self) -> &'a str {
        self.arch
    }
    pub fn raw_version(&self) -> Version<&'a str> {
        Version::new(self.version)
    }
    pub fn version(&self) -> std::result::Result<Version<&'a str>, ParseError> {
        Version::try_from(self.version)
    }
    pub fn depends(
        &self,
    ) -> impl Iterator<Item = std::result::Result<Dependency<&'a str>, ParseError>> {
        ParsedDependencyIterator::new(self.depends.unwrap_or(""))
    }
    pub fn pre_depends(
        &self,
    ) -> impl Iterator<Item = std::result::Result<Dependency<&'a str>, ParseError>> {
        ParsedDependencyIterator::new(self.pre_depends.unwrap_or(""))
    }
    pub fn breaks(
        &self,
    ) -> impl Iterator<Item = std::result::Result<Constraint<&'a str>, ParseError>> {
        ParsedConstraintIterator::new(self.breaks.unwrap_or(""), false)
    }
    pub fn conflicts(
        &self,
    ) -> impl Iterator<Item = std::result::Result<Constraint<&'a str>, ParseError>> {
        ParsedConstraintIterator::new(self.conflicts.unwrap_or(""), false)
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
        ControlParser::new(self.src)
            .map(|f| f.unwrap())
            .find(|f| f.is_a(name))
            .map(|f| f.value())
            .ok_or_else(|| {
                ParseError::from(format!(
                    "Package {} description lacks field {}",
                    &self, name
                ))
            })
    }
    pub fn fields(&self) -> impl Iterator<Item = ControlField<'a>> {
        ControlParser::new(self.src).map(|f| f.unwrap())
    }
    pub fn try_parse_from(
        parser: &mut ControlParser<'a>,
    ) -> Result<Option<Package<'a>>, ParseError> {
        let mut parsed = false;
        let snap = unsafe { parser.snap() };
        let mut package = parser.try_fold(
            Package::<'a>::default(),
            |mut pkg,
             field: Result<ControlField<'a>, ParseError>|
             -> Result<Package<'a>, ParseError> {
                let field = field?;
                if !parsed {
                    parsed = true;
                }
                if field.is_a("Package") {
                    pkg.name = field.value().trim();
                } else if field.is_a("Architecture") {
                    pkg.arch = field.value().trim();
                } else if field.is_a("Version") {
                    pkg.version = field.value().trim();
                } else if field.is_a("Provides") {
                    pkg.provides.replace(field.value());
                } else if field.is_a("Depends") {
                    pkg.depends.replace(field.value());
                } else if field.is_a("Pre-Depends") {
                    pkg.pre_depends.replace(field.value());
                } else if field.is_a("Conflicts") {
                    pkg.conflicts.replace(field.value());
                } else if field.is_a("Breaks") {
                    pkg.breaks.replace(field.value());
                } else if field.is_a("Essential") {
                    if field.value().eq_ignore_ascii_case("yes") {
                        pkg.essential = true;
                    }
                } else if field.is_a("Priority") {
                    pkg.priority = Priority::from(field.value());
                } else if field.is_a("Multi-Arch") {
                    pkg.multi_arch = MultiArch::from(field.value());
                }
                Ok(pkg)
            },
        )?;
        if !parsed {
            Ok(None)
        } else if package.name.is_empty() {
            Err(ParseError::from("Field Package not found"))
        } else if package.arch.is_empty() {
            Err(ParseError::from("Field Architecture not found"))
        } else if package.version.is_empty() {
            Err(ParseError::from("Field Version not found"))
        } else {
            package.src = unsafe { snap.into_slice(parser) };
            Ok(Some(package))
        }
    }
}

impl<'a> From<&Package<'a>> for MutableControlStanza {
    fn from(stanza: &Package<'a>) -> Self {
        MutableControlStanza::parse(stanza.src).unwrap()
    }
}

pub struct Packages {
    prio: u32,
    inner: Arc<PackagesInner>,
}

impl Clone for Packages {
    fn clone(&self) -> Self {
        Packages {
            prio: self.prio,
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Packages {
    pub fn get(&self, index: usize) -> Option<&Package<'_>> {
        self.inner.with_packages(|packages| packages.get(index))
    }
    pub fn len(&self) -> usize {
        self.inner.with_packages(|packages| packages.len())
    }
    pub fn repo_file(
        &self,
        index: usize,
        hash_field_name: &'static str,
    ) -> io::Result<(&str, u64, Hash)> {
        self.get(index)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("package index {} is out of range", index),
                )
            })
            .and_then(|p| p.repo_file(hash_field_name))
    }
    pub fn src(&self) -> &str {
        self.inner.with_data(|d| d.as_str())
    }
    pub fn package_by_name(&self, name: &str) -> Option<&Package<'_>> {
        self.inner
            .with_packages(|packages| packages.iter().find(|package| package.name() == name))
    }
    pub fn packages(&self) -> impl Iterator<Item = &Package<'_>> {
        self.inner.with_packages(|packages| packages.iter())
    }
    pub fn prio(&self) -> u32 {
        self.prio
    }
    pub fn with_prio(self, prio: u32) -> Self {
        Self {
            prio,
            inner: self.inner,
        }
    }
    pub fn new(data: IndexFile, prio: Option<u32>) -> Result<Self, ParseError> {
        Ok(Packages {
            prio: prio.unwrap_or(500),
            inner: Arc::new(
                PackagesInnerTryBuilder {
                    data,
                    packages_builder:
                        |data: &'_ IndexFile| -> Result<Vec<Package<'_>>, ParseError> {
                            let mut parser = ControlParser::new(data.as_str());
                            let mut packages: Vec<Package<'_>> = vec![];
                            while let Some(package) = Package::try_parse_from(&mut parser)? {
                                packages.push(package)
                            }
                            Ok(packages)
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
                format!("Error parsing packages file: {}", err),
            )
        })
    }
}

impl From<&Packages> for MutableControlFile {
    fn from(pkgs: &Packages) -> Self {
        pkgs.inner
            .with_packages(|pkgs| pkgs.iter())
            .map(|pkg| MutableControlStanza::from(pkg))
            .collect()
    }
}

impl Serialize for Packages {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.inner.with_data(|d| d.as_str());
        serializer.serialize_str(s)
    }
}
impl<'de> Deserialize<'de> for Packages {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Packages::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for Packages {
    type Error = ParseError;
    fn try_from(inp: &str) -> Result<Self, Self::Error> {
        Self::new(inp.to_owned().into(), None)
    }
}

impl TryFrom<String> for Packages {
    type Error = ParseError;
    fn try_from(inp: String) -> Result<Self, Self::Error> {
        Self::new(inp.into(), None)
    }
}

impl TryFrom<Vec<u8>> for Packages {
    type Error = ParseError;
    fn try_from(inp: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(
            String::from_utf8(inp)
                .map_err(|err| ParseError::from(format!("{}", err)))?
                .into(),
            None,
        )
    }
}

#[self_referencing]
struct PackagesInner {
    data: IndexFile,
    #[borrows(data)]
    #[covariant]
    packages: Vec<Package<'this>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;
    assert_impl_all!(MutableControlStanza: Send, Sync);
}
