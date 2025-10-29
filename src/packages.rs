use {
    crate::{
        control::{
            ControlField, ControlParser, ControlStanza, Field, FindFields, MutableControlStanza,
            ParseError,
        },
        hash::Hash,
        version::{
            Constraint, Dependency, ParsedConstraintIterator, ParsedDependencyIterator,
            ParsedProvidedNameIterator, ProvidedName, Version,
        },
    },
    futures_lite::io::{AsyncRead, AsyncReadExt},
    ouroboros::self_referencing,
    std::{io, sync::Arc},
};

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

impl<'a> std::fmt::Display for Package<'a> {
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
    inner: PackagesInner,
}

impl Packages {
    pub fn get(&self, index: usize) -> Option<&Package<'_>> {
        self.inner.with_packages(|packages| packages.get(index))
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
    pub(crate) fn new_from_bytes<D>(data: D, prio: Option<u32>) -> Result<Self, ParseError>
    where
        Vec<u8>: From<D>,
    {
        let s = String::from_utf8(data.into())
            .map_err(|err| ParseError::from(format!("Invalid UTF-8: {}", err)))?;
        Self::new(s.into_boxed_str(), prio)
    }
    pub fn new<S>(data: S, prio: Option<u32>) -> Result<Self, ParseError>
    where
        Arc<str>: From<S>,
    {
        Ok(Packages {
            prio: prio.unwrap_or(500),
            inner: PackagesInnerTryBuilder {
                data: Arc::<str>::from(data),
                packages_builder: |data: &'_ Arc<str>| -> Result<Vec<Package<'_>>, ParseError> {
                    let mut parser = ControlParser::new(data.as_ref());
                    let mut packages: Vec<Package<'_>> = vec![];
                    while let Some(package) = Package::try_parse_from(&mut parser)? {
                        packages.push(package)
                    }
                    Ok(packages)
                },
            }
            .try_build()?,
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

impl TryFrom<&str> for Packages {
    type Error = ParseError;
    fn try_from(inp: &str) -> Result<Self, Self::Error> {
        Self::new(inp.to_owned().into_boxed_str(), None)
    }
}

impl TryFrom<String> for Packages {
    type Error = ParseError;
    fn try_from(inp: String) -> Result<Self, Self::Error> {
        Self::new(inp.into_boxed_str(), None)
    }
}

impl TryFrom<Vec<u8>> for Packages {
    type Error = ParseError;
    fn try_from(inp: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(
            String::from_utf8(inp)
                .map_err(|err| ParseError::from(format!("{}", err)))?
                .into_boxed_str(),
            None,
        )
    }
}

#[self_referencing]
struct PackagesInner {
    data: Arc<str>,
    #[borrows(data)]
    #[covariant]
    packages: Vec<Package<'this>>,
}
