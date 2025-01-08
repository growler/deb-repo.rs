use {
    crate::{
        control::{ControlField, ControlParser, ControlStanza, ParseError, MutableControlStanza},
        digest::{Digest, Sha256},
        repo::{DebRepo, VerifyingDebReader},
        version::{
            Constraint, Dependency, ParsedConstraintIterator, ParsedDependencyIterator,
            ParsedProvidedNameIterator, ProvidedName, Version,
        },
    },
    async_std::io::{self, Read},
    ouroboros::self_referencing,
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
    path: Option<&'a str>,
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
    pub fn repo_file(&self) -> io::Result<(&'a str, usize, Sha256)> {
        let (path, size, sha256) = self
            .fields()
            .find_fields(("Filename", "Size", "SHA256"))
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("package {} lacks field {}", self, err),
                )
            })?;
        Ok((
            path,
            crate::parse_size(size.as_bytes())?,
            Digest::<sha2::Sha256>::try_from(sha256)?,
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
    pub fn full_name(&self) -> ProvidedName<&'a str, Version<&'a str>> {
        ProvidedName::Exact(self.name, Version::from(self.version))
    }
    pub fn provides(
        &self,
    ) -> impl Iterator<Item = std::result::Result<ProvidedName<&'a str, Version<&'a str>>, ParseError>>
    {
        ParsedProvidedNameIterator::new(self.provides.unwrap_or(""))
    }
    pub fn provides_name(&self, name: &str) -> bool {
        self.name == name
            || self.provides.map_or(false, |provides| {
                ParsedProvidedNameIterator::new(provides)
                    .filter_map(|n| n.ok())
                    .find(|pv| *pv.name() == name)
                    .is_some()
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
    pub fn multi_arch(&self) -> MultiArch {
        self.multi_arch
    }
    pub fn architecture(&self) -> &'a str {
        self.arch
    }
    pub fn version(&self) -> Version<&'a str> {
        Version::from(self.version)
    }
    pub fn depends(
        &self,
    ) -> impl Iterator<
        Item = std::result::Result<
            Dependency<Option<&'a str>, &'a str, Version<&'a str>>,
            ParseError,
        >,
    > {
        ParsedDependencyIterator::new(self.depends.unwrap_or(""))
    }
    pub fn pre_depends(
        &self,
    ) -> impl Iterator<
        Item = std::result::Result<
            Dependency<Option<&'a str>, &'a str, Version<&'a str>>,
            ParseError,
        >,
    > {
        ParsedDependencyIterator::new(self.pre_depends.unwrap_or(""))
    }
    pub fn breaks(
        &self,
    ) -> impl Iterator<
        Item = std::result::Result<
            Constraint<Option<&'a str>, &'a str, Version<&'a str>>,
            ParseError,
        >,
    > {
        ParsedConstraintIterator::new(self.breaks.unwrap_or(""), false)
    }
    pub fn conflicts(
        &self,
    ) -> impl Iterator<
        Item = std::result::Result<
            Constraint<Option<&'a str>, &'a str, Version<&'a str>>,
            ParseError,
        >,
    > {
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
            .ok_or_else(|| ParseError::from(format!("Package {} description lacks field {}", &self, name)))
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
                } else if field.is_a("Filename") {
                    pkg.path.replace(field.value());
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
        } else {
            if package.name.is_empty() {
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
}

impl<'a> From<&Package<'a>> for MutableControlStanza {
    fn from(stanza: &Package<'a>) -> Self {
        MutableControlStanza::parse(stanza.src).unwrap()
    }
}

pub struct Packages<S>
where
    S: AsRef<str> + 'static,
{
    pub(crate) repo: DebRepo,
    inner: PackagesInner<S>,
}

impl<S: AsRef<str> + 'static> Packages<S> {
    pub fn get(&self, index: usize) -> Option<&Package<'_>> {
        self.inner.with_packages(|packages| packages.get(index))
    }
    pub async fn get_deb_reader(&self, index: usize) -> io::Result<VerifyingDebReader> {
        let (path, size, hash) = self
            .get(index)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("package index {} is out of range", index),
                )
            })
            .and_then(|p| p.repo_file())?;
        self.repo.verifying_deb_reader(path, size, hash).await
    }
    pub fn package_by_name(&self, name: &str) -> Option<&Package<'_>> {
        self.inner
            .with_packages(|packages| packages.iter().find(|package| package.name() == name))
    }
    pub fn packages(&self) -> impl Iterator<Item = &Package<'_>> {
        self.inner.with_packages(|packages| packages.iter())
    }
    pub fn new(repo: DebRepo, data: S) -> Result<Self, ParseError> {
        Ok(Packages {
            repo,
            inner: PackagesInnerTryBuilder {
                data,
                packages_builder: |data: &'_ S| -> Result<Vec<Package<'_>>, ParseError> {
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
    pub(crate) fn new_test(data: S) -> Result<Self, ParseError> {
        Self::new(crate::repo::null_provider(), data)
    }
}

impl Packages<Box<str>> {
    pub async fn read<R: Read + Unpin>(r: &mut R) -> io::Result<Self> {
        use async_std::io::ReadExt;
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

impl TryFrom<&str> for Packages<Box<str>> {
    type Error = ParseError;
    fn try_from(inp: &str) -> Result<Self, Self::Error> {
        Self::new_test(inp.to_owned().into_boxed_str())
    }
}

impl TryFrom<String> for Packages<Box<str>> {
    type Error = ParseError;
    fn try_from(inp: String) -> Result<Self, Self::Error> {
        Self::new_test(inp.into_boxed_str())
    }
}

impl TryFrom<Vec<u8>> for Packages<Box<str>> {
    type Error = ParseError;
    fn try_from(inp: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new_test(
            String::from_utf8(inp)
                .map_err(|err| ParseError::from(format!("{}", err)))?
                .into_boxed_str(),
        )
    }
}

#[self_referencing]
struct PackagesInner<S>
where
    S: AsRef<str> + 'static,
{
    data: S,
    #[borrows(data)]
    #[covariant]
    packages: Vec<Package<'this>>,
}

trait FindFields<M, R, E> {
    fn find_fields(self, matches: M) -> std::result::Result<R, E>;
}

impl<'a, I> FindFields<&'a str, &'a str, &'a str> for I
where
    I: Iterator<Item = ControlField<'a>>,
{
    fn find_fields(self, m: &'a str) -> std::result::Result<&'a str, &'a str> {
        self.fold(None, |found, field| {
            if field.is_a(m) {
                Some(field.value())
            } else {
                found
            }
        })
        .ok_or(m)
    }
}
impl<'a, I> FindFields<(&'a str, &'a str), (&'a str, &'a str), &'a str> for I
where
    I: Iterator<Item = ControlField<'a>>,
{
    fn find_fields(
        self,
        m: (&'a str, &'a str),
    ) -> std::result::Result<(&'a str, &'a str), &'a str> {
        let r = self.fold((None, None), |found, field| {
            if field.is_a(m.0) {
                (Some(field.value()), found.1)
            } else if field.is_a(m.1) {
                (found.0, Some(field.value()))
            } else {
                found
            }
        });
        Ok((r.0.ok_or(m.0)?, r.1.ok_or(m.1)?))
    }
}
impl<'a, I> FindFields<(&'a str, &'a str, &'a str), (&'a str, &'a str, &'a str), &'a str> for I
where
    I: Iterator<Item = ControlField<'a>>,
{
    fn find_fields(
        self,
        m: (&'a str, &'a str, &'a str),
    ) -> std::result::Result<(&'a str, &'a str, &'a str), &'a str> {
        let r = self.fold((None, None, None), |found, field| {
            if field.is_a(m.0) {
                (Some(field.value()), found.1, found.2)
            } else if field.is_a(m.1) {
                (found.0, Some(field.value()), found.2)
            } else if field.is_a(m.2) {
                (found.0, found.1, Some(field.value()))
            } else {
                found
            }
        });
        Ok((r.0.ok_or(m.0)?, r.1.ok_or(m.1)?, r.2.ok_or(m.2)?))
    }
}
