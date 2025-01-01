use {
    crate::{
        control::{ControlField, ControlParser},
        error::{Error, Result},
        version::{
            Dependency, ParseError, ParsedDependencyIterator, ParsedProvidedNameIterator,
            ParsedConstraintIterator, ProvidedName, Constraint, Version,
        },
    },
    async_std::io::Read,
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
    pub fn multi_arch(&self) -> MultiArch {
        self.multi_arch
    }
    pub fn essential_or_required(&self) -> bool {
        self.essential || self.priority == Priority::Required
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
    pub fn field(&self, name: &str) -> Option<&'a str> {
        ControlParser::new(self.src)
            .map(|f| f.unwrap())
            .find(|f| f.is_a(name))
            .map(|f| f.value())
    }
    pub fn fields(&self) -> impl Iterator<Item = ControlField<'a>> {
        ControlParser::new(self.src).map(|f| f.unwrap())
    }
    pub fn try_parse_from(parser: &mut ControlParser<'a>) -> Result<Option<Package<'a>>> {
        let mut parsed = false;
        let snap = unsafe { parser.snap() };
        let mut package = parser.try_fold(
            Package::<'a>::default(),
            |mut pkg, field: Result<ControlField<'a>>| -> Result<Package<'a>> {
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
                Err(Error::FieldNotFound("Package"))
            } else if package.arch.is_empty() {
                Err(Error::FieldNotFound("Architecture"))
            } else if package.version.is_empty() {
                Err(Error::FieldNotFound("Version"))
            } else {
                package.src = unsafe { snap.into_slice(parser) };
                Ok(Some(package))
            }
        }
    }
}

pub struct Packages {
    inner: PackagesInner,
}

impl Packages {
    pub fn get(&self, index: usize) -> Option<&Package<'_>> {
        self.inner.with_packages(|packages| packages.get(index))
    }
    pub fn package_by_name(&self, name: &str) -> Option<&Package<'_>> {
        self.inner
            .with_packages(|packages| packages.iter().find(|package| package.name() == name))
    }
    pub fn packages(&self) -> impl Iterator<Item = &Package<'_>> {
        self.inner.with_packages(|packages| packages.iter())
    }
    pub async fn read<R: Read + Unpin>(r: &mut R) -> Result<Self> {
        use async_std::io::ReadExt;
        let mut buf = String::new();
        r.read_to_string(&mut buf).await?;
        Self::try_from(buf)
    }
}

impl TryFrom<Vec<u8>> for Packages {
    type Error = Error;
    fn try_from(inp: Vec<u8>) -> Result<Self> {
        Self::try_from(String::from_utf8(inp).map_err(|err| err.utf8_error())?)
    }
}

impl TryFrom<String> for Packages {
    type Error = Error;
    fn try_from(inp: String) -> Result<Self> {
        Ok(Packages {
            inner: PackagesInnerTryBuilder {
                data: inp.into_boxed_str(),
                packages_builder: |data: &'_ Box<str>| -> Result<Vec<Package<'_>>> {
                    let mut parser = ControlParser::new(&data);
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
}

#[self_referencing]
struct PackagesInner {
    data: Box<str>,
    #[borrows(data)]
    #[covariant]
    packages: Vec<Package<'this>>,
}
