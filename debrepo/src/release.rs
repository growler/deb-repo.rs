/// This module provides functionality for handling Debian repository 'Release' files.
///
/// # Examples
///
/// ```ignore
/// let release = Release::try_from(fs::read_to_string("Release").unwrap()).unwrap();
/// println!("{}", release.codename().unwrap());
///
/// let contents_all = release.file("main/Contents-all.gz").unwrap();
/// println!("size: {} digest: {}", contents_all.size, contents_all.digest);
///
/// let package_size = release.packages_file_for("contrib", "amd64", Some(".xz"));
/// println!("size: {}", package_size);
/// ```
use {
    crate::{
        control::{ControlStanza, ParseError},
        hash::Hash,
        indexfile::IndexFile,
        parse_size,
    },
    chrono::{DateTime, Utc},
    itertools::Itertools,
    ouroboros::self_referencing,
    smallvec::SmallVec,
};

pub struct Release {
    inner: ReleaseInner,
}

impl Clone for Release {
    fn clone(&self) -> Self {
        Release {
            inner: ReleaseInnerTryBuilder {
                data: self.inner.with_data(|d| d.clone()),
                #[allow(clippy::borrowed_box)]
                control_builder: |data: &'_ IndexFile| {
                    ControlStanza::parse(data).map_err(|err| {
                        ParseError::from(format!("error parsing release file: {}", err))
                    })
                },
            }
            .try_build()
            .expect("failed to clone release file"),
        }
    }
}

impl Release {
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.with_data(|d| d.as_bytes())
    }
    pub fn len(&self) -> usize {
        self.inner.with_data(|d| d.len())
    }
    pub fn is_empty(&self) -> bool {
        self.inner.with_data(|d| d.is_empty())
    }
    fn files<'a, S: AsRef<str>>(
        &'a self,
        components: &'a [S],
        hash_name: &'a str,
    ) -> Result<impl Iterator<Item = Result<(&'a str, &'a str, u64), ParseError>>, ParseError> {
        let release_components = self.field("Components").unwrap_or("");
        if components.iter().any(|c| {
            !release_components.split_ascii_whitespace().any(|rc| {
                rc.split('/')
                    .next_back()
                    .map(|s| s == c.as_ref())
                    .unwrap_or(false)
            })
        }) {
            return Err(ParseError::from(format!(
                "Component(s) {} not found in release components: {}",
                components
                    .iter()
                    .map(|s| s.as_ref())
                    .filter(|s| !release_components
                        .split_ascii_whitespace()
                        .any(|rc| rc == *s))
                    .join(", "),
                release_components
            )));
        }
        let field = self.field(hash_name).ok_or_else(|| {
            ParseError::from(format!("Field {} not found in the release file", hash_name,))
        })?;
        Ok(field
            .lines()
            .map(|l| l.trim())
            .filter(|l| l != &"")
            .map(|line| {
                let parts: SmallVec<[&'_ str; 3]> = line.split_ascii_whitespace().collect();
                if let [digest, size, path] = parts[..] {
                    let size = parse_size(size.as_bytes()).map_err(|err| {
                        ParseError::from(format!("invalid size: {:?} {}", size, err))
                    })?;
                    Ok((path, digest, size))
                } else {
                    Err(ParseError::from(format!("Invalid release line: {}", line)))
                }
            }))
    }
    pub fn package_files<'a, S: AsRef<str>>(
        &'a self,
        components: &'a [S],
        hash_name: &'a str,
        arch: &'a str,
    ) -> Result<impl Iterator<Item = Result<(&'a str, Hash, u64), ParseError>>, ParseError> {
        let fetch_all_arch = self
            .field("No-Support-for-Architecture-all")
            .is_none_or(|v| v.trim_ascii() != "Packages");
        let arch = if fetch_all_arch {
            vec!["all", arch]
        } else {
            vec![arch]
        };
        let files = self.files(components, hash_name)?.try_fold(
            arch.iter()
                .flat_map(|arch| {
                    components
                        .iter()
                        .map(move |c| (c.as_ref(), *arch, None::<(&str, Hash, u64)>))
                })
                .collect::<Vec<_>>(),
            move |mut files, file| {
                let (path, digest, size) = file?;
                for (comp, arch, entry) in files.iter_mut() {
                    if let Some(rest) = path.strip_prefix(*comp) {
                        if let Some(rest) = rest.strip_prefix("/binary-") {
                            if let Some(rest) = rest.strip_prefix(*arch) {
                                if let Some("" | ".gz" | ".xz" | ".bz2" | ".zst" | ".zstd") =
                                    rest.strip_prefix("/Packages")
                                {
                                    if size < entry.as_ref().map_or(u64::MAX, |(_, _, size)| *size)
                                    {
                                        let hash =
                                            Hash::from_hex(hash_name, digest).map_err(|err| {
                                                ParseError::from(format!(
                                                    "invalid hash: {} {}",
                                                    digest, err
                                                ))
                                            })?;
                                        *entry = Some((path, hash, size));
                                    }
                                }
                            }
                        }
                    }
                }
                Ok::<_, ParseError>(files)
            },
        )?;
        Ok(files.into_iter().filter_map(|(comp, arch, entry)| {
            if let Some((path, hash, size)) = entry {
                // if entry size is zero (empty Packages file), skip it
                if size == 0 {
                    None
                } else {
                    Some(Ok((path, hash, size)))
                }
            } else if entry.is_none() {
                Some(Err(ParseError::from(format!(
                    "no Packages file found for component {} {}",
                    comp, arch,
                ))))
            } else {
                None
            }
        }))
    }
    pub fn source_files<'a, S: AsRef<str>>(
        &'a self,
        components: &'a [S],
        hash_name: &'a str,
    ) -> Result<impl Iterator<Item = Result<(&'a str, Hash, u64), ParseError>>, ParseError> {
        let files = self.files(components, hash_name)?.try_fold(
            components
                .iter()
                .map(move |c| (c.as_ref(), None::<(&str, Hash, u64)>))
                .collect::<Vec<_>>(),
            move |mut files, file| {
                let (path, digest, size) = file?;
                for (comp, entry) in files.iter_mut() {
                    if let Some(rest) = path.strip_prefix(*comp) {
                        if let Some(rest) = rest.strip_prefix("/source") {
                            if let Some("" | ".gz" | ".xz" | ".bz2" | ".zst" | ".zstd") =
                                rest.strip_prefix("/Sources")
                            {
                                if size < entry.as_ref().map_or(u64::MAX, |(_, _, size)| *size) {
                                    let hash =
                                        Hash::from_hex(hash_name, digest).map_err(|err| {
                                            ParseError::from(format!(
                                                "invalid hash: {} {}",
                                                digest, err
                                            ))
                                        })?;
                                    *entry = Some((path, hash, size));
                                }
                            }
                        }
                    }
                }
                Ok::<_, ParseError>(files)
            },
        )?;
        Ok(files.into_iter().filter_map(|(comp, entry)| {
            if let Some((path, hash, size)) = entry {
                // if entry size is zero (empty Sources file), skip it
                if size == 0 {
                    None
                } else {
                    Some(Ok((path, hash, size)))
                }
            } else if entry.is_none() {
                Some(Err(ParseError::from(format!(
                    "no Sources file found for component {}",
                    comp,
                ))))
            } else {
                None
            }
        }))
    }
    fn field(&self, name: &str) -> Option<&str> {
        self.inner.with_control(|ctrl| ctrl.field(name))
    }
    pub fn codename(&self) -> Option<&str> {
        self.field("Codename")
    }
    pub fn origin(&self) -> Option<&str> {
        self.field("Origin")
    }
    pub fn label(&self) -> Option<&str> {
        self.field("Label")
    }
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.field("Components").map_or_else(
            || "".split_ascii_whitespace(),
            |line| line.split_ascii_whitespace(),
        )
    }
    pub fn architectures(&self) -> impl Iterator<Item = &str> {
        self.field("Architectures").map_or_else(
            || "".split_ascii_whitespace(),
            |line| line.split_ascii_whitespace(),
        )
    }
    pub fn description(&self) -> &str {
        self.field("Description").unwrap_or("")
    }
    pub fn date(&self) -> Option<DateTime<Utc>> {
        self.field("Date")
            .and_then(|date| DateTime::parse_from_rfc2822(date).map(|t| t.to_utc()).ok())
    }
    pub fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.field("Valid-Until")
            .and_then(|date| DateTime::parse_from_rfc2822(date).map(|t| t.to_utc()).ok())
    }
    pub fn new(data: IndexFile) -> Result<Release, ParseError> {
        Ok(Release {
            inner: ReleaseInnerTryBuilder {
                data,
                #[allow(clippy::borrowed_box)]
                control_builder: |data: &'_ IndexFile| {
                    ControlStanza::parse(data).map_err(|err| {
                        ParseError::from(format!("error parsing release file: {}", err))
                    })
                },
            }
            .try_build()?,
        })
    }
}

impl TryFrom<String> for Release {
    type Error = ParseError;
    fn try_from(str: String) -> Result<Self, Self::Error> {
        Release::new(str.into())
    }
}

impl TryFrom<Box<str>> for Release {
    type Error = ParseError;
    fn try_from(str: Box<str>) -> Result<Self, Self::Error> {
        Release::new(str.into())
    }
}

impl TryFrom<Vec<u8>> for Release {
    type Error = ParseError;
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        Release::new(
            String::from_utf8(vec)
                .map_err(|utf8err| ParseError::from(format!("invalid UTF-8: {}", utf8err)))?
                .into(),
        )
    }
}

#[self_referencing]
struct ReleaseInner {
    data: IndexFile,
    #[borrows(data)]
    #[covariant]
    control: ControlStanza<'this>,
}
