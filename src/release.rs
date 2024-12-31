/// This module provides functionality for handling Debian repository 'Release' files.
/// 
/// # Examples
///
/// ```
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
        control::ControlStanza,
        digest::Digest,
        error::{Error, Result},
        parse_size,
    },
    chrono::{DateTime, Utc},
    ouroboros::self_referencing,
};

pub struct Release {
    inner: ReleaseInner,
}

macro_rules! matches {
    ($input:expr, [ * ]) => {  true };
    ($input:expr, [ $component:tt ]) => { $input == $component };
    ($input:expr, [ $component:tt $($rest:tt)* ]) => {
        if let Some(rest) = $input.strip_prefix($component) {
           matches!(rest, [$($rest)*])
        } else {
            false
        }
    };
}

impl Release {
    pub fn file(&self, path: &str) -> Option<&ReleaseFile<'_>> {
        self.inner.with_files(|files| {
            files.iter().find(|file| file.path == path)
        })
    }
    pub fn packages_file_for(
        &self,
        component: &str,
        arch: &str,
        ext: Option<&str>,
    ) -> Option<&ReleaseFile<'_>> {
        self.inner.with_files(|files| {
            files.iter().find(|file| matches!(file.path, [ component "/binary-" arch "/Packages" (ext.unwrap_or("")) ]))
        })
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
        self.field("Componments").map_or_else(
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
        self.field("Date").and_then(|date| {
            DateTime::parse_from_rfc2822(date).map(|t| t.to_utc()).ok()
        })
    }
    pub fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.field("Valid-Until").and_then(|date| {
            DateTime::parse_from_rfc2822(date).map(|t| t.to_utc()).ok()
        })
    }
}

pub struct ReleaseFile<'a> {
    path: &'a str,
    digest: Digest<sha2::Sha256>,
    size: usize,
}

impl<'a> ReleaseFile<'a> {
    pub fn path(&self) -> &'a str {
        self.path
    }
    pub fn digest(&self) -> &Digest<sha2::Sha256> {
        &self.digest
    }
    pub fn size(&self) -> usize {
        self.size
    }
}

impl<'a> Eq for ReleaseFile<'a> {}
impl<'a> PartialEq for ReleaseFile<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl<'a> PartialOrd for ReleaseFile<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.path.cmp(other.path))
    }
}

impl<'a> Ord for ReleaseFile<'a> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path.cmp(other.path)
    }
}

impl TryFrom<Vec<u8>> for Release {
    type Error = Error;
    fn try_from(inp: Vec<u8>) -> Result<Self> {
        Self::try_from(String::from_utf8(inp).map_err(|err| err.utf8_error())?)
    }
}

impl TryFrom<String> for Release {
    type Error = Error;
    fn try_from(inp: String) -> Result<Self> {
        Ok(Release {
            inner: ReleaseInnerTryBuilder {
                data: inp.into_boxed_str(),
                control_builder: |data: &'_ Box<str>| ControlStanza::parse(data.as_ref()),
                files_builder: |control: &'_ ControlStanza| {
                    let files: Result<Vec<ReleaseFile<'_>>> = control
                        .field("SHA256")
                        .ok_or_else(|| Error::FieldNotFound("SHA256"))?
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| l != &"")
                        .map(|line| {
                            let parts: Vec<&'_ str> = line.split_ascii_whitespace().collect();
                            if let [digest, size, path] = parts[..] {
                                let digest: Digest<sha2::Sha256> = digest.try_into()?;
                                let size = parse_size(size.as_bytes())?;
                                Ok(ReleaseFile { digest, size, path })
                            } else {
                                Err(Error::InvalidReleaseList(line.to_string()))
                            }
                        })
                        .collect();
                    files
                },
            }
            .try_build()?,
        })
    }
}

#[self_referencing]
struct ReleaseInner {
    data: Box<str>,
    #[borrows(data)]
    #[covariant]
    control: ControlStanza<'this>,
    #[borrows(control)]
    #[covariant]
    files: Vec<ReleaseFile<'this>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;

    #[test]
    fn test_find_release_entry() {
        let data = "\
SHA256:
 6ab13ddda55cf4f5a09f538d474c867bcafc821aee52a47313c2a47384160cc4    93686 contrib/binary-all/Packages
 c413f8b439c06cd92877ba816933a99041ea298e36138ae5c239eb75fc31cbe0    27285 contrib/binary-all/Packages.gz
 9b6ce8e2bcccc2a0e9d3e5f7864d89ac1dc2ec6335419dd6cc0e6bdd96697325    24088 contrib/binary-all/Packages.xz
 adea676f9da362ee55eca0f6f7597b824dfa1b0476eed5ee0414cea2c9a83179      117 contrib/binary-all/Release
 3a9ed913ce8eb058e0cf89a3011155699393f25951f08bde90358b6f0c6716d1   233622 contrib/binary-amd64/Packages
 25a55976ac9eeb2078c50a9e4adb0984a4379de1e5f654adb6e2d534b3417367    65631 contrib/binary-amd64/Packages.gz
 d53b837ab6882732f0e67bc5b693cb958976f248fdfa1cf97209ca948a46a0bd    54116 contrib/binary-amd64/Packages.xz
 e3ddd6d88f8c795b5fab1026bfddbb6937f5f3b64c51efad85303e7fd0f8bd28      119 contrib/binary-amd64/Release
 5c6a7dcf2bd5502b623043f515648f10769b3d8a129413fd3008ed6fd31a1785   194011 contrib/binary-arm64/Packages
 86332f06307512769d23db09b656041e2daf0cfe9eb356c880d8a79f18c6bd03    54718 contrib/binary-arm64/Packages.gz
 0601d762ab26a93dcf066d78b4d34f789ca34155929a5dd069a5c50ac58a627e    45652 contrib/binary-arm64/Packages.xz
".to_string();
        let release = Release::try_from(data).unwrap();
        let file = release.packages_file_for("contrib", "amd64", None).unwrap();
        assert_eq!(
            file.digest,
            Digest::<sha2::Sha256>::try_from(
                "3a9ed913ce8eb058e0cf89a3011155699393f25951f08bde90358b6f0c6716d1"
            )
            .unwrap()
        );
        assert_eq!(file.size, 233622);
        assert_eq!(file.path, "contrib/binary-amd64/Packages");
        let file = release
            .packages_file_for("contrib", "arm64", Some(".xz"))
            .unwrap();
        assert_eq!(
            file.digest,
            Digest::<sha2::Sha256>::try_from(
                "0601d762ab26a93dcf066d78b4d34f789ca34155929a5dd069a5c50ac58a627e"
            )
            .unwrap()
        );
        assert_eq!(file.size, 45652);
        assert_eq!(file.path, "contrib/binary-arm64/Packages.xz");
    }
}
