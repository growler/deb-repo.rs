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
        control::{ControlStanza, ParseError},
        parse_size,
    },
    chrono::{DateTime, Utc},
    iterator_ext::IteratorExt,
    ouroboros::self_referencing,
    smallvec::SmallVec,
    std::borrow::Cow,
};

pub struct Release {
    inner: ReleaseInner,
}

#[derive(Clone)]
pub(crate) struct ReleaseFile<'a> {
    pub path: Cow<'a, str>,
    pub hash: Cow<'a, str>,
    pub size: u64,
}

impl Release {
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.with_data(|d| d.as_bytes())
    }
    pub fn len(&self) -> usize {
        self.inner.with_data(|d| d.len())
    }
    pub(crate) fn files<F>(
        &self,
        hash_field_name: &'static str,
        mut filter: F,
    ) -> Result<impl Iterator<Item = Result<ReleaseFile<'_>, ParseError>>, ParseError>
    where
        F: FnMut(&str) -> bool,
    {
        let field = self.inner.with_control(|c| {
            c.field(hash_field_name).ok_or_else(|| {
                ParseError::from(format!(
                    "Field {} not found in the release file",
                    hash_field_name,
                ))
            })
        })?;
        Ok(field
            .lines()
            .map(|l| l.trim())
            .filter(|l| l != &"")
            .map(|line| {
                let parts: SmallVec<[&'_ str; 3]> = line.split_ascii_whitespace().collect();
                if let [digest, size, path] = parts[..] {
                    Ok((digest, size, path))
                } else {
                    Err(ParseError::from(format!("Invalid release line: {}", line)))
                }
            })
            .try_filter_map(move |(digest, size, path)| {
                if filter(path) {
                    let size = parse_size(size.as_bytes()).map_err(|err| {
                        ParseError::from(format!("Invalid size: {:?} {}", size, err))
                    })?;
                    Ok(Some(ReleaseFile {
                        path: path.into(),
                        hash: digest.into(),
                        size: size,
                    }))
                } else {
                    Ok(None)
                }
            }))
    }
    // pub async fn fetch_packages(&self, component: &str, arch: &str) -> io::Result<Packages> {
    //     let (path, size, hash) = self.packages_file(component, arch).ok_or_else(|| {
    //         io::Error::new(
    //             io::ErrorKind::InvalidData,
    //             format!(
    //                 "File {}/binary-{}/Packages(.xz|.gz)? not found in release",
    //                 component, arch
    //             ),
    //         )
    //     })?;
    //     let release = String::from_utf8(self.repo.fetch_verify_unpack(&path, size, hash).await?)
    //         .map_err(|err| {
    //             io::Error::new(
    //                 io::ErrorKind::InvalidData,
    //                 format!("Invalid release file: {}", err),
    //             )
    //         })?;
    //     Ok(Packages::new(release.into_boxed_str()).map_err(|err| {
    //         io::Error::new(
    //             io::ErrorKind::InvalidData,
    //             format!("Invalid release file: {}", err),
    //         )
    //     })?)
    // }
    fn field(&self, name: &str) -> Option<&str> {
        self.inner
            .with_control(|ctrl| ctrl.field(name).map(|s| s.as_ref()))
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
    pub fn new(data: Box<str>) -> Result<Release, ParseError> {
        Ok(Release {
            inner: ReleaseInnerTryBuilder {
                data,
                control_builder: |data: &'_ Box<str>| {
                    ControlStanza::parse(data.as_ref()).map_err(|err| {
                        ParseError::from(format!("error parsing release file: {}", err))
                    })
                },
            }
            .try_build()?,
        })
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
    data: Box<str>,
    #[borrows(data)]
    #[covariant]
    control: ControlStanza<'this>,
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::hash::Hash;
//
//     type HashAlgo = sha2::Sha256;
//
//     #[test]
//     fn test_find_release_entry() {
//         let data = "\
// SHA256:
//  6ab13ddda55cf4f5a09f538d474c867bcafc821aee52a47313c2a47384160cc4    93686 contrib/binary-all/Packages
//  c413f8b439c06cd92877ba816933a99041ea298e36138ae5c239eb75fc31cbe0    27285 contrib/binary-all/Packages.gz
//  9b6ce8e2bcccc2a0e9d3e5f7864d89ac1dc2ec6335419dd6cc0e6bdd96697325    24088 contrib/binary-all/Packages.xz
//  adea676f9da362ee55eca0f6f7597b824dfa1b0476eed5ee0414cea2c9a83179      117 contrib/binary-all/Release
//  3a9ed913ce8eb058e0cf89a3011155699393f25951f08bde90358b6f0c6716d1   233622 contrib/binary-amd64/Packages
//  25a55976ac9eeb2078c50a9e4adb0984a4379de1e5f654adb6e2d534b3417367    65631 contrib/binary-amd64/Packages.gz
//  d53b837ab6882732f0e67bc5b693cb958976f248fdfa1cf97209ca948a46a0bd    54116 contrib/binary-amd64/Packages.xz
//  e3ddd6d88f8c795b5fab1026bfddbb6937f5f3b64c51efad85303e7fd0f8bd28      119 contrib/binary-amd64/Release
//  5c6a7dcf2bd5502b623043f515648f10769b3d8a129413fd3008ed6fd31a1785   194011 contrib/binary-arm64/Packages
//  86332f06307512769d23db09b656041e2daf0cfe9eb356c880d8a79f18c6bd03    54718 contrib/binary-arm64/Packages.gz
//  0601d762ab26a93dcf066d78b4d34f789ca34155929a5dd069a5c50ac58a627e    45652 contrib/binary-arm64/Packages.xz
// ".to_string().into_boxed_str();
//         let release = Release::new("sid", "".to_string().into(), data).unwrap();
//         let (path, size, hash) = release.packages_file("contrib", "all").unwrap();
//         assert_eq!(
//             hash,
//             Digest::try_from("9b6ce8e2bcccc2a0e9d3e5f7864d89ac1dc2ec6335419dd6cc0e6bdd96697325")
//                 .unwrap()
//         );
//         assert_eq!(size, 24088);
//         assert_eq!(path, "dists/sid/contrib/binary-all/Packages.xz");
//         let (path, size, hash) = release.packages_file("contrib", "arm64").unwrap();
//         assert_eq!(
//             hash,
//             Digest::try_from("0601d762ab26a93dcf066d78b4d34f789ca34155929a5dd069a5c50ac58a627e")
//                 .unwrap()
//         );
//         assert_eq!(size, 45652);
//         assert_eq!(path, "dists/sid/contrib/binary-arm64/Packages.xz");
//     }
// }
