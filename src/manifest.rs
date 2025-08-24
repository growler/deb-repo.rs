use {
    crate::{
        digest::{self, Hash},
        repo::{DebRepo, DebRepoBuilder},
        universe::Universe,
        version::{Constraint, Dependency, Version},
    },
    async_std::{io, path::Path},
    chrono::{DateTime, Utc},
    futures::stream::{self, StreamExt, TryStreamExt},
    serde::{Deserialize, Serialize},
    std::pin::pin,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum SourceOptionArch {
    Restrict(Vec<String>),
    Exclude(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    arch: Option<SourceOptionArch>,
    url: String,
    distr: String,
    comp: Vec<String>,
}

impl Source {
    pub fn should_include_arch(&self, arch: &str) -> bool {
        match &self.arch {
            Some(SourceOptionArch::Restrict(archs)) => archs.iter().any(|s| s == arch),
            Some(SourceOptionArch::Exclude(exclude)) => exclude != arch,
            None => true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,
    #[serde(default, rename = "install", with = "requirements_list")]
    requirements: Vec<Dependency<Option<String>, String, Version<String>>>,
    #[serde(
        default,
        rename = "exclude",
        with = "constraints_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    constraints: Vec<Constraint<Option<String>, String, Version<String>>>,
}

impl Manifest {
    const MAX_SIZE: u64 = 8 * 1024 * 1024;
    pub fn new() -> Self {
        return Manifest {
            sources: Vec::new(),
            requirements: Vec::new(),
            constraints: Vec::new(),
        };
    }
    pub fn sources(&self) -> impl Iterator<Item = &Source> {
        self.sources.iter()
    }
    pub fn add_source(&mut self, src: Source) {
        if self.sources.iter().find(|&s| src.eq(s)).is_none() {
            self.sources.push(src)
        }
    }
    pub fn requirements(
        &self,
    ) -> impl Iterator<Item = &Dependency<Option<String>, String, Version<String>>> {
        self.requirements.iter()
    }
    pub fn add_requirement(&mut self, dep: Dependency<Option<String>, String, Version<String>>) {
        if self.requirements.iter().find(|&d| dep.eq(d)).is_none() {
            self.requirements.push(dep)
        }
    }
    pub fn drop_requirement(&mut self, dep: Dependency<Option<String>, String, Version<String>>) {
        self.requirements.retain(|d| !d.eq(&dep));
    }
    pub fn constraints(
        &self,
    ) -> impl Iterator<Item = &Constraint<Option<String>, String, Version<String>>> {
        self.constraints.iter()
    }
    pub fn add_constraint(&mut self, con: Constraint<Option<String>, String, Version<String>>) {
        if self.constraints.iter().find(|&c| con.eq(c)).is_none() {
            self.constraints.push(con)
        }
    }
    pub fn into_requirements(
        self,
    ) -> (
        Vec<Dependency<Option<String>, String, Version<String>>>,
        Vec<Constraint<Option<String>, String, Version<String>>>,
    ) {
        (self.requirements, self.constraints)
    }
    pub async fn read<R: io::Read + Send>(r: R) -> io::Result<Self> {
        use io::ReadExt;
        let mut r = pin!(r.take(Self::MAX_SIZE));
        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let text = std::str::from_utf8(&buf).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to read manifest: {}", err),
            )
        })?;
        let result: Manifest = serde_yaml::from_str(text).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        Ok(result)
    }
    pub async fn write<W: io::Write + Send>(&self, w: W) -> io::Result<()> {
        use io::WriteExt;
        let out = serde_yaml::to_string(self).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize manifest: {}", err),
            )
        })?;
        let mut w = pin!(w);
        w.write_all(out.as_bytes()).await?;
        Ok(())
    }

    pub async fn fetch_universe<B: DebRepoBuilder>(
        &self,
        arch: &str,
        repo_builder: &B,
        limit: usize,
    ) -> io::Result<Universe> {
        let sources = self.sources().cloned().collect::<Vec<_>>();
        let releases = stream::iter(sources.into_iter().enumerate())
            .map(|(id, src)| async move {
                let repo: DebRepo = repo_builder.build(&src.url).await?.into();
                let rel = repo.fetch_release(&src.distr).await?;
                Ok::<_, io::Error>((src, id, rel))
            })
            .buffer_unordered(limit)
            .try_filter_map(move |(src, id, rel)| async move {
                if !src.should_include_arch(arch) {
                    Ok(None)
                } else {
                    let components = if src.comp.is_empty() {
                        rel.components().map(String::from).collect::<Vec<_>>()
                    } else {
                        src.comp.iter().map(|s| s.clone()).collect::<Vec<_>>()
                    };
                    Ok(Some((rel, id, components)))
                }
            })
            .try_collect::<Vec<_>>()
            .await?;
        let tasks: Vec<_> = releases
            .iter()
            .flat_map(|(rel, id, components)| {
                components.iter().map(move |comp| async move {
                    Ok::<_, io::Error>((id, rel.fetch_packages(comp, arch).await?))
                })
            })
            .collect();
        let mut packages = stream::iter(tasks)
            .buffer_unordered(limit)
            .try_collect::<Vec<_>>()
            .await?;
        packages.sort_by_key(|(id, _)| *id);
        Ok(Universe::new(
            &arch,
            packages.into_iter().map(|(_, pkg)| pkg),
        )?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedIndex {
    uri: String,
    #[serde(with = "digest::serde::base64")]
    hash: Hash<sha2::Sha256>,
}

impl LockedIndex {
    pub fn new(uri: String, hash: Hash<sha2::Sha256>) -> Self {
        LockedIndex { uri, hash }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedPackage {
    source: u32,
    uri: String,
    #[serde(with = "digest::serde::base64")]
    hash: Hash<sha2::Sha256>,
}

impl LockedPackage {
    pub fn new(source: u32, uri: String, hash: Hash<sha2::Sha256>) -> Self {
        LockedPackage { source, uri, hash }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedSource {
    source: Source,
    assets: Vec<LockedIndex>,
}

impl LockedSource {
    pub fn new(source: Source, assets: Vec<LockedIndex>) -> Self {
        LockedSource { source, assets }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockFile {
    timestamp: DateTime<Utc>,
    #[serde(with = "digest::serde::base64")]
    hash: Hash<sha2::Sha256>,
    sources: Vec<LockedSource>,
    packages: Vec<LockedPackage>,
}

impl LockFile {
    const MAX_SIZE: u64 = 8 * 1024 * 1024;
    pub async fn read_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::read(async_std::fs::File::open(path.as_ref()).await?).await
    }
    pub async fn read<R: io::Read + Send>(r: R) -> io::Result<Self> {
        use io::ReadExt;
        let mut r = pin!(r.take(Self::MAX_SIZE));
        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let result: LockFile = serde_json::from_slice(&buf).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse locked recipe: {}", err),
            )
        })?;
        for pkg in &result.packages {
            if (pkg.source as usize) >= result.sources.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "package {:?} source index {} out of bounds (max {})",
                        pkg.uri,
                        pkg.source,
                        result.sources.len() - 1
                    ),
                ));
            }
        }
        Ok(result)
    }
    pub async fn write_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        self.write(async_std::fs::File::create(path.as_ref()).await?)
            .await
    }
    pub async fn write<W: io::Write + Send>(&self, w: W) -> io::Result<()> {
        use io::WriteExt;
        let out = serde_json::to_vec_pretty(self).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to format locked recipe: {}", err),
            )
        })?;
        let mut w = pin!(w);
        w.write_all(&out).await?;
        Ok(())
    }
}

mod requirements_list {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D>(
        de: D,
    ) -> Result<Vec<Dependency<Option<String>, String, Version<String>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<String> = Vec::<String>::deserialize(de)?;
        raw.into_iter()
            .enumerate()
            .map(|(i, s)| {
                s.parse::<Dependency<Option<String>, String, Version<String>>>()
                    .map_err(|e| serde::de::Error::custom(format!("install[{i}]: {e}")))
            })
            .collect()
    }

    pub fn serialize<S>(
        value: &Vec<Dependency<Option<String>, String, Version<String>>>,
        ser: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_strings: Vec<String> = value.iter().map(ToString::to_string).collect();
        as_strings.serialize(ser)
    }
}

mod constraints_list {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D>(
        de: D,
    ) -> Result<Vec<Constraint<Option<String>, String, Version<String>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<String> = Vec::<String>::deserialize(de)?;
        raw.into_iter()
            .enumerate()
            .map(|(i, s)| {
                crate::version::Constraint::parse_inverse(&s)
                    .map_err(|e| serde::de::Error::custom(format!("exclude[{i}]: {e}")))
                    .map(|c| {
                        c.translate(
                            |a| a.map(|s| s.to_string()),
                            |n| n.to_string(),
                            |v| v.translate(|s| s.to_string()),
                        )
                    })
            })
            .collect()
    }

    pub fn serialize<S>(
        value: &Vec<Constraint<Option<String>, String, Version<String>>>,
        ser: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_strings: Vec<String> = value.iter().cloned().map(|c| (!c).to_string()).collect();
        as_strings.serialize(ser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
sources:
  - url: http://deb.debian.org/debian
    distr: bookworm
    comp: [main]

install:
  - "libc6"
  - "apt (>= 1.8.0)"
  - "iptables | nftables (>> 0.8.0)"
  - "pkg:i386"
  - "pandoc"

exclude:
  - "python (<< 3)"
"#;

    #[test]
    fn round_trip_manifest() {
        let m: Manifest = serde_yaml::from_str(EXAMPLE).unwrap();
        let out = serde_yaml::to_string(&m).unwrap();
        // sanity: should still parse after a serialize
        let _: Manifest = serde_yaml::from_str(&out).unwrap();
    }
}
