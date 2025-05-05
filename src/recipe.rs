use {
    crate::{
        digest::Digest,
        version::{Dependency, Constraint},
    },
    async_std::io,
    serde::{Serialize, Deserialize},
    std::pin::pin,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Source {
    arch: Option<String>,
    url: String,
    distr: String,
    comp: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Recipe {
    sources: Vec<Source>,
    requirements: Vec<Dependency<Option<String>, String, String>>,
    constraints: Vec<Constraint<Option<String>, String, String>>,
}

impl Recipe {
    const MAX_SIZE: u64 = 8 * 1024 * 1024;
    pub fn sources(&self) -> impl Iterator<Item = &Source> {
        self.sources.iter()
    }
    pub fn add_source(&mut self, src: Source) {
        if self.sources.iter().find(|&s| src.eq(s)).is_none() {
            self.sources.push(src)
        }
    }
    pub fn requirements(&self) -> impl Iterator<Item = &Dependency<Option<String>, String, String>> {
        self.requirements.iter()
    }
    pub fn add_requirement(&mut self, dep: Dependency<Option<String>, String, String>) {
        if self.requirements.iter().find(|&d| dep.eq(d)).is_none() {
            self.requirements.push(dep)
        }
    }
    pub fn constraints(&self) -> impl Iterator<Item = &Constraint<Option<String>, String, String>> {
        self.constraints.iter()
    }
    pub fn add_constraint(&mut self, con: Constraint<Option<String>, String, String>) {
        if self.constraints.iter().find(|&c| con.eq(c)).is_none() {
            self.constraints.push(con)
        }
    }
    pub async fn read<R: io::Read + Send>(r: R) -> io::Result<Self> {
        use io::ReadExt;
        let mut r = pin!(r.take(Self::MAX_SIZE));
        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let result = serde_json::from_slice(&buf).map_err(|err| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse recipe: {}", err)
        ))?;
        Ok(result)
    }
    pub async fn write<W: io::Write + Send>(&self, w: W) -> io::Result<()> {
        use io::WriteExt;
        let out = serde_json::to_vec(self).map_err(|err| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to format recipe: {}", err)
        ))?;
        let mut w = pin!(w);
        w.write_all(&out).await?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecipeAsset {
    path: String,
    hash: Digest<sha2::Sha256>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedSource {
    source: Source,
    assets: Vec<RecipeAsset>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedPackage {
    source: u32,
    file: RecipeAsset,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedRecipe {
    sources: Vec<LockedSource>,
    packages: Vec<LockedPackage>,
}

impl LockedRecipe {
    const MAX_SIZE: u64 = 8 * 1024 * 1024;
    pub async fn read<R: io::Read + Send>(r: R) -> io::Result<()> {
        use io::ReadExt;
        let mut r = pin!(r.take(Self::MAX_SIZE));
        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let result = serde_json::from_slice(&buf).map_err(|err| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse locked recipe: {}", err)
        ))?;
        Ok(result)
    }
    pub async fn write<W: io::Write + Send>(&self, w: W) -> io::Result<()> {
        use io::WriteExt;
        let out = serde_json::to_vec(self).map_err(|err| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to format locked recipe: {}", err)
        ))?;
        let mut w = pin!(w);
        w.write_all(&out).await?;
        Ok(())
    }
}

/*

I need to write a rust module that would handle a recipe for debian installation.
The recipe is a file consisting of following sections:

```
[distribution]
arch = amd64

[source]
deb [arch=amd64] http://repp/debian distr main non-free

[include]
package
package1 (>=1.2.3) | package2

[exclude]
package3
package4 (<5.6)
```

The first section ("distribution") includes optional parameters. The only parameter so far is "arch".
The second section ("source") provides a list of sources in format of apt.list ("deb" followed by the optional attribute 
followed by repository URL followed by distribution name followed by the list of components)
The "include" section provides a list of package to include in format of Debian control file "Requires" field: name, 
name with version, or a union.
The "exclude" section provides a list of packages to exclude from distribution.

The recipe is accompanied by the recipe.lock file that includes following items

a list of source files including InRelease file and Packages.xz files and their corresponing SHA-256 sums.
a list of packages including package name, package version, package URL and the corrsponding SHA-256 sum.

Please provide the following:

The requirement is represented by struct Dependency<Option<String>, String, String>> and can be parsed by 
the method Dependency::parse(&str) -> io::Result<Self>. The struct also implements Display.
The constraint is represented by struct Constraint<Option<String>, String, String>> and can be parsed by 
the method Consraint::parse(&str) -> io::Result<Self>. The struct also implement Display.

There is also struct Universe providing methods to find the solution for the list of sources, requirements and constraints,
and that operate with PackageId type. It also can return the package details being provided with the PackageId.

What I expect:
 - write a struct Recipe and RecipeLock that would hold the internal representation of recipe.
 - write a method to read recipe from the file,
 - write a method to serialize recipe to the file,
 - write a method to read recipe locks from the file (format should be text but otherwise no preferences),
 - write a method to serialize recipe to the file.

*/

