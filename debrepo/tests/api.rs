use {
    debrepo::{
        auth::{Auth, AuthProvider},
        control::{ControlFile, ControlStanza, Field, MutableControlFile, MutableControlStanza},
        deb,
        hash::VerifyingReader,
        universe::Universe,
        Dependency, FileList, HostFileSystem, PackageOrigin, Packages, SourceUniverse, Sources,
        Version,
    },
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    smol::io::{AsyncReadExt, Cursor},
    static_assertions::assert_impl_all,
    std::fs,
    tempfile::tempdir,
};

assert_impl_all!(deb::DebReader<'_, smol::fs::File>: Send, Sync);
assert_impl_all!(HostFileSystem: Send, Sync);
assert_impl_all!(FileList: Send, Sync);
assert_impl_all!(MutableControlStanza: Send, Sync);

#[test]
fn parses_basic_inline() -> std::io::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("auth.toml");
    fs::write(
        &path,
        r#"
[[auth]]
host = "deb.company.com"
login = "user"
password = "secret"
"#,
    )?;

    smol::block_on(async {
        let provider = AuthProvider::new(Some(path.to_string_lossy()))?;
        let url = url::Url::parse("https://deb.company.com").unwrap();
        match provider.auth(&url).await.as_deref() {
            Some(Auth::Basic { login, password }) => {
                assert_eq!(login, "user");
                assert_eq!(password, "secret");
            }
            other => panic!("unexpected auth: {:?}", other),
        }
        Ok(())
    })
}

#[test]
fn parses_env_and_command_sources() -> std::io::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("auth.toml");
    fs::write(
        &path,
        r#"
[[auth]]
host = "env.example"
login = "user"
password.env = "AUTH_PASSWORD"

[[auth]]
host = "cmd.example"
token.cmd = "printf token-from-cmd"
"#,
    )?;
    std::env::set_var("AUTH_PASSWORD", "from-env");

    smol::block_on(async {
        let provider = AuthProvider::new(Some(path.to_string_lossy()))?;

        let env_url = url::Url::parse("https://env.example").unwrap();
        match provider.auth(&env_url).await.as_deref() {
            Some(Auth::Basic { login, password }) => {
                assert_eq!(login, "user");
                assert_eq!(password, "from-env");
            }
            other => panic!("unexpected auth: {:?}", other),
        }

        let cmd_url = url::Url::parse("https://cmd.example").unwrap();
        match provider.auth(&cmd_url).await.as_deref() {
            Some(Auth::Token { token }) => assert_eq!(token, "token-from-cmd"),
            other => panic!("unexpected auth: {:?}", other),
        }
        Ok(())
    })
}

#[test]
fn parses_cert_paths_and_password() -> std::io::Result<()> {
    let dir = tempdir()?;
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    fs::write(&cert_path, "CERTDATA")?;
    fs::write(&key_path, "KEYDATA")?;
    let path = dir.path().join("auth.toml");
    fs::write(
        &path,
        format!(
            r#"
[[auth]]
host = "tls.example"
cert = "{}"
key = "{}"
password = "cert-password"
"#,
            cert_path.file_name().unwrap().to_string_lossy(),
            key_path.file_name().unwrap().to_string_lossy()
        ),
    )?;

    smol::block_on(async {
        let provider = AuthProvider::new(Some(path.to_string_lossy()))?;
        let url = url::Url::parse("https://tls.example").unwrap();
        match provider.auth(&url).await.as_deref() {
            Some(Auth::Cert {
                cert,
                key,
                password,
            }) => {
                assert_eq!(cert, b"CERTDATA");
                assert_eq!(key.as_deref(), Some(b"KEYDATA".as_slice()));
                assert_eq!(password.as_deref(), Some("cert-password"));
            }
            other => panic!("unexpected auth: {:?}", other),
        }
        Ok(())
    })
}

#[test]
fn test_multiline() {
    let data = "Base:\n Value1\n Value2\nField:\n Value\n\n";
    match ControlFile::parse(data) {
        Ok(file) => {
            let stanzas: Vec<&ControlStanza> = file.stanzas.iter().collect();
            assert_eq!(file.stanzas.len(), 1);
            assert_eq!(stanzas[0].fields().count(), 2);
            assert_eq!(stanzas[0].field("Field").unwrap(), "\n Value");
        }
        Err(err) => panic!("Failed to parse control file {:?}", err),
    }
}

#[test]
fn test_parse_control_file() {
    let data = "\
FieldName: FieldValue

Simple: simple value
Folded: line
 continuation
Multi-Line:
 Line one
 .
 Line two


";
    match ControlFile::parse(data) {
        Ok(file) => {
            let stanzas: Vec<&ControlStanza> = file.stanzas.iter().collect();
            assert_eq!(file.stanzas.len(), 2);
            assert_eq!(stanzas[0].fields().count(), 1);
            assert_eq!(stanzas[1].fields().count(), 3);
            assert_eq!(stanzas[1].field("Simple").unwrap(), "simple value");
            assert_eq!(stanzas[1].field("folded").unwrap(), "line\n continuation");
            assert_eq!(
                stanzas[1].field("multi-line").unwrap(),
                "\n Line one\n .\n Line two"
            );
        }
        Err(err) => panic!("Failed to parse control file {:?}", err),
    }
}

#[test]
fn test_multiline_eof() {
    let data = "Base:\n Value1\n Value2\nField:\n Value";
    match ControlFile::parse(data) {
        Ok(file) => {
            let stanzas: Vec<&ControlStanza> = file.stanzas.iter().collect();
            assert_eq!(file.stanzas.len(), 1);
            assert_eq!(stanzas[0].fields().count(), 2);
            assert_eq!(stanzas[0].field("Field").unwrap(), "\n Value");
        }
        Err(err) => panic!("Failed to parse control file {:?}", err),
    }
}

#[test]
fn test_single_eof() {
    let data = "Base:\n Value1\n Value2\nField: Value";
    match ControlFile::parse(data) {
        Ok(file) => {
            let stanzas: Vec<&ControlStanza> = file.stanzas.iter().collect();
            assert_eq!(file.stanzas.len(), 1);
            assert_eq!(stanzas[0].fields().count(), 2);
            assert_eq!(stanzas[0].field("Field").unwrap(), "Value");
        }
        Err(err) => panic!("Failed to parse control file {:?}", err),
    }
}

#[test]
fn test_mulitple() {
    let data: Vec<&str> = vec!["A: B\n\n", "A: B\n\n"];
    let parsed: Vec<ControlFile<'_>> = data
        .iter()
        .map(|d| ControlFile::parse(d).unwrap())
        .collect();
    assert!(&parsed[0]
        .stanzas()
        .next()
        .unwrap()
        .fields()
        .next()
        .unwrap()
        .is_a("a"))
}

#[test]
fn test_add_stanza() {
    let mut cf = MutableControlFile::new();
    let s = cf.new_stanza();
    s.set("A", "B");
    let d = "D".to_string();
    s.set("C", d);
    assert_eq!(format!("{}", cf), "A: B\nC: D\n\n");
}

#[test]
fn test_add_field() {
    let data = "\
Package: test
Arch: i386
Description:
 Test description
";
    let mut stanza = MutableControlStanza::parse(data).unwrap();
    stanza.set("NewField", "NewValue");
    assert_eq!(stanza.field("NewField").unwrap(), "NewValue");
    stanza.set("Field1", "Value1");
    assert_eq!(stanza.field("Field1").unwrap(), "Value1");
    let mut it = stanza.fields();
    let f = it.next().unwrap();
    assert_eq!(f.name(), "Package");
    assert_eq!(f.value(), "test");
    let f = it.next().unwrap();
    assert_eq!(f.name(), "Arch");
    assert_eq!(f.value(), "i386");
}

#[test]
fn test_verifying_reader() {
    smol::block_on(async {
        let data = b"hello world";
        let size = data.len() as u64;
        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected_digest = hasher.finalize();

        let cursor = Cursor::new(data);
        let mut reader = VerifyingReader::<Sha256, _>::new(cursor, size, expected_digest);

        let mut buf = vec![0; size.try_into().unwrap()];
        let n = reader.read(&mut buf).await.unwrap() as u64;
        assert_eq!(n, size);
        assert_eq!(&buf, data);

        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    });
}

#[test]
fn test_verifying_reader_incorrect_digest() {
    smol::block_on(async {
        let data = b"hello world";
        let size = data.len() as u64;
        let incorrect_digest = Sha256::digest(b"incorrect");

        let cursor = Cursor::new(data);
        let mut reader = VerifyingReader::<Sha256, _>::new(cursor, size, incorrect_digest);

        let mut buf = vec![0; size.try_into().unwrap()];
        let n = reader.read(&mut buf).await.unwrap() as u64;
        assert_eq!(n, size);
        assert_eq!(&buf, data);

        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("error verifying stream by"));
    });
}

#[test]
fn test_verifying_reader_incorrect_size() {
    smol::block_on(async {
        let data = b"hello world";
        let size = data.len() as u64 + 1;
        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected_digest = hasher.finalize();

        let cursor = Cursor::new(data);
        let mut reader = VerifyingReader::<Sha256, _>::new(cursor, size, expected_digest);

        let mut buf = vec![0; data.len()];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf, data);

        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("error verifying stream:"));
    });
}

#[derive(Debug, Deserialize, Serialize)]
struct WirePackageOrigin {
    value: PackageOrigin,
}

#[test]
fn package_origin_accessors_match_variants() {
    assert_eq!(PackageOrigin::Unknown.manifest(), None);
    assert_eq!(PackageOrigin::Unknown.archive(), None);
    assert_eq!(PackageOrigin::Local { manifest_id: 7 }.manifest(), Some(7));
    assert_eq!(PackageOrigin::Local { manifest_id: 7 }.archive(), None);
    assert_eq!(
        PackageOrigin::Archive {
            manifest_id: 3,
            archive_id: 9
        }
        .manifest(),
        Some(3)
    );
    assert_eq!(
        PackageOrigin::Archive {
            manifest_id: 3,
            archive_id: 9
        }
        .archive(),
        Some(9)
    );
}

#[test]
fn package_origin_serializes_new_string_forms() {
    assert_eq!(
        toml_edit::ser::to_string(&WirePackageOrigin {
            value: PackageOrigin::Unknown
        })
        .unwrap(),
        "value = \"\"\n"
    );
    assert_eq!(
        toml_edit::ser::to_string(&WirePackageOrigin {
            value: PackageOrigin::Local { manifest_id: 5 }
        })
        .unwrap(),
        "value = \":5\"\n"
    );
    assert_eq!(
        toml_edit::ser::to_string(&WirePackageOrigin {
            value: PackageOrigin::Archive {
                manifest_id: 2,
                archive_id: 8
            }
        })
        .unwrap(),
        "value = \":2:8\"\n"
    );
}

#[test]
fn package_origin_deserializes_legacy_and_new_forms() {
    assert_eq!(
        toml_edit::de::from_str::<WirePackageOrigin>("value = 7\n")
            .unwrap()
            .value,
        PackageOrigin::Archive {
            manifest_id: 0,
            archive_id: 7
        }
    );
    assert_eq!(
        toml_edit::de::from_str::<WirePackageOrigin>("value = \"\"\n")
            .unwrap()
            .value,
        PackageOrigin::Unknown
    );
    assert_eq!(
        toml_edit::de::from_str::<WirePackageOrigin>("value = \":4\"\n")
            .unwrap()
            .value,
        PackageOrigin::Local { manifest_id: 4 }
    );
    assert_eq!(
        toml_edit::de::from_str::<WirePackageOrigin>("value = \":4:12\"\n")
            .unwrap()
            .value,
        PackageOrigin::Archive {
            manifest_id: 4,
            archive_id: 12
        }
    );
    assert!(toml_edit::de::from_str::<WirePackageOrigin>("value = \"7\"\n").is_err());
}

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
fn universe_returns_first_match() {
    let s1: Sources = sample_source().try_into().unwrap();
    let s2: Sources = Sources::try_from(sample_source()).unwrap();
    let mut uni = SourceUniverse::new();
    uni.push(s1);
    uni.push(s2);
    let entry = uni.source("1oom").next().unwrap();
    assert_eq!(entry.name(), "1oom");
}

macro_rules! test_solution {
    (@skip $n:ident $problem:expr => $solution:expr , $src:expr) => {};
    ($n:ident $problem:expr => $solution:expr , $src:expr) => {
        #[test]
        fn $n() {
            let mut uni = Universe::new(
                "amd64",
                vec![
                    Packages::new($src.to_string().into(), PackageOrigin::Unknown, None)
                        .expect("failed to parse test source"),
                ]
                .into_iter(),
            )
            .unwrap();
            let solution = match uni.solve(
                $problem
                    .into_iter()
                    .map(|dep| Dependency::try_from(dep).expect("failed to parse dependency")),
                vec![],
            ) {
                Ok(solution) => solution,
                Err(err) => {
                    panic!("{}", uni.display_conflict(err))
                }
            };
            let solution = uni.installation_order(&solution);
            let solution: Vec<_> = solution
                .into_iter()
                .flatten()
                .map(|i| format!("{}", uni.display_solvable(i)))
                .collect();
            assert_eq!(solution, $solution);
        }
    };
}

test_solution!(self_dependent
[ "alpha" ] => [ "alpha:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Provides: beta
Breaks: beta
");

test_solution!(absent
[ "alpha" ] => [ "alpha:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Conflicts: beta
");

test_solution!(absent_2
[ "alpha" ] => [ "alpha:amd64=1.0", "beta:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Depends: beta (= 1.0) | omega

Package: beta
Architecture: amd64
Version: 1.0
");

test_solution!(mutual
[ "alpha" ] => [ "alpha:amd64=2.6.1" ],
"Package: alpha
Architecture: amd64
Version: 2.6.1
Provides: beta (= 2.6.1)
Breaks: beta (<= 1.5~alpha4~)

Package: beta
Architecture: amd64
Version: 2.6.1
Depends: alpha (>= 1.5~alpha4~)
");

test_solution!(dep_break
[ "alpha" ] => [ "alpha:amd64=2.38.1-5+deb12u2", "beta:amd64=2.38.1-5+deb12u2" ],
"Package: alpha
Architecture: amd64
Version: 2.38.1-5+deb12u2
Depends: beta

Package: beta
Architecture: amd64
Version: 2.38.1-5+deb12u2
Breaks: alpha (<= 2.38~)
");

test_solution!(dep_range
[ "keyboard-configuration" ] => [ "keyboard-configuration:all=1.221", "xkb-data:all=2.35.1-1" ],
"Package: keyboard-configuration
Version: 1.221
Architecture: all
Depends: xkb-data (>= 2.35.1~), xkb-data (<< 2.35.1A)

Package: xkb-data
Version: 2.35.1-1
Architecture: all
");

test_solution!(dep_chain
[ "alpha" ] => [ "alpha:amd64=1.0", "beta:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Depends: beta (= 1.0)

Package: beta
Architecture: amd64
Version: 1.0
");

test_solution!(or_witness_cycle_avoided
[ "alpha", "zeta" ] => [
    "alpha:amd64=1.0",
    "beta:amd64=1.0",
    "xis:amd64=1.0",
    "zeta:amd64=1.0",
],
"Package: alpha
Architecture: amd64
Version: 1.0
Depends: xis

Package: xis
Architecture: amd64
Version: 1.0
Depends: alpha (= 1.0) | beta

Package: beta
Architecture: amd64
Version: 1.0

Package: zeta
Architecture: amd64
Version: 1.0
Depends: beta (= 1.0)
");

test_solution!(pre_depends_ordering
[ "pkg" ] => [ "core:amd64=1.0", "pkg:amd64=1.0" ],
"Package: pkg
Architecture: amd64
Version: 1.0
Pre-Depends: core (= 1.0)

Package: core
Architecture: amd64
Version: 1.0
");

test_solution!(priority_tiebreaks
[ "o1", "r1", "e1" ] => [ "e1:amd64=1.0", "r1:amd64=1.0", "o1:amd64=1.0" ],
"Package: e1
Architecture: amd64
Version: 1.0
Essential: yes

Package: r1
Architecture: amd64
Version: 1.0
Priority: required

Package: o1
Architecture: amd64
Version: 1.0
Priority: optional
");

test_solution!(union_duplicate_vs_dedup
[ "xz" ] => [ "foo:amd64=1.0", "xz:amd64=1.0" ],
"Package: xz
Architecture: amd64
Version: 1.0
Depends: foo (= 1.0) | foo (>= 1.0)

Package: foo
Architecture: amd64
Version: 1.0
");

macro_rules! assert_version {
    ($left:tt $op:tt $right:tt) => {
        std::assert!(Version::from_str($left).unwrap() $op Version::from_str($right).unwrap())
    };
}

#[test]
fn test_alpha_compare() {
    use std::str::FromStr;

    assert_version!("~~" < "~~a");
    assert_version!("~~a" > "~~");
    assert_version!("~~a" < "~");
    assert_version!("~" > "~~a");
    assert_version!("a" < "b");
    assert_version!("b" > "a");
    assert_version!("c" < "db");
    assert_version!("b" < "+a");
}

#[test]
fn test_versions() {
    use std::str::FromStr;

    assert_version!("2.38.1-5+deb12u2" > "2.38~");
    assert_version!("2.35.1-1" >= "2.35.1~");
    assert_version!("2.35.1-1" < "2.35.1A");
    assert_version!("2" > "1");
    assert_version!("1:2" > "1:1");
    assert_version!("1:2.5" > "2.5");
    assert_version!("1.0.1" > "1.0.0");
    assert_version!("2.0.1" > "1.0.1");
    assert_version!("2.0.0" > "2.0.0~rc1");
    assert_version!("2.0.0~rc2" > "2.0.0~rc1");
    assert_version!("2.0.0~rc2+u1" > "2.0.0~rc2");
    assert_version!("1.0.3~rc2+b2" > "1.0.3~rc2+b1");
    assert_version!("2.0.0" > "2.0.0~b1");
    assert_version!("2.0.0+u10" > "2.0.0+u9");
    assert_version!("2.21-9" > "2.19-18+deb8u3");
    assert_version!("2.21-9" > "2.19-18+deb8u3");
    assert_version!("2:1.2498-1" > "2:1.2492-4");
    assert_version!("0.0.0+2016.01.15.git.29cc9e1b05-2+b8" < "0.0.0+2016.02.15.git.29cc9e1b05");
    assert_version!("6.2.2006+really6.2.1905+dfsg-5.1+b1" == "6.2.2006+really6.2.1905+dfsg-5.1+b1");
}
