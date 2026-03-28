mod common;

use {
    common::{write_executable, EnvGuard},
    debrepo::auth::{Auth, AuthProvider},
    std::path::{Path, PathBuf},
};

fn write_auth_file(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("auth.toml");
    std::fs::write(&path, body).expect("write auth file");
    path
}

fn parse_url(url: &str) -> url::Url {
    url::Url::parse(url).expect("parse url")
}

fn expect_new_error(arg: Option<&str>) -> std::io::Error {
    match AuthProvider::new(arg) {
        Ok(_) => panic!("auth provider unexpectedly succeeded"),
        Err(err) => err,
    }
}

#[test]
fn auth_provider_resolves_sources_skips_invalid_entries_and_caches_command_results() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("client.pem"), b"client-cert\n").expect("write cert");
    std::fs::write(dir.path().join("client.key"), b"client-key\n").expect("write key");
    std::fs::write(dir.path().join("cert.pass"), b"passphrase\n").expect("write password");
    let counter = dir.path().join("token-count");
    let script = dir.path().join("emit-token.sh");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\ncount=0\nif [ -f \"{}\" ]; then count=$(cat \"{}\"); fi\ncount=$((count + 1))\nprintf '%s' \"$count\" > \"{}\"\nprintf 'cmd-token\\n'\n",
            counter.display(),
            counter.display(),
            counter.display()
        ),
    );

    let auth_path = write_auth_file(
        dir.path(),
        r#"
[[auth]]
host = "basic.example"
login = "alice"
password = { env = "AUTH_PASSWORD" }

[[auth]]
host = "token.example"
token = { cmd = "./emit-token.sh" }

[[auth]]
host = "cert.example"
cert = "client.pem"
key = { file = "client.key" }
password = { file = "cert.pass" }

[[auth]]
host = "fallback.example"
token = { file = "missing.token" }

[[auth]]
host = "fallback.example"
token = "fallback-token"

[[auth]]
host = "invalid.example"
password = "missing-login"
"#,
    );

    let mut env = EnvGuard::new();
    env.set("AUTH_PASSWORD", "env-secret");

    let provider = AuthProvider::new(Some(format!("file:{}", auth_path.display())))
        .expect("create auth provider");

    let basic = smol::block_on(provider.auth(&parse_url("https://basic.example/repo")))
        .expect("resolve basic auth");
    assert_eq!(
        basic.as_ref(),
        &Auth::Basic {
            login: "alice".to_string(),
            password: "env-secret".to_string(),
        }
    );

    let token = smol::block_on(provider.auth(&parse_url("https://token.example/repo")))
        .expect("resolve token auth");
    assert_eq!(
        token.as_ref(),
        &Auth::Token {
            token: "cmd-token".to_string(),
        }
    );
    let token_again = smol::block_on(provider.auth(&parse_url("https://token.example/again")))
        .expect("resolve cached token auth");
    assert_eq!(token_again.as_ref(), token.as_ref());
    assert_eq!(
        std::fs::read_to_string(&counter).expect("read counter"),
        "1",
        "command-backed auth should be cached per host"
    );

    let cert = smol::block_on(provider.auth(&parse_url("https://cert.example/secure")))
        .expect("resolve cert auth");
    assert_eq!(
        cert.as_ref(),
        &Auth::Cert {
            cert: b"client-cert\n".to_vec(),
            key: Some(b"client-key\n".to_vec()),
            password: Some("passphrase".to_string()),
        }
    );

    let fallback = smol::block_on(provider.auth(&parse_url("https://fallback.example/repo")))
        .expect("resolve fallback auth");
    assert_eq!(
        fallback.as_ref(),
        &Auth::Token {
            token: "fallback-token".to_string(),
        }
    );

    assert!(
        smol::block_on(provider.auth(&parse_url("https://invalid.example/repo"))).is_none(),
        "invalid entries should be ignored"
    );
    assert!(
        smol::block_on(provider.auth(&parse_url("https://unknown.example/repo"))).is_none(),
        "unknown hosts should not resolve auth"
    );
}

#[test]
fn auth_provider_reports_missing_auth_file() {
    let err = expect_new_error(Some("/definitely/missing/auth.toml"));
    assert!(err
        .to_string()
        .contains("no auth file /definitely/missing/auth.toml"));
}

#[test]
fn vault_backed_auth_provider_covers_env_and_connection_error_paths() {
    let mut env = EnvGuard::new();
    env.remove("VAULT_ADDR");
    env.remove("VAULT_TOKEN");
    env.remove("VAULT_SKIP_VERIFY");
    env.remove("VAULT_CACERT");

    let err = expect_new_error(Some("vault:secret/testing"));
    assert!(err.to_string().contains("VAULT_ADDR must be set"));

    env.set("VAULT_ADDR", "http://127.0.0.1:9/");
    let err = expect_new_error(Some("vault:secret/testing"));
    assert!(err.to_string().contains("VAULT_TOKEN must be set"));

    let ca_cert = tempfile::tempdir().expect("tempdir");
    let ca_path = ca_cert.path().join("vault-ca.pem");
    std::fs::write(
        &ca_path,
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .expect("write ca cert");
    env.set("VAULT_TOKEN", "vault-token");
    env.set("VAULT_SKIP_VERIFY", "1");
    env.set("VAULT_CACERT", &ca_path);

    env.set("VAULT_ADDR", "http://127.0.0.1:9/");
    let provider = AuthProvider::new(Some("vault:secret/testing")).expect("vault provider");
    assert!(
        smol::block_on(provider.auth(&parse_url("https://vault-basic.example/repo"))).is_none(),
        "connection failures should be reported as missing auth through the public provider API"
    );

    env.set("VAULT_ADDR", "not a url");
    let err = expect_new_error(Some("vault:secret/testing"));
    assert!(err.to_string().contains("invalid VAULT_ADDR not a url"));
}
