use {
    debrepo::{auth::AuthProvider, HttpTransport, TransportProvider},
    smol::io::AsyncReadExt,
    std::{
        fs,
        path::{Path, PathBuf},
    },
    tempfile::tempdir,
};

fn file_url(path: &Path) -> String {
    url::Url::from_file_path(path)
        .expect("file url")
        .to_string()
}

fn closed_local_url(scheme: &str, path: &str) -> String {
    format!("{scheme}://127.0.0.1:65534{path}")
}

async fn read_opened(
    transport: &HttpTransport,
    url: &str,
) -> std::io::Result<(Vec<u8>, Option<u64>)> {
    let (mut reader, size) = transport.open(url).await?;
    let mut body = Vec::new();
    reader.read_to_end(&mut body).await?;
    Ok((body, size))
}

async fn open_err(transport: &HttpTransport, url: &str) -> std::io::Error {
    match transport.open(url).await {
        Ok(_) => panic!("opening {url} unexpectedly succeeded"),
        Err(err) => err,
    }
}

fn write_auth_file(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("auth.toml");
    fs::write(&path, body).expect("write auth file");
    path
}

#[test]
fn file_transport_returns_body_and_size() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("payload.txt");
    let bytes = b"transport file payload\n";
    fs::write(&path, bytes).expect("write payload");
    let transport = HttpTransport::new(
        AuthProvider::new::<&str>(None).expect("auth"),
        false,
        false,
        None,
    );

    let (body, size) =
        smol::block_on(read_opened(&transport, &file_url(&path))).expect("open file");
    assert_eq!(body, bytes);
    assert_eq!(size, Some(bytes.len() as u64));
}

#[test]
fn invalid_urls_and_unsupported_scheme_return_expected_errors() {
    let transport = HttpTransport::new(
        AuthProvider::new::<&str>(None).expect("auth"),
        false,
        false,
        None,
    );

    let err = smol::block_on(open_err(&transport, "relative/path"));
    assert!(err
        .to_string()
        .contains("expects absolute path: relative/path"));

    let err = smol::block_on(open_err(&transport, "http://[::1"));
    assert!(err.to_string().contains("invalid URL http://[::1"));

    let err = smol::block_on(open_err(&transport, "ftp://example.invalid/pool"));
    assert!(err.to_string().contains("unsupported transport ftp"));
}

#[test]
fn http_transport_with_token_auth_reaches_network_phase() {
    let dir = tempdir().expect("tempdir");
    let auth_path = write_auth_file(
        dir.path(),
        r#"
[[auth]]
host = "127.0.0.1"
token = "transport-token"
"#,
    );
    let auth = AuthProvider::new(Some(auth_path.to_string_lossy())).expect("auth provider");
    let transport = HttpTransport::new(auth, false, false, None);

    let err = smol::block_on(open_err(&transport, &closed_local_url("http", "/token")));
    assert!(!err.to_string().contains("failed to build request"));
}

#[test]
fn http_transport_with_basic_auth_reaches_network_phase() {
    let dir = tempdir().expect("tempdir");
    let auth_path = write_auth_file(
        dir.path(),
        r#"
[[auth]]
host = "127.0.0.1"
login = "alice"
password = "secret"
"#,
    );
    let auth = AuthProvider::new(Some(auth_path.to_string_lossy())).expect("auth provider");
    let transport = HttpTransport::new(auth, false, false, None);

    let err = smol::block_on(open_err(&transport, &closed_local_url("http", "/basic")));
    assert!(!err.to_string().contains("failed to build request"));
}

#[test]
fn cert_auth_is_rejected_for_http_and_attempted_for_https() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("client.pem");
    fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .expect("write cert");
    let auth_path = write_auth_file(
        dir.path(),
        &format!(
            r#"
[[auth]]
host = "127.0.0.1"
cert = "{}"
"#,
            cert_path.file_name().expect("cert name").to_string_lossy()
        ),
    );
    let auth = AuthProvider::new(Some(auth_path.to_string_lossy())).expect("auth provider");
    let transport = HttpTransport::new(auth, false, false, None);

    let http_err = smol::block_on(open_err(&transport, "http://127.0.0.1/resource"));
    assert!(http_err
        .to_string()
        .contains("client certificates are only supported for https URLs"));

    let https_err = smol::block_on(open_err(&transport, &closed_local_url("https", "/secure")));
    assert!(!https_err
        .to_string()
        .contains("client certificates are only supported for https URLs"));
}

#[test]
fn invalid_auth_header_value_reports_request_build_failure() {
    let dir = tempdir().expect("tempdir");
    let auth_path = write_auth_file(
        dir.path(),
        r#"
[[auth]]
host = "127.0.0.1"
token = "line1\nline2"
"#,
    );
    let auth = AuthProvider::new(Some(auth_path.to_string_lossy())).expect("auth provider");
    let transport = HttpTransport::new(auth, false, false, None);

    let err = smol::block_on(open_err(&transport, "http://127.0.0.1/request-build"));
    assert!(err
        .to_string()
        .contains("failed to build request for http://127.0.0.1/request-build"));
}

#[test]
fn client_builder_optional_branches_are_exercised_without_binding_loopback() {
    let transport = HttpTransport::new(
        AuthProvider::new::<&str>(None).expect("auth"),
        true,
        true,
        None,
    );

    let err = smol::block_on(open_err(&transport, &closed_local_url("http", "/forced")));
    assert!(!err.to_string().contains("failed to build request"));
}
