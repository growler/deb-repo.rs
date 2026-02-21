use {
    crate::auth::Auth,
    isahc::{
        config::{CaCertificate, Configurable, SslOption},
        http::{Request, StatusCode},
        HttpClient,
    },
    serde::Deserialize,
    smol::io::AsyncReadExt,
    std::{env, path::PathBuf, time::Duration},
    url::Url,
};

/// Vault-backed authentication provider.
pub struct VaultAuth {
    client: HttpClient,
    base: Url,
    token: String,
    path: String,
}

impl VaultAuth {
    pub fn new(path: &str) -> std::io::Result<Self> {
        let addr = env::var("VAULT_ADDR").map_err(|err| {
            std::io::Error::other(format!("VAULT_ADDR must be set for vault auth: {}", err))
        })?;
        let token = env::var("VAULT_TOKEN").map_err(|err| {
            std::io::Error::other(format!("VAULT_TOKEN must be set for vault auth: {}", err))
        })?;
        let skip_verify = env::var("VAULT_SKIP_VERIFY")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false);
        let ca_cert = env::var_os("VAULT_CACERT").map(PathBuf::from);

        let client = build_client(skip_verify, ca_cert)?;
        let base = Url::parse(&addr).map_err(|err| {
            std::io::Error::other(format!("invalid VAULT_ADDR {}: {}", addr, err))
        })?;
        let path = format!("v1/{}/", path.trim_start_matches('/').trim_end_matches('/'));
        Ok(Self {
            client,
            base,
            token,
            path,
        })
    }

    pub async fn fetch(&self, host: &str) -> std::io::Result<Option<Auth>> {
        let url = self.secret_url(host)?;
        let request = Request::get(url.as_str())
            .header("X-Vault-Token", &self.token)
            .body(())
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        let mut rsp = self.client.send_async(request).await.map_err(to_io_error)?;
        match rsp.status() {
            StatusCode::OK => {
                let mut body = String::new();
                rsp.body_mut()
                    .read_to_string(&mut body)
                    .await
                    .map_err(to_io_error)?;
                let parsed: VaultResponse = serde_json::from_str(&body).map_err(|err| {
                    std::io::Error::other(format!("invalid vault response: {}", err))
                })?;
                let secret = match parsed.data {
                    Some(secret) => secret,
                    None => return Ok(None),
                };
                secret.into_auth()
            }
            StatusCode::NOT_FOUND => Ok(None),
            other => Err(std::io::Error::other(format!(
                "vault returned {} for {}",
                other, url
            ))),
        }
    }

    fn secret_url(&self, host: &str) -> std::io::Result<Url> {
        self.base
            .join(&format!("{}{}", self.path, host))
            .map_err(|err| std::io::Error::other(format!("invalid vault URL: {}", err)))
    }
}

#[derive(Debug, Deserialize)]
struct VaultResponse {
    data: Option<VaultSecret>,
}

#[derive(Debug, Deserialize)]
struct VaultSecret {
    #[serde(rename = "type")]
    kind: String,
    login: Option<String>,
    password: Option<String>,
    token: Option<String>,
    cert: Option<String>,
    key: Option<String>,
}

impl VaultSecret {
    fn into_auth(self) -> std::io::Result<Option<Auth>> {
        let kind = self.kind.as_str();
        match kind {
            "basic" => {
                let login = self
                    .login
                    .ok_or_else(|| std::io::Error::other("missing login for basic auth"))?;
                let password = self
                    .password
                    .ok_or_else(|| std::io::Error::other("missing password for basic auth"))?;
                Ok(Some(Auth::Basic { login, password }))
            }
            "token" => {
                let token = self
                    .token
                    .ok_or_else(|| std::io::Error::other("missing token for token auth"))?;
                Ok(Some(Auth::Token { token }))
            }
            "mtls" => {
                let cert = self
                    .cert
                    .ok_or_else(|| std::io::Error::other("missing cert for mtls auth"))?;
                let key = self
                    .key
                    .ok_or_else(|| std::io::Error::other("missing key for mtls auth"))?;
                Ok(Some(Auth::Cert {
                    cert: cert.into_bytes(),
                    key: Some(key.into_bytes()),
                    password: None,
                }))
            }
            _ => Err(std::io::Error::other(format!(
                "unsupported auth type '{}' in vault secret",
                kind
            ))),
        }
    }
}

fn build_client(skip_verify: bool, ca_cert: Option<PathBuf>) -> std::io::Result<HttpClient> {
    let mut builder = HttpClient::builder().timeout(Duration::from_secs(10));
    if skip_verify {
        builder = builder.ssl_options(
            SslOption::DANGER_ACCEPT_INVALID_CERTS | SslOption::DANGER_ACCEPT_INVALID_HOSTS,
        );
    }
    if let Some(cert) = ca_cert {
        builder = builder.ssl_ca_certificate(CaCertificate::file(cert));
    }
    builder
        .build()
        .map_err(|err| std::io::Error::other(format!("failed to build vault client: {}", err)))
}

fn to_io_error(err: impl ToString) -> std::io::Error {
    std::io::Error::other(err.to_string())
}
