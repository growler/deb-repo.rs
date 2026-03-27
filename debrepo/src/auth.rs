//! Authentication provider for transports.
//! Supports static `auth.toml` files and Vault prefixes (see README for full format details).
use {
    crate::auth_vault::VaultAuth,
    serde::{Deserialize, Serialize},
    smol::process::Command,
    std::{
        collections::HashMap,
        env, fs,
        path::{Path, PathBuf},
        sync::Arc,
    },
    tracing::warn,
    url::Url,
};

/// Authentication material resolved per host.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Auth {
    /// HTTP Basic/Digest credentials.
    Basic { login: String, password: String },
    /// Bearer token sent as `Authorization: Bearer <token>`.
    Token { token: String },
    /// Client certificate (PEM). `key` and `password` are optional.
    Cert {
        cert: Vec<u8>,
        key: Option<Vec<u8>>,
        password: Option<String>,
    },
}

/// Provides per-host authentication from a file (`auth.toml` by default) or Vault prefix.
/// Authentication provider for transport requests.
pub struct AuthProvider {
    cache: async_lock::RwLock<HashMap<String, Option<Arc<Auth>>>>,
    entries: HashMap<String, smallvec::SmallVec<[AuthDefinition; 1]>>,
    vault: Option<VaultAuth>,
}

#[derive(Debug, Clone)]
enum AuthDefinition {
    Basic {
        login: String,
        password: ValueSource,
    },
    Token {
        token: ValueSource,
    },
    Cert {
        cert: ValueSource,
        key: Option<ValueSource>,
        password: Option<ValueSource>,
    },
}

#[derive(Debug, Clone)]
enum ValueSource {
    Inline(String),
    Env(String),
    File(PathBuf),
    Command { command: String, cwd: PathBuf },
}

#[derive(Debug, Deserialize)]
struct AuthFile {
    #[serde(default)]
    auth: Vec<AuthSpec>,
}

/// Single auth entry from `auth.toml`.
#[derive(Debug, Deserialize)]
struct AuthSpec {
    host: String,
    login: Option<String>,
    password: Option<ValueSpec>,
    token: Option<ValueSpec>,
    cert: Option<ValueSpec>,
    key: Option<ValueSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ValueSpec {
    Simple(String),
    Source(ValueSpecSource),
}

#[derive(Debug, Deserialize, Default)]
struct ValueSpecSource {
    env: Option<String>,
    cmd: Option<String>,
    file: Option<String>,
    path: Option<String>,
    key: Option<String>,
}

impl AuthProvider {
    /// Build an auth provider from:
    /// - `None` (default) -> `./auth.toml`
    /// - `file:/path/to/auth.toml` or `/path/to/auth.toml`
    /// - `vault:<prefix>` where `<prefix>/<host>` contains a Vault secret
    pub fn new<S: AsRef<str>>(arg: Option<S>) -> std::io::Result<Self> {
        let (entries, vault) = match arg.as_ref().map(|s| s.as_ref().to_owned()) {
            None => (None, None),
            Some(ref value) if value.starts_with("vault:") => {
                let rest = value.trim_start_matches("vault:");
                (None, Some(VaultAuth::new(rest)?))
            }
            Some(value) => {
                let file_path = Path::new(value.strip_prefix("file:").unwrap_or(&value));
                let entries = Self::load_file(file_path)?;
                (Some(entries), None)
            }
        };

        let provider = Self {
            cache: async_lock::RwLock::new(HashMap::new()),
            entries: entries.unwrap_or_else(HashMap::new),
            vault,
        };

        Ok(provider)
    }

    pub async fn auth(&self, url: &Url) -> Option<Arc<Auth>> {
        let host = url.host_str()?;

        if let Some(entry) = self.cache.read().await.get(host) {
            return entry.as_ref().map(Arc::clone);
        }

        let resolved = self.resolve_for_host(host).await.map(Arc::new);
        let mut cache = self.cache.write().await;
        cache.insert(host.to_string(), resolved.as_ref().map(Arc::clone));
        resolved
    }

    async fn resolve_for_host(&self, host: &str) -> Option<Auth> {
        if let Some(entries) = self.entries.get(host) {
            for entry in entries {
                match entry.resolve().await {
                    Ok(auth) => return Some(auth),
                    Err(err) => warn!("failed to resolve auth for {}: {}", host, err),
                }
            }
        }
        if let Some(vault) = &self.vault {
            match vault.fetch(host).await {
                Ok(auth) => return auth,
                Err(err) => warn!("failed to fetch auth for {} from vault: {}", host, err),
            }
        }
        None
    }

    fn load_file(
        path: &Path,
    ) -> std::io::Result<HashMap<String, smallvec::SmallVec<[AuthDefinition; 1]>>> {
        let file_path = fs::canonicalize(path).map_err(|err| {
            std::io::Error::other(format!("no auth file {}: {}", path.display(), err))
        })?;
        let base_dir = file_path.parent().ok_or_else(|| {
            std::io::Error::other(format!("invalid auth file path: {}", file_path.display()))
        })?;
        let content = fs::read_to_string(path)?;
        let parsed: AuthFile = toml_edit::de::from_str(&content).map_err(|err| {
            std::io::Error::other(format!(
                "failed to parse auth file {}: {}",
                path.display(),
                err
            ))
        })?;
        let mut entries: HashMap<String, smallvec::SmallVec<[AuthDefinition; 1]>> = HashMap::new();
        for spec in parsed.auth {
            match AuthDefinition::from_spec(&spec, base_dir) {
                Ok(Some(def)) => {
                    entries.entry(spec.host.clone()).or_default().push(def);
                }
                Ok(None) => warn!("auth entry for {} is missing credentials", spec.host),
                Err(err) => warn!("skipping auth entry for {}: {}", spec.host, err),
            }
        }
        Ok(entries)
    }
}

impl AuthDefinition {
    fn from_spec(spec: &AuthSpec, base_dir: &Path) -> std::io::Result<Option<AuthDefinition>> {
        if let Some(token) = spec
            .token
            .as_ref()
            .map(|t| value_spec_to_source(t, base_dir, false))
            .transpose()?
        {
            return Ok(Some(AuthDefinition::Token { token }));
        }

        if let Some(cert) = spec
            .cert
            .as_ref()
            .map(|c| value_spec_to_source(c, base_dir, true))
            .transpose()?
        {
            let key = spec
                .key
                .as_ref()
                .map(|k| value_spec_to_source(k, base_dir, true))
                .transpose()?;
            let password = spec
                .password
                .as_ref()
                .map(|p| value_spec_to_source(p, base_dir, false))
                .transpose()?;
            return Ok(Some(AuthDefinition::Cert {
                cert,
                key,
                password,
            }));
        }

        if let (Some(login), Some(password)) = (
            spec.login.as_ref(),
            spec.password
                .as_ref()
                .map(|p| value_spec_to_source(p, base_dir, false))
                .transpose()?,
        ) {
            return Ok(Some(AuthDefinition::Basic {
                login: login.clone(),
                password,
            }));
        }

        Ok(None)
    }

    async fn resolve(&self) -> std::io::Result<Auth> {
        match self {
            AuthDefinition::Basic { login, password } => Ok(Auth::Basic {
                login: login.clone(),
                password: password.load_string().await?,
            }),
            AuthDefinition::Token { token } => Ok(Auth::Token {
                token: token.load_string().await?,
            }),
            AuthDefinition::Cert {
                cert,
                key,
                password,
            } => Ok(Auth::Cert {
                cert: cert.load_bytes().await?,
                key: match key {
                    Some(k) => Some(k.load_bytes().await?),
                    None => None,
                },
                password: match password {
                    Some(p) => Some(p.load_string().await?),
                    None => None,
                },
            }),
        }
    }
}

impl ValueSource {
    async fn load_bytes(&self) -> std::io::Result<Vec<u8>> {
        match self {
            ValueSource::Inline(value) => Ok(value.clone().into_bytes()),
            ValueSource::Env(var) => env::var(var)
                .map(|v| v.into_bytes())
                .map_err(|err| std::io::Error::other(format!("missing env {}: {}", var, err))),
            ValueSource::File(path) => smol::fs::read(path).await.map_err(|err| {
                std::io::Error::other(format!("failed to read {}: {}", path.display(), err))
            }),
            ValueSource::Command { command, cwd } => {
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .current_dir(cwd)
                    .output()
                    .await?;
                if !output.status.success() {
                    return Err(std::io::Error::other(format!(
                        "command '{}' exited with {}",
                        command, output.status
                    )));
                }
                Ok(output.stdout)
            }
        }
    }

    async fn load_string(&self) -> std::io::Result<String> {
        let raw = self.load_bytes().await?;
        let mut value =
            String::from_utf8(raw).map_err(|err| std::io::Error::other(err.to_string()))?;
        if matches!(self, ValueSource::Command { .. } | ValueSource::File(_)) {
            while value.ends_with('\n') || value.ends_with('\r') {
                value.pop();
            }
        }
        Ok(value)
    }
}

fn value_spec_to_source(
    value: &ValueSpec,
    base_dir: &Path,
    prefer_file: bool,
) -> std::io::Result<ValueSource> {
    match value {
        ValueSpec::Simple(v) => {
            if prefer_file && !looks_like_inline(v) {
                Ok(ValueSource::File(resolve_path(base_dir, v)))
            } else {
                Ok(ValueSource::Inline(v.clone()))
            }
        }
        ValueSpec::Source(source) => {
            if let Some(env) = &source.env {
                Ok(ValueSource::Env(env.clone()))
            } else if let Some(cmd) = &source.cmd {
                Ok(ValueSource::Command {
                    command: cmd.clone(),
                    cwd: base_dir.to_path_buf(),
                })
            } else if let Some(file) = source.file.as_ref().or(source.path.as_ref()).or(source
                .key
                .as_ref()
                .filter(|_| prefer_file || source.env.is_none()))
            {
                Ok(ValueSource::File(resolve_path(base_dir, file)))
            } else {
                Err(std::io::Error::other("no value source provided"))
            }
        }
    }
}

fn looks_like_inline(value: &str) -> bool {
    value.contains('\n') || value.contains("-----BEGIN")
}

fn resolve_path(base: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}
