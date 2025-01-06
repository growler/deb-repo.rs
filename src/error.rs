//! Errors

/// Result wrapper
type Result<T> = std::result::Result<T, Error>;

/// Crate errors
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("invalid digest `{0}`: {1}")]
    InvalidDigest(String, String),

    #[error("I/O error: {0:?}")]
    Io(#[from] std::io::Error),

    #[error("invalid URL: {0:?}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("invalid HTTP request: {0:?}")]
    InvalidRequest(#[from] isahc::http::Error),

    #[error("HTTP error: {0:?}")]
    Http(#[from] isahc::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid encoding: {0:?}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("reader has unexpected references")]
    UnexpectedReference,

    #[error("failed to parse release file: {0}")]
    InvalidReleaseList(String),

    #[error("version requirement parse error: {0}")]
    RequirementParseError(String),

    #[error("missing field {0}")]
    FieldNotFound(&'static str),

    // parsing errors
    #[error("invalid field name: {0:?}")]
    InvalidFieldName(String),

    #[error("unterminated field: {0:?}")]
    UnterminatedField(String),

    #[error("expected control stanza")]
    EmptyControl,

    #[error("invalid release line: {0:?}")]
    InvalidReleaseLine(String),

    #[error("release component not found {0:?}")]
    ReleaseFileNotFound(String),

    #[error("{0}")]
    Other(String),
}
