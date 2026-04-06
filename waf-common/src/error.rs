//! WAF Error Types
//!
//! Error handling for the WAF system.

use thiserror::Error;

/// WAF error enumeration
#[derive(Error, Debug)]
pub enum WafError {
    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// YAML parsing errors
    #[error("YAML parsing error: {0}")]
    YamlParse(String),

    /// JSON errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Regex compilation errors
    #[error("Regex error: {0}")]
    Regex(String),

    /// Network errors
    #[error("Network error: {0}")]
    Network(String),

    /// Redis errors
    #[error("Redis error: {0}")]
    Redis(String),

    /// Rule evaluation errors
    #[error("Rule evaluation error: {0}")]
    RuleEvaluation(String),

    /// Invalid request errors
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Upstream server errors
    #[error("Upstream error: {0}")]
    Upstream(String),

    /// TLS errors
    #[error("TLS error: {0}")]
    Tls(String),

    /// Authentication errors
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Challenge failed
    #[error("Challenge failed: {0}")]
    ChallengeFailed(String),

    /// Not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Internal server error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<regex::Error> for WafError {
    fn from(e: regex::Error) -> Self {
        WafError::Regex(e.to_string())
    }
}

impl From<redis::RedisError> for WafError {
    fn from(e: redis::RedisError) -> Self {
        WafError::Redis(e.to_string())
    }
}

impl From<serde_yaml::Error> for WafError {
    fn from(e: serde_yaml::Error) -> Self {
        WafError::YamlParse(e.to_string())
    }
}

/// Result type alias for WAF operations
pub type Result<T> = std::result::Result<T, WafError>;
