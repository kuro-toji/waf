//! WAF Configuration
//!
//! Configuration structures for the WAF system.
//!
//! ## Configuration File
//!
//! WAF is configured via YAML files. The main config file contains:
//! - General settings (listen address, upstream)
//! - Rate limiting configuration
//! - Bot detection settings
//! - Logging preferences
//! - Metrics configuration
//!
//! ## Example Configuration
//!
//! ```yaml
//! waf:
//!   listen_addr: "0.0.0.0:8080"
//!   upstream_addr: "127.0.0.1:8000"
//!   trusted_proxies:
//!     - "10.0.0.0/8"
//!
//! rate_limiter:
//!   enabled: true
//!   default_limit: 1000
//!   default_window_seconds: 60
//! ```
//!
//! ## Loading Configuration
//!
//! ```rust
//! use waf_common::WafConfig;
//!
//! let config = WafConfig::load_from_file("config/waf.yaml")?;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root WAF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    /// General WAF settings
    pub waf: WafSettings,
    /// Proxy configuration
    pub proxy: ProxyConfig,
    /// Rate limiter configuration
    pub rate_limiter: RateLimiterConfig,
    /// Bot detector configuration
    pub bot_detector: BotDetectorConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
}

/// General WAF settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafSettings {
    /// Server name to report
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// Listen address for WAF
    pub listen_addr: String,
    /// Upstream server address
    pub upstream_addr: String,
    /// Maximum request body size in bytes
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,
    /// Allowed CIDR blocks for X-Forwarded-For trust
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Minimum severity to block
    #[serde(default)]
    pub min_severity_to_block: String,
}

fn default_server_name() -> String {
    "WAF/1.0".to_string()
}

fn default_max_body_size() -> usize {
    1048576 // 1MB
}

fn default_timeout() -> u64 {
    60
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Enable TLS termination
    #[serde(default)]
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
    /// Keep-alive timeout in seconds
    #[serde(default = "default_keep_alive")]
    pub keep_alive_timeout: u64,
    /// Maximum connections to upstream
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Upstream health check interval in seconds
    #[serde(default = "default_health_check")]
    pub health_check_interval: u64,
}

fn default_keep_alive() -> u64 {
    65
}

fn default_max_connections() -> u32 {
    256
}

fn default_health_check() -> u64 {
    30
}

/// Rate limiter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    /// Enable rate limiting
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Default requests per window
    #[serde(default = "default_rate_limit")]
    pub default_limit: u64,
    /// Default window size in seconds
    #[serde(default = "default_window")]
    pub default_window_seconds: u64,
    /// Redis backend URL (optional, uses in-memory if not set)
    pub redis_url: Option<String>,
    /// Rate limit rules
    #[serde(default)]
    pub rules: Vec<RateLimitRule>,
}

fn default_enabled() -> bool {
    true
}

fn default_rate_limit() -> u64 {
    1000
}

fn default_window() -> u64 {
    60
}

/// Rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Rule name
    pub name: String,
    /// URI pattern to match
    pub uri_pattern: Option<String>,
    /// Client IP to match
    pub client_ip: Option<String>,
    /// Requests per window
    pub limit: u64,
    /// Window size in seconds
    pub window_seconds: u64,
    /// Action when exceeded
    #[serde(default)]
    pub action: String,
}

/// Bot detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotDetectorConfig {
    /// Enable bot detection
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Enable JavaScript challenge
    #[serde(default = "default_js_challenge")]
    pub js_challenge: bool,
    /// Enable CAPTCHA challenge
    #[serde(default)]
    pub captcha_challenge: bool,
    /// Challenge timeout in seconds
    #[serde(default = "default_challenge_timeout")]
    pub challenge_timeout: u64,
    /// IP reputation check enabled
    #[serde(default = "default_enabled")]
    pub ip_reputation_check: bool,
    /// Allow search engine bots
    #[serde(default = "default_allow_bots")]
    pub allow_search_bots: bool,
    /// Block known TOR exit nodes
    #[serde(default = "default_block_tor")]
    pub block_tor: bool,
    /// Block known VPN providers
    #[serde(default)]
    pub block_vpn: bool,
}

fn default_js_challenge() -> bool {
    true
}

fn default_challenge_timeout() -> u64 {
    300
}

fn default_allow_bots() -> bool {
    true
}

fn default_block_tor() -> bool {
    true
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format (json, text)
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Log file path (stdout if not set)
    pub log_file: Option<String>,
    /// Include request headers in logs
    #[serde(default)]
    pub include_headers: bool,
    /// Include request body in logs (may contain sensitive data)
    #[serde(default)]
    pub include_body: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics endpoint
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Metrics endpoint path
    #[serde(default = "default_metrics_path")]
    pub path: String,
    /// Prometheus pushgateway URL (optional)
    pub pushgateway_url: Option<String>,
    /// Push interval in seconds
    #[serde(default = "default_push_interval")]
    pub push_interval: u64,
}

fn default_enabled() -> bool {
    true
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_push_interval() -> u64 {
    60
}

/// Admin service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Enable admin API
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Listen address for admin service
    #[serde(default = "default_admin_listen")]
    pub listen_addr: String,
    /// API key for authentication
    pub api_key: Option<String>,
    /// Enable CORS
    #[serde(default = "default_cors")]
    pub cors_enabled: bool,
}

fn default_admin_listen() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_enabled() -> bool {
    true
}

fn default_cors() -> bool {
    true
}

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Enable dashboard
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Dashboard port
    #[serde(default = "default_dashboard_port")]
    pub port: u16,
}

fn default_dashboard_port() -> u16 {
    3000
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            waf: WafSettings {
                server_name: default_server_name(),
                listen_addr: "0.0.0.0:8080".to_string(),
                upstream_addr: "127.0.0.1:8000".to_string(),
                max_body_size: default_max_body_size(),
                timeout_seconds: default_timeout(),
                verbose: false,
                trusted_proxies: Vec::new(),
                min_severity_to_block: "medium".to_string(),
            },
            proxy: ProxyConfig {
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
                keep_alive_timeout: default_keep_alive(),
                max_connections: default_max_connections(),
                health_check_interval: default_health_check(),
            },
            rate_limiter: RateLimiterConfig {
                enabled: true,
                default_limit: default_rate_limit(),
                default_window_seconds: default_window(),
                redis_url: None,
                rules: Vec::new(),
            },
            bot_detector: BotDetectorConfig {
                enabled: true,
                js_challenge: true,
                captcha_challenge: false,
                challenge_timeout: default_challenge_timeout(),
                ip_reputation_check: true,
                allow_search_bots: true,
                block_tor: true,
                block_vpn: false,
            },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
                log_file: None,
                include_headers: false,
                include_body: false,
            },
            metrics: MetricsConfig {
                enabled: true,
                path: default_metrics_path(),
                pushgateway_url: None,
                push_interval: default_push_interval(),
            },
        }
    }
}

impl WafConfig {
    /// Load configuration from a YAML file
    pub fn load_from_file(path: &str) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Load configuration from a string
    pub fn load_from_str(content: &str) -> Result<Self, std::io::Error> {
        serde_yaml::from_str(content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WafConfig::default();
        assert_eq!(config.waf.listen_addr, "0.0.0.0:8080");
        assert_eq!(config.waf.upstream_addr, "127.0.0.1:8000");
        assert!(config.rate_limiter.enabled);
    }

    #[test]
    fn test_load_from_str() {
        let yaml = r#"
waf:
  listen_addr: "0.0.0.0:8090"
  upstream_addr: "127.0.0.1:9000"
rate_limiter:
  enabled: true
  default_limit: 500
"#;
        let config = WafConfig::load_from_str(yaml).unwrap();
        assert_eq!(config.waf.listen_addr, "0.0.0.0:8090");
        assert_eq!(config.waf.upstream_addr, "127.0.0.1:9000");
        assert_eq!(config.rate_limiter.default_limit, 500);
    }
}
