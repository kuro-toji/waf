//! WAF Type Definitions
//!
//! Core types for requests, responses, rules, and actions.
//!
//! ## Types Overview
//!
//! - [`HttpMethod`] - HTTP method enumeration
//! - [`Severity`] - Attack severity levels (Info, Low, Medium, High, Critical)
//! - [`Action`] - WAF actions (Allow, Block, Challenge, Log)
//! - [`MatchType`] - Rule matching strategies
//! - [`MatchField`] - Request fields that can be matched
//! - [`Rule`] - Complete WAF rule definition
//! - [`RequestContext`] - Full request representation
//! - [`EvaluationResult`] - Rule evaluation outcome
//! - [`AttackLog`] - Attack logging structure

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// HTTP method enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
    Other(String),
}

impl HttpMethod {
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Connect => "CONNECT",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Other(s) => s,
        }
    }
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "PATCH" => HttpMethod::Patch,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            "CONNECT" => HttpMethod::Connect,
            "TRACE" => HttpMethod::Trace,
            other => HttpMethod::Other(other.to_string()),
        }
    }
}

/// Attack severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}

/// WAF action to take on a request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "details")]
pub enum Action {
    /// Allow the request to proceed
    Allow,
    /// Block the request with a configurable response
    Block {
        /// HTTP status code for blocked request
        status_code: u16,
        /// Response body for blocked request
        body: String,
        /// Reason for blocking
        reason: String,
    },
    /// Challenge the client with CAPTCHA or JavaScript challenge
    Challenge {
        /// Challenge type
        challenge_type: ChallengeType,
        /// Session timeout in seconds
        timeout: u64,
    },
    /// Log the request but allow it through
    Log {
        /// Log level
        level: String,
        /// Message to log
        message: String,
    },
}

/// Challenge types for bot detection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeType {
    /// JavaScript challenge that browser must solve
    Javascript,
    /// CAPTCHA challenge
    Captcha,
    /// Rate limit challenge
    RateLimit,
}

impl Default for ChallengeType {
    fn default() -> Self {
        ChallengeType::Javascript
    }
}

/// Match type for rule conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    /// Regular expression pattern match
    Regex,
    /// Exact string match
    Exact,
    /// Contains substring
    Contains,
    /// Starts with prefix
    StartsWith,
    /// Ends with suffix
    EndsWith,
    /// Glob pattern match
    Glob,
    /// IP address or CIDR range
    IpRange,
}

/// Rule match condition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchCondition {
    /// Field to match against
    pub field: MatchField,
    /// Type of matching to perform
    pub match_type: MatchType,
    /// Value or pattern to match
    pub value: String,
    /// Case insensitive matching
    #[serde(default)]
    pub case_insensitive: bool,
}

/// Fields that can be matched in a request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchField {
    /// Request URI path
    Uri,
    /// Request query string
    Query,
    /// Request body
    Body,
    /// Specific HTTP header
    Header(String),
    /// Request method
    Method,
    /// Client IP address
    ClientIp,
    /// User-Agent header
    UserAgent,
    /// Referer header
    Referer,
    /// Cookie value
    Cookie(String),
    /// Request body as JSON (specific key)
    JsonBody(String),
    /// Request body as form data (specific field)
    FormData(String),
}

/// A WAF rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier
    pub id: String,
    /// Human-readable rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Attack severity level
    pub severity: Severity,
    /// Whether rule is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Match conditions (all must match for rule to trigger)
    pub conditions: Vec<MatchCondition>,
    /// Action to take when rule matches
    pub action: Action,
    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
    /// Rule priority (higher = evaluated first)
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Whitelist IPs that bypass this rule
    #[serde(default)]
    pub whitelist_ips: Vec<String>,
    /// Rule creation timestamp
    #[serde(default = "default_now")]
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    #[serde(default = "default_now")]
    pub updated_at: DateTime<Utc>,
}

fn default_enabled() -> bool {
    true
}

fn default_priority() -> i32 {
    0
}

fn default_now() -> DateTime<Utc> {
    Utc::now()
}

impl Rule {
    /// Create a new rule with a generated ID
    pub fn new(name: String, severity: Severity, action: Action) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description: None,
            severity,
            enabled: true,
            conditions: Vec::new(),
            action,
            tags: Vec::new(),
            priority: 0,
            whitelist_ips: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Add a condition to the rule
    pub fn add_condition(&mut self, condition: MatchCondition) {
        self.conditions.push(condition);
    }
}

/// Match result from a rule evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Whether rule matched
    pub matched: bool,
    /// The rule that matched (if any)
    pub rule: Option<Rule>,
    /// Matched value
    pub matched_value: Option<String>,
    /// Field that was matched
    pub matched_field: Option<MatchField>,
    /// Severity of matched attack
    pub severity: Option<Severity>,
    /// Action to take
    pub action: Option<Action>,
    /// Additional context
    #[serde(default)]
    pub context: Vec<(String, String)>,
}

impl MatchResult {
    /// Create a non-matching result
    pub fn no_match() -> Self {
        Self {
            matched: false,
            rule: None,
            matched_value: None,
            matched_field: None,
            severity: None,
            action: None,
            context: Vec::new(),
        }
    }

    /// Create a matching result
    pub fn matched(rule: Rule, value: String, field: MatchField) -> Self {
        let severity = rule.severity;
        let action = rule.action.clone();
        Self {
            matched: true,
            rule: Some(rule),
            matched_value: Some(value),
            matched_field: Some(field),
            severity: Some(severity),
            action: Some(action),
            context: Vec::new(),
        }
    }
}

/// Request context for WAF evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Unique request ID
    pub id: String,
    /// HTTP method
    pub method: HttpMethod,
    /// Request URI path
    pub uri: String,
    /// Query string (without ?)
    pub query_string: String,
    /// HTTP headers
    pub headers: Vec<(String, String)>,
    /// Client IP address
    pub client_ip: String,
    /// Request body (if available)
    pub body: Option<Vec<u8>>,
    /// Body content type
    pub content_type: Option<String>,
    /// Timestamp of request
    pub timestamp: DateTime<Utc>,
    /// TLS info
    pub tls: Option<TlsInfo>,
    /// Rate limit info
    pub rate_limit_info: Option<RateLimitInfo>,
}

impl RequestContext {
    /// Get a header value by name (case-insensitive)
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Get the request body as a string
    pub fn get_body_str(&self) -> Option<&str> {
        self.body.as_ref().and_then(|b| std::str::from_utf8(b).ok())
    }
}

/// TLS connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// Whether TLS is enabled
    pub enabled: bool,
    /// TLS version (e.g., "1.2", "1.3")
    pub version: Option<String>,
    /// Cipher suite
    pub cipher: Option<String>,
    /// Client certificate subject
    pub client_cert_subject: Option<String>,
}

/// Rate limiting information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    /// Current request count
    pub request_count: u64,
    /// Limit for the window
    pub limit: u64,
    /// Window duration in seconds
    pub window_seconds: u64,
    /// Remaining requests
    pub remaining: u64,
    /// Whether limit is exceeded
    pub exceeded: bool,
    /// Reset time
    pub reset_at: DateTime<Utc>,
}

/// WAF evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Unique request ID
    pub request_id: String,
    /// Whether request is allowed
    pub allowed: bool,
    /// Action that was taken
    pub action: Action,
    /// All matched rules
    pub matched_rules: Vec<Rule>,
    /// Highest severity of matched attacks
    pub highest_severity: Option<Severity>,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl EvaluationResult {
    /// Create an allowed result
    pub fn allowed(request_id: String, matched_rules: Vec<Rule>, processing_time_ms: u64) -> Self {
        let highest_severity = matched_rules.iter().map(|r| r.severity).max();
        Self {
            request_id,
            allowed: true,
            action: Action::Allow,
            matched_rules,
            highest_severity,
            processing_time_ms,
            timestamp: Utc::now(),
        }
    }

    /// Create a blocked result
    pub fn blocked(
        request_id: String,
        matched_rules: Vec<Rule>,
        action: Action,
        processing_time_ms: u64,
    ) -> Self {
        let highest_severity = matched_rules.iter().map(|r| r.severity).max();
        Self {
            request_id,
            allowed: false,
            action,
            matched_rules,
            highest_severity,
            processing_time_ms,
            timestamp: Utc::now(),
        }
    }
}

/// Attack type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttackType {
    /// SQL Injection
    SqlInjection,
    /// Cross-Site Scripting
    Xss,
    /// Cross-Site Request Forgery
    Csrf,
    /// Path Traversal
    PathTraversal,
    /// Command Injection
    CommandInjection,
    /// XML External Entity
    Xxe,
    /// LDAP Injection
    LdapInjection,
    /// Remote File Inclusion
    Rfi,
    /// Local File Inclusion
    Lfi,
    /// XML Injection
    XmlInjection,
    /// JSON Injection
    JsonInjection,
    /// Unknown attack type
    Unknown(String),
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::SqlInjection => write!(f, "sql_injection"),
            AttackType::Xss => write!(f, "xss"),
            AttackType::Csrf => write!(f, "csrf"),
            AttackType::PathTraversal => write!(f, "path_traversal"),
            AttackType::CommandInjection => write!(f, "command_injection"),
            AttackType::Xxe => write!(f, "xxe"),
            AttackType::LdapInjection => write!(f, "ldap_injection"),
            AttackType::Rfi => write!(f, "rfi"),
            AttackType::Lfi => write!(f, "lfi"),
            AttackType::XmlInjection => write!(f, "xml_injection"),
            AttackType::JsonInjection => write!(f, "json_injection"),
            AttackType::Unknown(s) => write!(f, "unknown_{}", s),
        }
    }
}

/// Attack log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackLog {
    /// Unique log ID
    pub id: String,
    /// Request context
    pub request: RequestContext,
    /// Attack type detected
    pub attack_type: AttackType,
    /// Matched rule
    pub matched_rule: Rule,
    /// Severity
    pub severity: Severity,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional metadata
    #[serde(default)]
    pub metadata: Vec<(String, String)>,
}

impl AttackLog {
    /// Create a new attack log
    pub fn new(request: RequestContext, attack_type: AttackType, matched_rule: Rule) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            request,
            attack_type,
            matched_rule,
            severity: matched_rule.severity,
            timestamp: Utc::now(),
            metadata: Vec::new(),
        }
    }
}
