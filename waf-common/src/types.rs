//! WAF Type Definitions
//!
//! Core types for requests, responses, rules, and actions.
//!
//! ## Types Overview
//!
//! - [`HttpMethod`] - HTTP method enumeration
//! - [`Severity`] - Attack severity levels (Info, Low, Medium, High, Critical)
//! - [`Sensitivity`] - Attack scoring sensitivity levels (Low, Medium, High)
//! - [`ScoringConfig`] - Configuration for cumulative attack scoring
//! - [`AttackScore`] - Result of attack scoring evaluation
//! - [`Action`] - WAF actions (Allow, Block, Challenge, Log)
//! - [`MatchType`] - Rule matching strategies
//! - [`MatchField`] - Request fields that can be matched
//! - [`Rule`] - Complete WAF rule definition
//! - [`RequestContext`] - Full request representation
//! - [`EvaluationResult`] - Rule evaluation outcome
//! - [`AttackLog`] - Attack logging structure
//!
//! ## Attack Scoring (OWASP CRS Style)
//!
//! Implements cumulative scoring where each matched rule adds to an anomaly score.
//! Based on OWASP Core Rule Set cooperative blocking model.
//!
//! ## Usage Example
//!
//! ```rust
//! use waf_common::{Rule, HttpMethod, Severity, Sensitivity, Action, MatchCondition, MatchType, MatchField, ScoringConfig, AttackScore};
//!
//! // Create a rule
//! let mut rule = Rule::new(
//!     "SQL Injection Detection".to_string(),
//!     Severity::Critical,
//!     Action::Block { status_code: 403, body: "Blocked".to_string(), reason: "SQLi detected".to_string() }
//! );
//! rule.add_condition(MatchCondition {
//!     field: MatchField::Query,
//!     match_type: MatchType::Regex,
//!     value: "(?i)union.*select".to_string(),
//!     case_insensitive: true,
//! });
//!
//! // Configure scoring with Medium sensitivity (blocks at score >= 40)
//! let scoring = ScoringConfig::medium();
//! ```

use std::collections::HashMap;

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
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    /// Get the default score weight for this severity level
    /// Base scores follow OWASP CRS anomaly scoring: critical=5, error=4, warning=3, notice=2
    pub fn score_weight(&self) -> u32 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

/// Sensitivity levels for attack scoring (OWASP CRS style paranoia levels)
/// Determines the threshold at which requests are blocked.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// Low sensitivity: block only at very high scores (threshold=60)
    /// Suitable for applications with high legitimate traffic variation
    #[default]
    Low = 0,
    /// Medium sensitivity: balanced blocking (threshold=40)
    /// Default for most production environments
    Medium = 1,
    /// High sensitivity: aggressive blocking at low scores (threshold=20)
    /// Use when false positives are acceptable trade-off for security
    High = 2,
}

impl Sensitivity {
    /// Get the cumulative score threshold for blocking
    /// Requests with score >= this value are blocked
    pub fn block_threshold(&self) -> u32 {
        match self {
            Sensitivity::Low => 60,
            Sensitivity::Medium => 40,
            Sensitivity::High => 20,
        }
    }

    /// Get the cumulative score threshold for challenging
    /// Requests with score >= this but < block_threshold get a challenge
    pub fn challenge_threshold(&self) -> u32 {
        // Challenge at 25% of block threshold
        (self.block_threshold() as f32 * 0.25) as u32
    }

    /// Get the cumulative score threshold for logging
    /// Requests with score >= this but < challenge_threshold are logged only
    pub fn log_threshold(&self) -> u32 {
        // Log at 10% of block threshold
        (self.block_threshold() as f32 * 0.10) as u32
    }

    /// Create a Sensitivity from a string (for config parsing)
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(Sensitivity::Low),
            "medium" => Some(Sensitivity::Medium),
            "high" => Some(Sensitivity::High),
            _ => None,
        }
    }
}

/// Configuration for attack scoring system
/// Implements OWASP CRS style cooperative blocking with cumulative anomaly scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Enable cumulative attack scoring
    #[serde(default)]
    pub enabled: bool,

    /// Sensitivity level for blocking decisions
    #[serde(default)]
    pub sensitivity: Sensitivity,

    /// Custom severity weights (overrides defaults)
    /// Maps severity level to score weight
    #[serde(default)]
    pub severity_weights: HashMap<Severity, u32>,

    /// Attack type multipliers
    /// Maps attack type tag to score multiplier (e.g., "sqli" -> 1.5)
    #[serde(default)]
    pub attack_multipliers: HashMap<String, f32>,

    /// Maximum cumulative score before capping
    #[serde(default = "default_max_score")]
    pub max_score: u32,

    /// Rules excluded from scoring (IDs)
    #[serde(default)]
    pub score_exempt_rules: Vec<String>,

    /// Whether to block immediately on first critical match
    /// (short-circuit evaluation)
    #[serde(default = "default_true")]
    pub short_circuit_critical: bool,
}

fn default_max_score() -> u32 {
    100
}

fn default_true() -> bool {
    true
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for backward compatibility
            sensitivity: Sensitivity::Medium,
            severity_weights: HashMap::new(),   // Use defaults
            attack_multipliers: HashMap::new(), // No multipliers by default
            max_score: 100,
            score_exempt_rules: Vec::new(),
            short_circuit_critical: false,
        }
    }
}

impl ScoringConfig {
    /// Create a config with low sensitivity
    pub fn low() -> Self {
        Self {
            enabled: true,
            sensitivity: Sensitivity::Low,
            ..Default::default()
        }
    }

    /// Create a config with medium sensitivity
    pub fn medium() -> Self {
        Self {
            enabled: true,
            sensitivity: Sensitivity::Medium,
            ..Default::default()
        }
    }

    /// Create a config with high sensitivity
    pub fn high() -> Self {
        Self {
            enabled: true,
            sensitivity: Sensitivity::High,
            ..Default::default()
        }
    }

    /// Get the weight for a severity level (custom or default)
    pub fn severity_weight(&self, severity: Severity) -> u32 {
        self.severity_weights
            .get(&severity)
            .copied()
            .unwrap_or_else(|| severity.score_weight())
    }

    /// Get the multiplier for an attack type
    pub fn attack_multiplier(&self, attack_type: &str) -> f32 {
        self.attack_multipliers
            .get(attack_type)
            .copied()
            .unwrap_or(1.0)
    }

    /// Check if a rule is exempt from scoring
    pub fn is_exempt(&self, rule_id: &str) -> bool {
        self.score_exempt_rules.iter().any(|id| id == rule_id)
    }
}

/// Result of cumulative attack scoring
/// Contains score breakdown and recommended action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScore {
    /// Total cumulative score (capped at max_score)
    pub total: u32,

    /// Score breakdown by severity level
    pub by_severity: HashMap<Severity, u32>,

    /// Individual rule contributions to the score
    pub contributions: Vec<RuleScoreContribution>,

    /// Detected attack types from rule tags
    pub attack_types: Vec<String>,

    /// Whether the threshold for blocking was exceeded
    pub should_block: bool,

    /// Whether the threshold for challenging was exceeded
    pub should_challenge: bool,

    /// Whether the threshold for logging was exceeded
    pub should_log: bool,

    /// The sensitivity level used for evaluation
    pub sensitivity: Sensitivity,

    /// Block threshold at current sensitivity
    pub block_threshold: u32,
}

/// Contribution from a single matched rule to the attack score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleScoreContribution {
    /// Rule identifier
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Severity level of the rule
    pub severity: Severity,
    /// Base score from severity weight
    pub base_score: u32,
    /// Score after applying attack type multiplier
    pub weighted_score: u32,
    /// Attack type tag if matched
    pub attack_type: Option<String>,
}

impl AttackScore {
    /// Calculate attack score from matched rules using scoring config
    pub fn calculate(rules: &[&Rule], config: &ScoringConfig) -> Self {
        if !config.enabled {
            return Self::zero(Sensitivity::Medium);
        }

        let mut total = 0u32;
        let mut by_severity: HashMap<Severity, u32> = HashMap::new();
        let mut contributions = Vec::new();
        let mut attack_types = Vec::new();

        for rule in rules {
            // Skip exempt rules
            if config.is_exempt(&rule.id) {
                continue;
            }

            // Calculate base score from severity
            let base_score = config.severity_weight(rule.severity);

            // Find attack type from tags. A rule may carry several tags;
            // the first one that has a configured multiplier wins, but every
            // tag is recorded in the audit trail for visibility.
            let attack_type = rule
                .tags
                .iter()
                .find(|t| config.attack_multipliers.contains_key(*t))
                .cloned();

            // Apply attack type multiplier
            let multiplier = attack_type
                .as_ref()
                .map(|at| config.attack_multiplier(at))
                .unwrap_or(1.0);

            let weighted_score = (base_score as f32 * multiplier) as u32;

            // Add to totals
            total += weighted_score;
            *by_severity.entry(rule.severity).or_insert(0) += weighted_score;

            // Track every tag as an attack type for the audit trail.
            for tag in &rule.tags {
                if !attack_types.contains(tag) {
                    attack_types.push(tag.clone());
                }
            }

            // Record contribution
            contributions.push(RuleScoreContribution {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                base_score,
                weighted_score,
                attack_type,
            });

            // Short-circuit on critical if configured
            if config.short_circuit_critical && rule.severity == Severity::Critical {
                total = total.max(config.sensitivity.block_threshold());
                break;
            }
        }

        // Cap at max score
        total = total.min(config.max_score);

        let sensitivity = config.sensitivity;
        let block_threshold = sensitivity.block_threshold();

        Self {
            total,
            by_severity,
            contributions,
            attack_types,
            should_block: total >= block_threshold,
            should_challenge: total >= sensitivity.challenge_threshold() && total < block_threshold,
            should_log: total >= sensitivity.log_threshold(),
            sensitivity,
            block_threshold,
        }
    }

    /// Create a zero score (no attacks)
    pub fn zero(sensitivity: Sensitivity) -> Self {
        Self {
            total: 0,
            by_severity: HashMap::new(),
            contributions: Vec::new(),
            attack_types: Vec::new(),
            should_block: false,
            should_challenge: false,
            should_log: false,
            sensitivity,
            block_threshold: sensitivity.block_threshold(),
        }
    }

    /// Get score for a specific severity level
    pub fn score_for_severity(&self, severity: Severity) -> u32 {
        self.by_severity.get(&severity).copied().unwrap_or(0)
    }
}

/// WAF action to take on a request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
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
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeType {
    /// JavaScript challenge that browser must solve
    #[default]
    Javascript,
    /// CAPTCHA challenge
    Captcha,
    /// Rate limit challenge
    RateLimit,
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
    /// Cumulative attack score (if scoring enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_score: Option<AttackScore>,
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
            attack_score: None,
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
            attack_score: None,
            processing_time_ms,
            timestamp: Utc::now(),
        }
    }

    /// Create from scoring result (new method)
    pub fn from_scoring(
        request_id: String,
        matched_rules: Vec<Rule>,
        attack_score: AttackScore,
        processing_time_ms: u64,
    ) -> Self {
        let highest_severity = matched_rules.iter().map(|r| r.severity).max();
        let allowed = !attack_score.should_block;
        let action = if attack_score.should_block {
            Action::Block {
                status_code: 403,
                body: "Access denied".to_string(),
                reason: format!(
                    "Attack score {} exceeds threshold {}",
                    attack_score.total, attack_score.block_threshold
                ),
            }
        } else if attack_score.should_challenge {
            Action::Challenge {
                challenge_type: ChallengeType::Javascript,
                timeout: 300,
            }
        } else {
            Action::Allow
        };

        Self {
            request_id,
            allowed,
            action,
            matched_rules,
            highest_severity,
            attack_score: Some(attack_score),
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
        let severity = matched_rule.severity;
        Self {
            id: Uuid::new_v4().to_string(),
            request,
            attack_type,
            matched_rule,
            severity,
            timestamp: Utc::now(),
            metadata: Vec::new(),
        }
    }
}
