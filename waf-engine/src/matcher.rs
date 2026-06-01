//! WAF Matcher
//!
//! Core rule matching engine.
//!
//! ## Performance Characteristics
//!
//! - Regex patterns are compiled once at rule load time
//! - Compiled patterns are cached in memory
//! - Short-circuit evaluation on high-severity matches
//! - Thread-safe rule updates via RwLock
//! - O(n*m) complexity where n=rules, m=conditions per rule
//!
//! ## Usage
//!
//! ```rust
//! use waf_engine::{RuleMatcher, RuleLoader};
//! use waf_common::{Severity, Rule, Action};
//!
//! // Load rules
//! let mut loader = RuleLoader::new();
//! loader.add_file("rules/owasp-top10.yaml");
//! let rules = loader.load().expect("Failed to load rules");
//!
//! // Create matcher with medium severity threshold
//! let matcher = RuleMatcher::new(rules, Severity::Medium);
//!
//! // Evaluate a request
//! let result = matcher.evaluate(&request_context);
//! if !result.allowed {
//!     println!("Request blocked by {} rules", result.matched_rules.len());
//! }
//! ```

use waf_common::*;
use crate::scoring::*;
use parking_lot::RwLock;
use std::sync::Arc;
use regex::Regex;
use std::collections::HashMap;

/// Rule matcher for evaluating requests against rules
pub struct RuleMatcher {
    compiled_rules: Arc<RwLock<Vec<CompiledRule>>>,
    severity_threshold: Severity,
    scoring_engine: Option<ScoringEngine>,
}

struct CompiledRule {
    rule: Rule,
    regexes: HashMap<String, Regex>,
}

/// Match result with additional context
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub action: Action,
    pub matched_value: String,
    pub matched_field: MatchField,
}

impl RuleMatcher {
    /// Create a new rule matcher with default configuration (scoring disabled)
    pub fn new(rules: Vec<Rule>, severity_threshold: Severity) -> Self {
        Self {
            compiled_rules: Arc::new(RwLock::new(Self::compile_rules(rules))),
            severity_threshold,
            scoring_engine: None,
        }
    }

    /// Create a new rule matcher with scoring enabled
    pub fn with_scoring(rules: Vec<Rule>, severity_threshold: Severity, scoring_config: ScoringConfig) -> Self {
        let scoring_engine = if scoring_config.enabled {
            Some(ScoringEngine::new(scoring_config))
        } else {
            None
        };
        Self {
            compiled_rules: Arc::new(RwLock::new(Self::compile_rules(rules))),
            severity_threshold,
            scoring_engine,
        }
    }

    /// Enable attack scoring with the given configuration
    pub fn enable_scoring(&mut self, config: ScoringConfig) {
        if config.enabled {
            self.scoring_engine = Some(ScoringEngine::new(config));
        }
    }

    /// Disable attack scoring
    pub fn disable_scoring(&mut self) {
        self.scoring_engine = None;
    }

    /// Check if scoring is enabled
    pub fn is_scoring_enabled(&self) -> bool {
        self.scoring_engine.as_ref().map(|e| e.is_enabled()).unwrap_or(false)
    }

    /// Compile rules into internal representation
    fn compile_rules(rules: Vec<Rule>) -> Vec<CompiledRule> {
        rules
            .into_iter()
            .filter_map(|rule| {
                let mut regexes = HashMap::new();
                for condition in &rule.conditions {
                    if condition.match_type == MatchType::Regex {
                        let pattern = if condition.case_insensitive {
                            format!("(?i){}", condition.value)
                        } else {
                            condition.value.clone()
                        };
                        match Regex::new(&pattern) {
                            Ok(re) => {
                                regexes.insert(condition.value.clone(), re);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to compile regex for rule {}: {}", rule.id, e);
                            }
                        }
                    }
                }
                Some(CompiledRule { rule, regexes })
            })
            .collect()
    }

    /// Update rules at runtime (for hot reload)
    pub fn update_rules(&self, rules: Vec<Rule>) {
        let compiled = Self::compile_rules(rules);
        let mut guard = self.compiled_rules.write();
        *guard = compiled;
    }

    /// Evaluate a request against all rules (legacy method)
    pub fn evaluate(&self, ctx: &RequestContext) -> EvaluationResult {
        let start = std::time::Instant::now();
        let matched_rules = self.find_matched_rules(ctx);
        let processing_time = start.elapsed().as_millis() as u64;

        // If scoring is enabled, use scoring-based evaluation
        if let Some(ref engine) = self.scoring_engine {
            let rule_refs: Vec<&Rule> = matched_rules.iter().collect();
            let attack_score = engine.calculate_score(&rule_refs);
            return EvaluationResult::from_scoring(
                ctx.id.clone(),
                matched_rules,
                attack_score,
                processing_time,
            );
        }

        // Legacy behavior: immediate block on matched Block action
        let mut blocked = false;
        let mut block_action = Action::Allow;

        for rule in &matched_rules {
            if let Action::Block { .. } = &rule.action {
                blocked = true;
                block_action = rule.action.clone();
                if rule.severity >= Severity::Critical {
                    break;
                }
            }
        }

        if blocked {
            EvaluationResult::blocked(ctx.id.clone(), matched_rules, block_action, processing_time)
        } else {
            EvaluationResult::allowed(ctx.id.clone(), matched_rules, processing_time)
        }
    }

    /// Find all matched rules without making blocking decision
    pub fn find_matched_rules(&self, ctx: &RequestContext) -> Vec<Rule> {
        let mut matched_rules = Vec::new();

        let rules = self.compiled_rules.read();

        // Check if client IP is whitelisted
        let is_whitelisted = |ip: &str, whitelist: &[String]| -> bool {
            whitelist.iter().any(|w| {
                if w.contains('/') {
                    ip.starts_with(&w[..w.rfind('.').unwrap_or(0)])
                } else {
                    ip == w
                }
            })
        };

        for compiled in rules.iter() {
            let rule = &compiled.rule;

            // Skip disabled rules
            if !rule.enabled {
                continue;
            }

            // Check IP whitelist
            if !rule.whitelist_ips.is_empty() && is_whitelisted(&ctx.client_ip, &rule.whitelist_ips) {
                continue;
            }

            // Check severity threshold
            if rule.severity < self.severity_threshold {
                continue;
            }

            // Evaluate all conditions (AND logic)
            let mut all_matched = true;
            for condition in &rule.conditions {
                if !self.evaluate_condition(condition, ctx, &compiled.regexes) {
                    all_matched = false;
                    break;
                }
            }

            if all_matched {
                matched_rules.push(rule.clone());
            }
        }

        matched_rules
    }

    /// Evaluate a request with scoring-based decision making
    pub fn evaluate_with_scoring(&self, ctx: &RequestContext) -> EvaluationResult {
        let start = std::time::Instant::now();
        let matched_rules = self.find_matched_rules(ctx);
        let processing_time = start.elapsed().as_millis() as u64;

        if let Some(ref engine) = self.scoring_engine {
            let rule_refs: Vec<&Rule> = matched_rules.iter().collect();
            let attack_score = engine.calculate_score(&rule_refs);
            return EvaluationResult::from_scoring(
                ctx.id.clone(),
                matched_rules,
                attack_score,
                processing_time,
            );
        }

        // Fallback to legacy evaluation if scoring not available
        self.evaluate(ctx)
    }

    /// Get scoring configuration summary if scoring is enabled
    pub fn scoring_summary(&self) -> Option<ScoringConfigSummary> {
        self.scoring_engine.as_ref().map(|e| e.config_summary())
    }

    /// Evaluate a single condition against the request context
    fn evaluate_condition(
        &self,
        condition: &MatchCondition,
        ctx: &RequestContext,
        _compiled_regexes: &HashMap<String, Regex>,
    ) -> bool {
        let value = self.get_field_value(&condition.field, ctx);
        
        if value.is_none() {
            return false;
        }

        let value = value.unwrap();

        match condition.match_type {
            MatchType::Regex => {
                // Try to compile and match on the fly for now
                let pattern = if condition.case_insensitive {
                    format!("(?i){}", condition.value)
                } else {
                    condition.value.clone()
                };
                
                if let Ok(re) = Regex::new(&pattern) {
                    re.is_match(&value)
                } else {
                    false
                }
            }
            MatchType::Exact => {
                if condition.case_insensitive {
                    value.to_lowercase() == condition.value.to_lowercase()
                } else {
                    value == condition.value
                }
            }
            MatchType::Contains => {
                if condition.case_insensitive {
                    value.to_lowercase().contains(&condition.value.to_lowercase())
                } else {
                    value.contains(&condition.value)
                }
            }
            MatchType::StartsWith => {
                if condition.case_insensitive {
                    value.to_lowercase().starts_with(&condition.value.to_lowercase())
                } else {
                    value.starts_with(&condition.value)
                }
            }
            MatchType::EndsWith => {
                if condition.case_insensitive {
                    value.to_lowercase().ends_with(&condition.value.to_lowercase())
                } else {
                    value.ends_with(&condition.value)
                }
            }
            MatchType::Glob => {
                // Simple glob matching
                let glob_to_regex = condition.value
                    .replace("*", ".*")
                    .replace("?", ".");
                let pattern = if condition.case_insensitive {
                    format!("(?i)^{}$", glob_to_regex)
                } else {
                    format!("^{}$", glob_to_regex)
                };
                Regex::new(&pattern).map(|re| re.is_match(&value)).unwrap_or(false)
            }
            MatchType::IpRange => {
                // Simplified IP range check
                value.starts_with(&condition.value) || value == condition.value
            }
        }
    }

    /// Get the value of a field from the request context
    fn get_field_value<'a>(&self, field: &MatchField, ctx: &'a RequestContext) -> Option<&'a str> {
        match field {
            MatchField::Uri => Some(&ctx.uri),
            MatchField::Query => Some(&ctx.query_string),
            MatchField::Body => ctx.get_body_str(),
            MatchField::Method => Some(ctx.method.as_str()),
            MatchField::ClientIp => Some(&ctx.client_ip),
            MatchField::UserAgent => ctx.get_header("user-agent"),
            MatchField::Referer => ctx.get_header("referer"),
            MatchField::Header(name) => ctx.get_header(name),
            MatchField::Cookie(name) => {
                ctx.get_header("cookie")
                    .and_then(|c| extract_cookie(c, name))
            }
            MatchField::JsonBody(key) => {
                ctx.get_body_str()
                    .and_then(|b| extract_json_value(b, key))
            }
            MatchField::FormData(field) => {
                ctx.get_body_str()
                    .and_then(|b| extract_form_value(b, field))
            }
        }
    }
}

/// Extract a specific cookie value by name
fn extract_cookie(cookie_header: &str, name: &str) -> Option<&str> {
    cookie_header
        .split(';')
        .find_map(|pair| {
            let mut parts = pair.trim().splitn(2, '=');
            if let Some(cookie_name) = parts.next() {
                if cookie_name.trim() == name {
                    return parts.next().map(|v| v.trim());
                }
            }
            None
        })
}

/// Extract a value from JSON body
fn extract_json_value(body: &str, key: &str) -> Option<&str> {
    // Simple JSON extraction (not a full parser)
    let search = format!("\"{}\"", key);
    if let Some(start) = body.find(&search) {
        if let SomeColon) = body[..start].rfind(':') {
            let after_colon = &body[after_colon..];
            if let Some(end) = after_colon.find(',').or_else(|| after_colon.find('}')) {
                let value = &after_colon[1..end].trim();
                if value.starts_with('"') && value.ends_with('"') {
                    return Some(&value[1..value.len()-1]);
                }
                return Some(value);
            }
        }
    }
    None
}

/// Extract a value from form data
fn extract_form_value(body: &str, field: &str) -> Option<&str> {
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if urlencoding_decode(k) == field {
                return Some(&urlencoding_decode(v));
            }
        }
    }
    None
}

/// Simple URL encoding decode
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    
    while let Some(c) = chars.next() {
        if c == '%' {
            if let (Some(a), Some(b)) = (chars.next(), chars.next()) {
                let hex = format!("{}{}", a, b);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                }
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> RequestContext {
        RequestContext {
            id: "test-123".to_string(),
            method: HttpMethod::Get,
            uri: "/api/users".to_string(),
            query_string: "id=1".to_string(),
            headers: vec![
                ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            client_ip: "192.168.1.1".to_string(),
            body: None,
            content_type: Some("application/json".to_string()),
            timestamp: chrono::Utc::now(),
            tls: None,
            rate_limit_info: None,
        }
    }

    #[test]
    fn test_exact_match() {
        let mut rule = Rule::new(
            "Test Rule".to_string(),
            Severity::High,
            Action::Block {
                status_code: 403,
                body: "Blocked".to_string(),
                reason: "Test".to_string(),
            },
        );
        rule.add_condition(MatchCondition {
            field: MatchField::Uri,
            match_type: MatchType::Exact,
            value: "/admin".to_string(),
            case_insensitive: false,
        });

        let matcher = RuleMatcher::new(vec![rule], Severity::Low);
        
        let mut ctx = create_test_context();
        ctx.uri = "/admin".to_string();
        let result = matcher.evaluate(&ctx);
        assert!(!result.allowed);

        ctx.uri = "/api/users".to_string();
        let result = matcher.evaluate(&ctx);
        assert!(result.allowed);
    }

    #[test]
    fn test_regex_match() {
        let mut rule = Rule::new(
            "SQLi Detection".to_string(),
            Severity::Critical,
            Action::Block {
                status_code: 403,
                body: "Blocked".to_string(),
                reason: "SQL injection".to_string(),
            },
        );
        rule.add_condition(MatchCondition {
            field: MatchField::Query,
            match_type: MatchType::Regex,
            value: "(?i)union.*select".to_string(),
            case_insensitive: true,
        });

        let matcher = RuleMatcher::new(vec![rule], Severity::Low);
        
        let mut ctx = create_test_context();
        ctx.query_string = "id=1 UNION SELECT * FROM users".to_string();
        let result = matcher.evaluate(&ctx);
        assert!(!result.allowed);

        ctx.query_string = "id=1".to_string();
        let result = matcher.evaluate(&ctx);
        assert!(result.allowed);
    }

    #[test]
    fn test_severity_threshold() {
        let mut rule = Rule::new(
            "Low Severity Rule".to_string(),
            Severity::Low,
            Action::Block {
                status_code: 403,
                body: "Blocked".to_string(),
                reason: "Test".to_string(),
            },
        );
        rule.add_condition(MatchCondition {
            field: MatchField::Uri,
            match_type: MatchType::Exact,
            value: "/test".to_string(),
            case_insensitive: false,
        });

        let matcher = RuleMatcher::new(vec![rule], Severity::High);
        
        let mut ctx = create_test_context();
        ctx.uri = "/test".to_string();
        let result = matcher.evaluate(&ctx);
        // Should be allowed because low severity < high threshold
        assert!(result.allowed);
    }
}