//! Attack Scoring Engine
//!
//! Implements cumulative threat scoring following the OWASP CRS cooperative
//! blocking model. Each matched rule contributes to a cumulative anomaly
//! score, which determines the final action (allow/challenge/block).
//!
//! ## Scoring Model
//!
//! ```text
//! Rule Matched → Severity Weight × Attack Multiplier → Score Contribution
//!                                            ↓
//!                              Cumulative Score Calculation
//!                                            ↓
//!                    Threshold Comparison → Block / Challenge / Log
//! ```
//!
//! ## Example
//!
//! ```rust
//! use waf_engine::scoring::ScoringEngine;
//! use waf_common::{ScoringConfig, Sensitivity, Severity, Rule, Action, MatchCondition, MatchType, MatchField};
//!
//! let config = ScoringConfig::medium();
//! let engine = ScoringEngine::new(config);
//!
//! let mut rule = Rule::new("SQLi".into(), Severity::Critical, Action::Allow);
//! rule.tags.push("sqli".into());
//!
//! let score = engine.calculate_score(&[&rule]);
//! assert!(score.should_block); // Critical = 5, exceeds Medium threshold of 40? No.
//! // But 3 Critical rules would = 15, etc.
//! ```
//!
//! ## Attack Type Multipliers
//!
//! Configure in ScoringConfig to increase score weight for specific attacks:
//!
//! ```yaml
//! scoring:
//!   attack_multipliers:
//!     sqli: 1.5   # SQL injection 50% more serious
//!     xss: 1.3    # XSS 30% more serious
//! ```

use std::collections::HashMap;
use waf_common::*;

/// Attack scoring engine implementing OWASP CRS style cumulative scoring
pub struct ScoringEngine {
    config: ScoringConfig,
}

impl ScoringEngine {
    /// Create a new scoring engine with the given configuration
    pub fn new(config: ScoringConfig) -> Self {
        Self { config }
    }

    /// Calculate the cumulative attack score from matched rules
    ///
    /// Each rule contributes its severity weight (modified by attack type
    /// multiplier if applicable) to a cumulative score. The result
    /// determines whether to block, challenge, or log.
    ///
    /// # Arguments
    ///
    /// * `rules` - Slice of references to matched rules
    ///
    /// # Returns
    ///
    /// `AttackScore` containing total score, breakdown, and recommended actions
    pub fn calculate_score(&self, rules: &[&Rule]) -> AttackScore {
        AttackScore::calculate(rules, &self.config)
    }

    /// Calculate score from owned rules (convenience method)
    pub fn calculate_score_owned(&self, rules: &[Rule]) -> AttackScore {
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        self.calculate_score(&rule_refs)
    }

    /// Get the current scoring configuration
    pub fn config(&self) -> &ScoringConfig {
        &self.config
    }

    /// Update scoring configuration at runtime (for hot reload)
    pub fn update_config(&mut self, config: ScoringConfig) {
        self.config = config;
    }

    /// Get the block threshold for the current sensitivity
    pub fn block_threshold(&self) -> u32 {
        self.config.sensitivity.block_threshold()
    }

    /// Get the challenge threshold for the current sensitivity
    pub fn challenge_threshold(&self) -> u32 {
        self.config.sensitivity.challenge_threshold()
    }

    /// Check if scoring is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get a summary of the current scoring configuration
    pub fn config_summary(&self) -> ScoringConfigSummary {
        ScoringConfigSummary {
            enabled: self.config.enabled,
            sensitivity: self.config.sensitivity,
            block_threshold: self.block_threshold(),
            challenge_threshold: self.challenge_threshold(),
            max_score: self.config.max_score,
            severity_weights: self.config.severity_weights.clone(),
            attack_multipliers: self.config.attack_multipliers.clone(),
            exempt_rules_count: self.config.score_exempt_rules.len(),
        }
    }
}

/// Summary of scoring configuration for monitoring/debugging
#[derive(Debug, Clone)]
pub struct ScoringConfigSummary {
    pub enabled: bool,
    pub sensitivity: Sensitivity,
    pub block_threshold: u32,
    pub challenge_threshold: u32,
    pub max_score: u32,
    pub severity_weights: HashMap<Severity, u32>,
    pub attack_multipliers: HashMap<String, f32>,
    pub exempt_rules_count: usize,
}

impl std::fmt::Display for ScoringConfigSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Scoring Engine Configuration:")?;
        writeln!(f, "  Enabled: {}", self.enabled)?;
        writeln!(f, "  Sensitivity: {:?}", self.sensitivity)?;
        writeln!(f, "  Block Threshold: {}", self.block_threshold)?;
        writeln!(f, "  Challenge Threshold: {}", self.challenge_threshold)?;
        writeln!(f, "  Max Score: {}", self.max_score)?;
        if !self.severity_weights.is_empty() {
            writeln!(f, "  Severity Weights: {:?}", self.severity_weights)?;
        }
        if !self.attack_multipliers.is_empty() {
            writeln!(f, "  Attack Multipliers: {:?}", self.attack_multipliers)?;
        }
        write!(f, "  Exempt Rules: {}", self.exempt_rules_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule(severity: Severity, tags: Vec<&str>) -> Rule {
        let mut rule = Rule::new(format!("Test {:?} Rule", severity), severity, Action::Allow);
        rule.tags = tags.into_iter().map(|s| s.to_string()).collect();
        rule
    }

    #[test]
    fn test_scoring_disabled() {
        let config = ScoringConfig {
            enabled: false,
            sensitivity: Sensitivity::Medium,
            ..Default::default()
        };
        let engine = ScoringEngine::new(config);

        let rule = create_test_rule(Severity::Critical, vec![]);
        let score = engine.calculate_score(&[&rule]);

        assert_eq!(score.total, 0);
        assert!(!score.should_block);
    }

    #[test]
    fn test_critical_rule_block_high_sensitivity() {
        let config = ScoringConfig::high();
        let engine = ScoringEngine::new(config);

        // High sensitivity: block at 20
        // Critical severity = 5 weight
        let rule = create_test_rule(Severity::Critical, vec![]);
        let score = engine.calculate_score(&[&rule]);

        // 5 < 20, so should not block alone
        assert!(!score.should_block);
        assert!(score.should_log); // 5 >= 2 (log threshold)
    }

    #[test]
    fn test_multiple_rules_accumulate() {
        let config = ScoringConfig::medium(); // block at 40
        let engine = ScoringEngine::new(config);

        // 4 Critical rules × 5 = 20, still under threshold
        let rules: Vec<Rule> = (0..4)
            .map(|_| create_test_rule(Severity::Critical, vec![]))
            .collect();
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let score = engine.calculate_score(&rule_refs);

        assert_eq!(score.total, 20);
        assert!(!score.should_block);

        // 8 Critical rules = 40, exactly at threshold
        let rules: Vec<Rule> = (0..8)
            .map(|_| create_test_rule(Severity::Critical, vec![]))
            .collect();
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let score = engine.calculate_score(&rule_refs);

        assert_eq!(score.total, 40);
        assert!(score.should_block);
    }

    #[test]
    fn test_attack_multiplier() {
        let mut config = ScoringConfig::medium();
        config.attack_multipliers.insert("sqli".to_string(), 2.0);
        let engine = ScoringEngine::new(config);

        // Critical (5) × sqli multiplier (2.0) = 10
        let mut rule = create_test_rule(Severity::Critical, vec!["sqli"]);
        rule.add_condition(MatchCondition {
            field: MatchField::Query,
            match_type: MatchType::Regex,
            value: ".*".to_string(),
            case_insensitive: false,
        });

        let score = engine.calculate_score(&[&rule]);

        assert_eq!(score.total, 10);
        assert_eq!(score.attack_types, vec!["sqli"]);
    }

    #[test]
    fn test_exempt_rules() {
        let mut config = ScoringConfig::medium();
        config.score_exempt_rules.push("exempt-rule".to_string());
        let engine = ScoringEngine::new(config);

        let exempt_rule = {
            let mut r = create_test_rule(Severity::Critical, vec![]);
            r.id = "exempt-rule".to_string();
            r
        };
        let normal_rule = create_test_rule(Severity::Critical, vec![]);

        let score = engine.calculate_score(&[&exempt_rule, &normal_rule]);

        // Only the non-exempt rule contributes (5 instead of 10)
        assert_eq!(score.total, 5);
    }

    #[test]
    fn test_severity_weights() {
        let mut config = ScoringConfig::medium();
        // Override Critical weight to be higher
        config.severity_weights.insert(Severity::Critical, 10);
        let engine = ScoringEngine::new(config);

        let rule = create_test_rule(Severity::Critical, vec![]);
        let score = engine.calculate_score(&[&rule]);

        assert_eq!(score.total, 10); // Custom weight
    }

    #[test]
    fn test_max_score_cap() {
        let config = ScoringConfig {
            enabled: true,
            sensitivity: Sensitivity::Low, // high threshold
            max_score: 50,                 // low cap
            ..Default::default()
        };
        let engine = ScoringEngine::new(config);

        // 100 rules at Critical (5 each) would be 500, but capped at 50
        let rules: Vec<Rule> = (0..100)
            .map(|_| create_test_rule(Severity::Critical, vec![]))
            .collect();
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let score = engine.calculate_score(&rule_refs);

        assert_eq!(score.total, 50); // Capped
        assert!(score.should_block); // 50 < 60 (Low threshold)
    }

    #[test]
    fn test_short_circuit_critical() {
        let config = ScoringConfig {
            enabled: true,
            sensitivity: Sensitivity::Low, // block at 60
            short_circuit_critical: true,
            ..Default::default()
        };
        let engine = ScoringEngine::new(config);

        // Even with many rules, hitting Critical triggers immediate high score
        let rules: Vec<Rule> = (0..20)
            .map(|_| create_test_rule(Severity::Critical, vec![]))
            .collect();
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let score = engine.calculate_score(&rule_refs);

        // Short circuit caps at threshold immediately
        assert!(score.should_block);
    }

    #[test]
    fn test_score_by_severity_breakdown() {
        let config = ScoringConfig::medium();
        let engine = ScoringEngine::new(config);

        let rules = vec![
            create_test_rule(Severity::Critical, vec![]),
            create_test_rule(Severity::Critical, vec![]),
            create_test_rule(Severity::High, vec![]),
            create_test_rule(Severity::Medium, vec![]),
        ];
        let rule_refs: Vec<&Rule> = rules.iter().collect();
        let score = engine.calculate_score(&rule_refs);

        assert_eq!(score.total, 5 + 5 + 4 + 3); // 17
        assert_eq!(score.score_for_severity(Severity::Critical), 10);
        assert_eq!(score.score_for_severity(Severity::High), 4);
        assert_eq!(score.score_for_severity(Severity::Medium), 3);
    }

    #[test]
    fn test_contributions_audit_trail() {
        let config = ScoringConfig::medium();
        let engine = ScoringEngine::new(config);

        let rule1 = {
            let mut r = create_test_rule(Severity::Critical, vec!["sqli"]);
            r.id = "sqli-001".to_string();
            r
        };
        let rule2 = {
            let mut r = create_test_rule(Severity::High, vec!["xss"]);
            r.id = "xss-001".to_string();
            r
        };

        let score = engine.calculate_score(&[&rule1, &rule2]);

        assert_eq!(score.contributions.len(), 2);
        assert!(score.attack_types.contains(&"sqli".to_string()));
        assert!(score.attack_types.contains(&"xss".to_string()));
    }
}
