//! LDAP Injection Detector
//!
//! Detects LDAP injection attacks.
//!
//! ## What is LDAP Injection?
//!
//! LDAP injection exploits applications that construct LDAP queries
//! from user input. Attackers can:
//! - Bypass authentication
//! - Discover sensitive information
//! - Modify LDAP tree structure
//!
//! ## Detection Patterns
//!
//! 1. **Wildcard abuse**: `*` in filters
//! 2. **Parentheses injection**: `(uid=*)`
//! 3. **Hex encoding**: `\x00`, `\2a` for asterisk
//! 4. **Attribute manipulation**: `uid=admin)(password=test`
//!
//! ## Dangerous Patterns
//!
//! - `*` alone or in filter context
//! - `(attribute=* )`
//! - Nested parentheses `(|(...)(...))`
//! - Empty values that might bypass validation
//!
//! ## Confidence Scoring
//!
//! - 0.85: Parentheses injection
//! - 0.80: Attribute manipulation
//! - 0.75: Hex encoding
//! - 0.70: Wildcard in filter

use regex::Regex;
use waf_common::*;

/// LDAP injection detection result
#[derive(Debug, Clone)]
pub struct LdapInjectionResult {
    pub detected: bool,
    pub pattern: String,
    pub matched_value: String,
    pub confidence: f32,
}

/// LDAP Injection Detector
pub struct LdapInjectionDetector {
    patterns: Vec<(Regex, &'static str, f32)>,
}

impl LdapInjectionDetector {
    /// Create a new LDAP injection detector
    pub fn new() -> Self {
        let patterns = vec![
            // ASTERISK wildcard
            (Regex::new(r"\*").unwrap(), "asterisk_wildcard", 0.7),
            // Hex encoding (common LDAP bypass)
            (
                Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap(),
                "hex_encoding",
                0.75,
            ),
            // Parentheses injection
            (
                Regex::new(r"\([^(]*\)").unwrap(),
                "parentheses_injection",
                0.85,
            ),
            // NULL character
            (Regex::new(r"\x00").unwrap(), "null_byte", 0.8),
            // Equals bypass patterns
            (
                Regex::new(r"(?i)(uid|sn|cn|ou|dc)=[^&]+").unwrap(),
                "attribute_injection",
                0.8,
            ),
            // LDAP meta-characters
            (Regex::new(r"[\(\)=\*,\x00]").unwrap(), "ldap_metachar", 0.7),
        ];

        Self { patterns }
    }

    /// Detect LDAP injection in input
    pub fn detect(&self, input: &str) -> LdapInjectionResult {
        for (regex, pattern_name, confidence) in &self.patterns {
            if let Some(m) = regex.find(input) {
                return LdapInjectionResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                };
            }
        }

        // Check for attribute manipulation
        if self.detect_attribute_manipulation(input) {
            return LdapInjectionResult {
                detected: true,
                pattern: "attribute_manipulation".to_string(),
                matched_value: input.to_string(),
                confidence: 0.8,
            };
        }

        LdapInjectionResult {
            detected: false,
            pattern: String::new(),
            matched_value: String::new(),
            confidence: 0.0,
        }
    }

    /// Detect attribute manipulation patterns
    fn detect_attribute_manipulation(&self, input: &str) -> bool {
        // Check for injection after equals sign
        if let Some(eq_pos) = input.find('=') {
            let after_eq = &input[eq_pos + 1..];
            // Check for wildcard or special chars after =
            if after_eq.contains('*') || after_eq.contains('(') || after_eq.contains(')') {
                return true;
            }
        }
        false
    }
}

impl Default for LdapInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_detection() {
        let detector = LdapInjectionDetector::new();

        let result = detector.detect("(uid=*)");
        assert!(result.detected);
        assert_eq!(result.pattern, "asterisk_wildcard");
    }

    #[test]
    fn test_parentheses_injection() {
        let detector = LdapInjectionDetector::new();

        let result = detector.detect("uid=admin)(password=test");
        assert!(result.detected);
    }
}
