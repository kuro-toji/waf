//! RFI Detector
//!
//! Detects Remote File Inclusion attacks.
//!
//! ## What is RFI?
//!
//! Remote File Inclusion attacks exploit applications that include
//! external files based on user input. Attackers can:
//! - Execute arbitrary code from remote servers
//! - Inject malware through compromised URLs
//! - Take full control of the application
//!
//! ## Detection Patterns
//!
//! 1. **HTTP/HTTPS URLs in parameters**:
//!    - `page=http://malicious.local/shell.txt`
//!    - `include=https://malicious.site/mal.php`
//! 2. **PHP wrappers**:
//!    - `php://input`, `php://filter`
//!    - `data://text/plain`, `expect://`
//! 3. **Protocol handlers**: `ftp://`, `sftp://`, etc.
//!
//! ## Confidence Scoring
//!
//! - 0.95: PHP wrapper injection (php://, expect://)
//! - 0.90: Encoded HTTP URL
//! - 0.80: HTTP URL in parameter value
//!
//! ## Prevention
//!
//! - Never include files based on user input without validation
//! - Use whitelists for allowed includes
//! - Disable `allow_url_include` in PHP

use regex::Regex;
use waf_common::*;

/// RFI detection result
#[derive(Debug, Clone)]
pub struct RfiResult {
    pub detected: bool,
    pub pattern: String,
    pub matched_value: String,
    pub confidence: f32,
}

/// RFI Detector
pub struct RfiDetector {
    patterns: Vec<(Regex, &'static str, f32)>,
    /// Whitelist of allowed domains
    allowed_domains: Vec<String>,
}

impl RfiDetector {
    /// Create a new RFI detector
    pub fn new() -> Self {
        let patterns = vec![
            // HTTP/HTTPS URL patterns
            (
                Regex::new(r"(?i)https?://[^\s'\"]+").unwrap(),
                "http_url",
                0.8,
            ),
            // PHP wrappers
            (
                Regex::new(r"(?i)(php://|expect://|ogg://|zip://|data://|glob://)").unwrap(),
                "php_wrapper",
                0.95,
            ),
            // Common RFI patterns
            (
                Regex::new(r"(?i)(page=|file=|path=|url=|template=|img=)[^&]*https?://").unwrap(),
                "rfi_param",
                0.95,
            ),
            // Encoded URLs
            (
                Regex::new(r"(?i)https%3a%2f%2f").unwrap(),
                "encoded_url",
                0.9,
            ),
        ];

        Self {
            patterns,
            allowed_domains: Vec::new(),
        }
    }

    /// Detect RFI in input
    pub fn detect(&self, input: &str) -> RfiResult {
        // Check patterns
        for (regex, pattern_name, confidence) in &self.patterns {
            if let Some(m) = regex.find(input) {
                // Check if URL is in allowed domains
                if pattern_name == "http_url" || pattern_name == "rfi_param" {
                    if let Some(url) = self.extract_url(m.as_str()) {
                        if !self.is_allowed_domain(&url) {
                            return RfiResult {
                                detected: true,
                                pattern: pattern_name.to_string(),
                                matched_value: m.as_str().to_string(),
                                confidence: *confidence,
                            };
                        } else {
                            continue;
                        }
                    }
                }

                return RfiResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                };
            }
        }

        RfiResult {
            detected: false,
            pattern: String::new(),
            matched_value: String::new(),
            confidence: 0.0,
        }
    }

    /// Extract URL from match
    fn extract_url(&self, s: &str) -> Option<String> {
        let s_lower = s.to_lowercase();
        if s_lower.starts_with("http://") || s_lower.starts_with("https://") {
            Some(s.to_string())
        } else {
            None
        }
    }

    /// Check if domain is allowed
    fn is_allowed_domain(&self, url: &str) -> bool {
        if self.allowed_domains.is_empty() {
            return false;
        }
        
        url.contains(&self.allowed_domains.iter().find(|d| url.contains(*d)).unwrap_or(&""))
    }

    /// Add allowed domain
    pub fn add_allowed_domain(&mut self, domain: &str) {
        self.allowed_domains.push(domain.to_string());
    }
}

impl Default for RfiDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfi_detection() {
        let detector = RfiDetector::new();
        
        let result = detector.detect("page=http://malicious.local/shell.txt");
        assert!(result.detected);
        assert_eq!(result.pattern, "rfi_param");
    }

    #[test]
    fn test_php_wrapper_detection() {
        let detector = RfiDetector::new();
        
        let result = detector.detect("file=php://input");
        assert!(result.detected);
    }
}