//! XXE Detector
//!
//! Detects XML External Entity injection attacks.
//!
//! ## What is XXE?
//!
//! XML External Entity (XXE) attacks exploit XML parsers that process
//! external entities referenced in XML documents. Attackers can:
//! - Read local files (/etc/passwd)
//! - Perform SSRF attacks
//! - Cause denial of service
//!
//! ## Detection Patterns
//!
//! 1. **DOCTYPE declarations**: `<!DOCTYPE ...>`
//! 2. **ENTITY declarations**: `<!ENTITY ...>`
//! 3. **External entity reference**: `SYSTEM "..."`
//! 4. **PUBLIC external ID**: `PUBLIC "..."`
//! 5. **File scheme**: `file://...`
//! 6. **PHP wrappers**: `php://...`, `expect://...`
//!
//! ## Confidence Scoring
//!
//! - 0.95: PHP wrapper or expect:// URI
//! - 0.90: External entity with PUBLIC/SYSTEM
//! - 0.85: ENTITY declaration
//! - 0.80: File scheme in entity
//! - 0.70: DOCTYPE declaration in XML content
//!
//! ## Use Cases
//!
//! - XML API protection
//! - SOAP service protection
//! - File read via XXE
//! - SSRF via XXE
//!
//! ## Usage
//!
//! ```rust
//! use waf_engine::detectors::XxeDetector;
//!
//! let detector = XxeDetector::new();
//! let xml = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
//! let result = detector.detect(xml);
//! if result.detected {
//!     println!("XXE detected: {}", result.pattern);
//! }
//! ```

use regex::Regex;

/// XXE detection result
#[derive(Debug, Clone)]
pub struct XxeResult {
    pub detected: bool,
    pub pattern: String,
    pub matched_value: String,
    pub confidence: f32,
}

/// XXE Detector
pub struct XxeDetector {
    patterns: Vec<(Regex, &'static str, f32)>,
}

impl XxeDetector {
    /// Create a new XXE detector
    pub fn new() -> Self {
        let patterns = vec![
            // More specific patterns first so they aren't shadowed by
            // the generic DOCTYPE / ENTITY matches below.
            // PHP wrapper
            (
                Regex::new(r"(?i)(php://|expect://|ogg://)").unwrap(),
                "php_wrapper",
                0.95,
            ),
            // External entity reference
            (
                Regex::new(r#"(?i)SYSTEM\s+['"]"#).unwrap(),
                "external_entity_system",
                0.95,
            ),
            // PUBLIC external ID
            (
                Regex::new(r#"(?i)PUBLIC\s+['"]"#).unwrap(),
                "external_entity_public",
                0.9,
            ),
            // ENTITY declaration
            (
                Regex::new(r"(?i)<!ENTITY\s+[^>]*>").unwrap(),
                "entity_declaration",
                0.85,
            ),
            // DOCTYPE declaration
            (
                Regex::new(r"(?i)<!DOCTYPE\s+[^>]*>").unwrap(),
                "doctype",
                0.7,
            ),
            // File scheme in entity
            (Regex::new(r"(?i)file\s*://").unwrap(), "file_scheme", 0.8),
            // HTTP scheme in entity
            (Regex::new(r"(?i)http\s*://").unwrap(), "http_scheme", 0.7),
            // Parameter entity
            (
                Regex::new(r"(?i)%[a-zA-Z]+;").unwrap(),
                "parameter_entity",
                0.6,
            ),
            // CDATA section (sometimes used in XXE)
            (Regex::new(r"(?i)<!\[CDATA\[").unwrap(), "cdata", 0.5),
        ];

        Self { patterns }
    }

    /// Detect XXE in input
    pub fn detect(&self, input: &str) -> XxeResult {
        for (regex, pattern_name, confidence) in &self.patterns {
            if let Some(m) = regex.find(input) {
                return XxeResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                };
            }
        }

        XxeResult {
            detected: false,
            pattern: String::new(),
            matched_value: String::new(),
            confidence: 0.0,
        }
    }

    /// Check if content looks like XML
    pub fn is_xml(&self, input: &str) -> bool {
        let trimmed = input.trim();
        trimmed.starts_with("<?xml") || trimmed.starts_with("<") && trimmed.contains(">")
    }
}

impl Default for XxeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doctype_detection() {
        let detector = XxeDetector::new();

        let result = detector.detect("<!DOCTYPE foo [<!ENTITY bar 'baz'>]>");
        assert!(result.detected);
        assert_eq!(result.pattern, "entity_declaration");
    }

    #[test]
    fn test_external_entity_detection() {
        let detector = XxeDetector::new();

        let result = detector.detect(r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#);
        assert!(result.detected);
        assert_eq!(result.pattern, "external_entity_system");
    }

    #[test]
    fn test_php_wrapper_detection() {
        let detector = XxeDetector::new();

        let result = detector.detect(
            r#"<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">"#,
        );
        assert!(result.detected);
        assert_eq!(result.pattern, "php_wrapper");
    }
}
