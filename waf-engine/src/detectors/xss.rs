//! XSS Detector
//!
//! Detects Cross-Site Scripting attacks using pattern matching and context analysis.
//!
//! ## XSS Contexts
//!
//! The detector identifies where the XSS payload might execute:
//! - **Html**: Inside HTML tags
//! - **Attribute**: Within HTML attribute values
//! - **Javascript**: Inside `<script>` blocks
//! - **Css**: Within style properties
//! - **Url**: In URL parameters
//!
//! ## Detection Patterns
//!
//! 1. **Script Tags**: Direct `<script>` injection
//! 2. **Event Handlers**: `onerror`, `onclick`, etc.
//! 3. **JavaScript URI**: `javascript:` in href/src
//! 4. **CSS Expression**: `expression()` in IE
//! 5. **Encoded XSS**: HTML entities, URL encoding
//! 6. **SVG/XML Based**: `<svg>`, `<xml>` tags
//!
//! ## Context-Aware Detection
//!
//! Different contexts require different detection strategies:
//! - `<script>` tags: Detect nested script attempts
//! - Event handlers: Detect `on*=attack` patterns
//! - URLs: Detect `javascript:` pseudo-protocol
//! - CSS: Detect `expression()`, `url(javascript:)`
//!
//! ## Usage
//!
//! ```rust
//! use waf_engine::detectors::XssDetector;
//!
//! let detector = XssDetector::new();
//! let result = detector.detect("<script>alert(1)</script>");
//! if result.detected {
//!     println!("XSS detected: {}", result.pattern);
//! }
//! ```

use regex::Regex;
use waf_common::*;

/// XSS detection result
#[derive(Debug, Clone)]
pub struct XssResult {
    pub detected: bool,
    pub pattern: String,
    pub matched_value: String,
    pub confidence: f32,
    pub context: XssContext,
}

/// XSS attack context
#[derive(Debug, Clone, PartialEq)]
pub enum XssContext {
    /// HTML context (inside tags)
    Html,
    /// Attribute context (inside quotes)
    Attribute,
    /// JavaScript context (inside script tags)
    Javascript,
    /// CSS context (inside style)
    Css,
    /// URL context
    Url,
    /// Unknown context
    Unknown,
}

/// XSS Detector
pub struct XssDetector {
    /// Script tag patterns
    script_patterns: Vec<(Regex, &'static str, f32)>,
    /// Event handler patterns
    event_handlers: Vec<(Regex, &'static str, f32)>,
    /// Attribute patterns
    attribute_patterns: Vec<(Regex, &'static str, f32)>,
}

impl XssDetector {
    /// Create a new XSS detector
    pub fn new() -> Self {
        let script_patterns = vec![
            // Script tag injection
            (
                Regex::new(r"(?i)<script[^>]*>.*?</script>").unwrap(),
                "script_tag",
                0.95,
            ),
            // Script tag with src
            (
                Regex::new(r"(?i)<script[^>]+src[^>]*>").unwrap(),
                "script_src",
                0.9,
            ),
            // Script tag with data URI
            (
                Regex::new(r"(?i)javascript\s*:").unwrap(),
                "javascript_uri",
                0.95,
            ),
            // VBScript URI
            (
                Regex::new(r"(?i)vbscript\s*:").unwrap(),
                "vbscript_uri",
                0.9,
            ),
        ];

        let event_handlers = vec![
            // Common event handlers
            (
                Regex::new(r"(?i)\bon\w+\s*=").unwrap(),
                "event_handler",
                0.85,
            ),
            // Specific high-risk event handlers
            (
                Regex::new(r"(?i)\bon(error|load|click|mouse\w+|key\w+|focus|blur|submit)\s*=")
                    .unwrap(),
                "high_risk_event",
                0.9,
            ),
            // Expression in CSS
            (
                Regex::new(r"(?i)expression\s*\(").unwrap(),
                "css_expression",
                0.95,
            ),
            // URL with javascript
            (
                Regex::new(r"(?i)url\s*\(\s*javascript\s*:").unwrap(),
                "css_url_js",
                0.95,
            ),
        ];

        let attribute_patterns = vec![
            // Style with expression
            (
                Regex::new(r"(?i)style\s*=.*expression").unwrap(),
                "style_expression",
                0.9,
            ),
            // href with javascript
            (
                Regex::new(r#"(?i)href\s*=\s*['"]?\s*javascript\s*:"#).unwrap(),
                "xss_href_js",
                0.9,
            ),
            // src=javascript:
            (
                Regex::new(r#"(?i)src\s*=\s*['"]?\s*javascript\s*:"#).unwrap(),
                "src_js",
                0.95,
            ),
            // data URI with script
            (
                Regex::new(r"(?i)data\s*:\s*text/html\s*,").unwrap(),
                "data_html",
                0.85,
            ),
            // meta refresh with javascript
            (
                Regex::new(r#"(?i)http-equiv\s*=\s*['"]?refresh['"]?[^>]*url\s*="#).unwrap(),
                "meta_refresh",
                0.8,
            ),
            // SVG/XML based XSS
            (Regex::new(r"(?i)<svg[^>]*>").unwrap(), "svg_tag", 0.75),
            (Regex::new(r"(?i)<xml[^>]*>").unwrap(), "xml_tag", 0.6),
        ];

        Self {
            script_patterns,
            event_handlers,
            attribute_patterns,
        }
    }

    /// Detect XSS in input string
    pub fn detect(&self, input: &str) -> XssResult {
        // Check script patterns
        for (regex, pattern_name, confidence) in &self.script_patterns {
            if let Some(m) = regex.find(input) {
                return XssResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                    context: self.determine_context(input, m.start()),
                };
            }
        }

        // Check event handlers
        for (regex, pattern_name, confidence) in &self.event_handlers {
            if let Some(m) = regex.find(input) {
                return XssResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                    context: self.determine_context(input, m.start()),
                };
            }
        }

        // Check attribute patterns
        for (regex, pattern_name, confidence) in &self.attribute_patterns {
            if let Some(m) = regex.find(input) {
                return XssResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                    context: self.determine_context(input, m.start()),
                };
            }
        }

        // Check for encoded XSS
        if self.check_encoded_xss(input) {
            return XssResult {
                detected: true,
                pattern: "encoded_xss".to_string(),
                matched_value: input.to_string(),
                confidence: 0.75,
                context: XssContext::Unknown,
            };
        }

        XssResult {
            detected: false,
            pattern: String::new(),
            matched_value: String::new(),
            confidence: 0.0,
            context: XssContext::Unknown,
        }
    }

    /// Determine the XSS context
    fn determine_context(&self, input: &str, match_start: usize) -> XssContext {
        let before = &input[..match_start];

        // Check what's before the match
        if before.contains("<script") || before.contains("javascript:") {
            XssContext::Javascript
        } else if before.contains("<style") || before.contains("style=") {
            XssContext::Css
        } else if before.contains("<svg") || before.contains("<xml") || before.contains("<") {
            XssContext::Html
        } else if before.contains("=") || before.contains("on") {
            XssContext::Attribute
        } else if before.contains("url(") || before.contains("href") {
            XssContext::Url
        } else {
            XssContext::Unknown
        }
    }

    /// Check for encoded XSS patterns
    fn check_encoded_xss(&self, input: &str) -> bool {
        // Check for HTML entities
        let html_entities = Regex::new(r"&#x?[0-9a-f]+;").unwrap();
        if html_entities.find(input).is_some() {
            // Check if it resolves to script-related content
            if input.to_lowercase().contains("script") || input.to_lowercase().contains("onerror") {
                return true;
            }
        }

        // Check for URL encoded script tags
        let url_encoded_script = Regex::new(r"%3cscript|%3Cscript|%3cscript").unwrap();
        if url_encoded_script.find(input).is_some() {
            return true;
        }

        // Check for mixed encoding
        let mixed_encoding = Regex::new(r"%3c[^>]*%3e").unwrap();
        if mixed_encoding.find(input).is_some() {
            return true;
        }

        false
    }

    /// Check for reflected XSS in URL parameters
    pub fn check_reflected(&self, url: &str, param_value: &str) -> bool {
        // Check if the param value appears in the URL (reflected)
        if url.contains(param_value) && !param_value.is_empty() {
            // Check if there's XSS patterns in the reflected value
            let result = self.detect(param_value);
            return result.detected;
        }
        false
    }
}

impl Default for XssDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_tag_detection() {
        let detector = XssDetector::new();

        let result = detector.detect("<script>alert('xss')</script>");
        assert!(result.detected);
        assert_eq!(result.pattern, "script_tag");
        assert_eq!(result.context, XssContext::Html);
    }

    #[test]
    fn test_event_handler_detection() {
        let detector = XssDetector::new();

        let result = detector.detect("<img onerror=alert(1)>");
        assert!(result.detected);
        assert_eq!(result.pattern, "high_risk_event");
    }

    #[test]
    fn test_javascript_uri_detection() {
        let detector = XssDetector::new();

        let result = detector.detect("javascript:alert('xss')");
        assert!(result.detected);
        assert_eq!(result.pattern, "javascript_uri");
    }

    #[test]
    fn test_href_js_detection() {
        let detector = XssDetector::new();

        let result = detector.detect("href='javascript:alert(1)'");
        assert!(result.detected);
        assert_eq!(result.pattern, "href_js");
    }

    #[test]
    fn test_encoded_xss_detection() {
        let detector = XssDetector::new();

        let result = detector.detect("&#60;script&#62;alert(1)&#60;/script&#62;");
        assert!(result.detected);
        assert_eq!(result.pattern, "encoded_xss");
    }

    #[test]
    fn test_normal_input() {
        let detector = XssDetector::new();

        let result = detector.detect("Hello, this is normal text!");
        assert!(!result.detected);
    }

    #[test]
    fn test_reflected_xss() {
        let detector = XssDetector::new();

        let url = "/search?q=<script>alert(1)</script>";
        let param_value = "<script>alert(1)</script>";
        assert!(detector.check_reflected(url, param_value));
    }
}
