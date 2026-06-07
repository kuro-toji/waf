//! Path Traversal Detector
//!
//! Detects directory traversal attacks.
//!
//! ## Detection Patterns
//!
//! 1. **Unix traversal**: `../` patterns in paths
//! 2. **Windows traversal**: `..\` or `../` with backslash
//! 3. **URL-encoded**: `%2e%2e` (encoded `..`)
//! 4. **Double-encoded**: `%252e%252e` (double encoded)
//! 5. **Null byte**: `\x00` for extension bypass
//! 6. **Sensitive paths**: Detection of access to sensitive files
//!
//! ## Confidence Levels
//!
//! - 0.95: Unix/Windows traversal with special chars
//! - 0.90: URL-encoded traversal
//! - 0.85: Null byte or sensitive path access
//! - 0.70: General path traversal attempt
//!
//! ## Use Cases
//!
//! - File inclusion vulnerabilities (LFI)
//! - Reading sensitive files (/etc/passwd, config files)
//! - Extension bypass attacks (file.php%00.jpg)
//!
//! ## Usage
//!
//! ```rust
//! use waf_engine::detectors::PathTraversalDetector;
//!
//! let detector = PathTraversalDetector::new();
//! let result = detector.detect("../../../etc/passwd");
//! if result.detected {
//!     println!("Path traversal: {}", result.pattern);
//! }
//! ```

use regex::Regex;

/// Path traversal detection result
#[derive(Debug, Clone)]
pub struct PathTraversalResult {
    pub detected: bool,
    pub pattern: String,
    pub matched_value: String,
    pub confidence: f32,
}

/// Path Traversal Detector
pub struct PathTraversalDetector {
    patterns: Vec<(Regex, &'static str, f32)>,
    /// Allowed base paths (whitelist)
    allowed_paths: Vec<String>,
}

impl PathTraversalDetector {
    /// Create a new path traversal detector
    pub fn new() -> Self {
        let patterns = vec![
            // Unix path traversal
            (Regex::new(r"\.\.(?:\/|$)").unwrap(), "unix_traversal", 0.95),
            // Windows path traversal
            (Regex::new(r"\.\.[\\/]").unwrap(), "windows_traversal", 0.95),
            // URL-encoded traversal
            (Regex::new(r"(?i)%2e%2e").unwrap(), "encoded_traversal", 0.9),
            // Double URL-encoded traversal
            (
                Regex::new(r"(?i)%252e%252e").unwrap(),
                "double_encoded_traversal",
                0.95,
            ),
            // Path with null byte (more specific — must come before the
            // generic null_byte pattern below).
            (
                Regex::new(r"(?i)\.(?:jpg|gif|png|pdf)\x00").unwrap(),
                "null_byte_extension",
                0.8,
            ),
            // Null byte injection
            (Regex::new(r"\x00").unwrap(), "null_byte", 0.85),
            // Common traversal patterns
            (
                Regex::new(r"(?i)(etc|passwd|shadow|windows|system32|boot\.ini)").unwrap(),
                "sensitive_path",
                0.7,
            ),
        ];

        Self {
            patterns,
            allowed_paths: vec![],
        }
    }

    /// Detect path traversal in input
    pub fn detect(&self, input: &str) -> PathTraversalResult {
        // Check patterns
        for (regex, pattern_name, confidence) in &self.patterns {
            if let Some(m) = regex.find(input) {
                return PathTraversalResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                };
            }
        }

        PathTraversalResult {
            detected: false,
            pattern: String::new(),
            matched_value: String::new(),
            confidence: 0.0,
        }
    }

    /// Add allowed path
    pub fn add_allowed_path(&mut self, path: &str) {
        self.allowed_paths.push(path.to_string());
    }

    /// Check if path is allowed (if whitelist is configured)
    pub fn is_path_allowed(&self, path: &str) -> bool {
        if self.allowed_paths.is_empty() {
            return true;
        }

        self.allowed_paths
            .iter()
            .any(|ap| path.starts_with(ap) || path == ap)
    }
}

impl Default for PathTraversalDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_traversal_detection() {
        let detector = PathTraversalDetector::new();

        let result = detector.detect("../../../etc/passwd");
        assert!(result.detected);
        assert_eq!(result.pattern, "unix_traversal");
    }

    #[test]
    fn test_windows_traversal_detection() {
        let detector = PathTraversalDetector::new();

        let result = detector.detect("..\\..\\windows\\system32\\config\\sam");
        assert!(result.detected);
        assert_eq!(result.pattern, "windows_traversal");
    }

    #[test]
    fn test_encoded_traversal_detection() {
        let detector = PathTraversalDetector::new();

        let result = detector.detect("%2e%2e%2f%2e%2e%2fetc%2fpasswd");
        assert!(result.detected);
    }

    #[test]
    fn test_null_byte_detection() {
        let detector = PathTraversalDetector::new();

        let result = detector.detect("image.jpg\x00.exe");
        assert!(result.detected);
        assert_eq!(result.pattern, "null_byte_extension");
    }

    #[test]
    fn test_normal_path() {
        let detector = PathTraversalDetector::new();

        let result = detector.detect("/images/photo.jpg");
        assert!(!result.detected);
    }
}
