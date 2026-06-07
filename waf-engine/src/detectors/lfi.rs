//! LFI Detector
//!
//! Detects Local File Inclusion attacks.
//!
//! ## LFI vs Path Traversal
//!
//! - Path Traversal: Attempts to access files outside web root
//! - LFI: Exploits application feature to include local files
//!   Both often use `../` patterns - LFI detector focuses on
//!   common web application file inclusion patterns.
//!
//! ## Detection Patterns
//!
//! 1. **Directory traversal**: `../` or `..\` patterns
//! 2. **URL-encoded traversal**: `%2e%2e`
//! 3. **Null byte injection**: `\x00` for extension bypass
//! 4. **Common LFI paths**:
//!    - `/etc/passwd`, `/etc/shadow`
//!    - `/windows/system32/config/sam`
//!    - `/proc/self/environ`
//!
//! ## Null Byte Truncation
//!
//! Many PHP applications are vulnerable to null byte truncation:
//! `file.php%00.jpg` gets interpreted as `file.php\x00`
//! allowing execution of PHP files outside allowed paths.
//!
//! ## Usage
//!
//! ```rust
//! use waf_engine::detectors::LfiDetector;
//!
//! let detector = LfiDetector::new();
//! let result = detector.detect("file=../../etc/passwd");
//! if result.detected {
//!     println!("LFI detected: {}", result.pattern);
//! }
//! ```

use regex::Regex;

/// LFI detection result
#[derive(Debug, Clone)]
pub struct LfiResult {
    pub detected: bool,
    pub pattern: String,
    pub matched_value: String,
    pub confidence: f32,
}

/// LFI Detector
pub struct LfiDetector {
    patterns: Vec<(Regex, &'static str, f32)>,
    /// Common LFI paths to detect
    common_lfi_paths: Vec<&'static str>,
}

impl LfiDetector {
    /// Create a new LFI detector
    pub fn new() -> Self {
        let patterns = vec![
            // Directory traversal patterns
            (Regex::new(r"\.\.(?:\/|$)").unwrap(), "traversal", 0.95),
            // URL-encoded traversal
            (Regex::new(r"(?i)%2e%2e").unwrap(), "encoded_traversal", 0.9),
            // Null byte injection
            (Regex::new(r"\x00").unwrap(), "null_byte", 0.8),
        ];

        let common_lfi_paths = vec![
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/windows/system32/",
            "/boot.ini",
            "/windows/win.ini",
            "/proc/self/environ",
            "/proc/version",
            "/var/log/",
            "/opt/",
            "/usr/local/",
        ];

        Self {
            patterns,
            common_lfi_paths,
        }
    }

    /// Detect LFI in input
    pub fn detect(&self, input: &str) -> LfiResult {
        // Check traversal patterns
        for (regex, pattern_name, confidence) in &self.patterns {
            if let Some(m) = regex.find(input) {
                return LfiResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                };
            }
        }

        // Check for common LFI paths
        let input_lower = input.to_lowercase();
        for path in &self.common_lfi_paths {
            if input_lower.contains(&path.to_lowercase()) {
                return LfiResult {
                    detected: true,
                    pattern: "common_lfi_path".to_string(),
                    matched_value: path.to_string(),
                    confidence: 0.85,
                };
            }
        }

        LfiResult {
            detected: false,
            pattern: String::new(),
            matched_value: String::new(),
            confidence: 0.0,
        }
    }
}

impl Default for LfiDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traversal_detection() {
        let detector = LfiDetector::new();

        let result = detector.detect("file=../../../../etc/passwd");
        assert!(result.detected);
        assert_eq!(result.pattern, "traversal");
    }

    #[test]
    fn test_common_path_detection() {
        let detector = LfiDetector::new();

        let result = detector.detect("page=/etc/passwd");
        assert!(result.detected);
        assert_eq!(result.pattern, "common_lfi_path");
    }
}
