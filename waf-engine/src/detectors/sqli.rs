//! SQL Injection Detector
//!
//! Detects SQL injection attacks using multiple detection strategies.
//!
//! ## Detection Techniques
//!
//! 1. **Pattern Match**: Regex-based detection of known SQLi patterns
//! 2. **Keyword Analysis**: Detects high density of SQL keywords
//! 3. **Syntax Anomaly**: Detects quote/bracket mismatches
//! 4. **Time-based Blind**: Detects sleep/benchmark patterns
//! 5. **Union-based**: Detects UNION SELECT patterns
//!
//! ## Confidence Scoring
//!
//! Each detection returns a confidence score (0.0-1.0):
//! - >= 0.9: High confidence, block immediately
//! - >= 0.7: Medium confidence, consider block
//! - >= 0.5: Low confidence, log and optionally challenge
//!
//! ## False Positive Mitigation
//!
//! - Quote anomaly detection may trigger on legitimate SQL in search
//! - Use severity thresholds to filter low-confidence detections
//! - Consider application context (e.g., admin interfaces)
//!
//! ## Usage
//!
//! ```rust
//! use waf_engine::detectors::SqlInjectionDetector;
//!
//! let detector = SqlInjectionDetector::new();
//! let result = detector.detect("' OR '1'='1");
//! if result.detected {
//!     println!("SQL injection detected: {}", result.pattern);
//! }
//! ```

use regex::Regex;

/// SQL Injection detection result
#[derive(Debug, Clone)]
pub struct SqlInjectionResult {
    /// Whether SQL injection was detected
    pub detected: bool,
    /// The matched pattern
    pub pattern: String,
    /// Matched value
    pub matched_value: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Detection technique used
    pub technique: SqlInjectionTechnique,
}

/// SQL injection detection technique
#[derive(Debug, Clone)]
pub enum SqlInjectionTechnique {
    /// Pattern-based detection
    PatternMatch,
    /// SQL keyword analysis
    KeywordAnalysis,
    /// Syntax anomaly detection
    SyntaxAnomaly,
    /// Time-based blind detection
    TimeBasedBlind,
    /// Union-based detection
    UnionBased,
}

/// SQL Injection Detector
pub struct SqlInjectionDetector {
    /// Regex patterns for detection
    patterns: Vec<(Regex, &'static str, f32)>,
    /// SQL keywords to detect
    sql_keywords: Vec<&'static str>,
}

impl SqlInjectionDetector {
    /// Create a new SQL injection detector
    pub fn new() -> Self {
        let patterns = vec![
            // Union-based SQL injection
            (
                Regex::new(r"(?i)\bunion\s+(all\s+)?select\b").unwrap(),
                "union_select",
                0.9,
            ),
            // Comment-based injection
            (Regex::new(r"(?i)--|/\*|\*/").unwrap(), "sql_comment", 0.7),
            // OR-based injection (tautology)
            (
                Regex::new(r#"(?i)\b(or|and)\s+["']?\w+["']?\s*(=|>|<)\s*["']?\w+["']?"#).unwrap(),
                "or_condition",
                0.85,
            ),
            // Stacked queries
            (
                Regex::new(r"(?i);\s*(drop|delete|insert|update|exec|execute)\b").unwrap(),
                "stacked_query",
                0.95,
            ),
            // UNION SELECT with column count enumeration
            (
                Regex::new(r"(?i)union\s+select\s+\d+\s*(,\s*\d+)+").unwrap(),
                "union_enum",
                0.9,
            ),
            // Hex-encoded injection
            (Regex::new(r"0x[0-9a-f]+").unwrap(), "hex_encoding", 0.6),
            // SLEEP/BENCHMARK (time-based blind)
            (
                Regex::new(r"(?i)\b(sleep|benchmark|waitfor|pg_sleep)\s*\(").unwrap(),
                "time_blind",
                0.95,
            ),
            // Information schema access
            (
                Regex::new(r"(?i)(information_schema|mysql\.database|pg_catalog|sysobjects)")
                    .unwrap(),
                "info_schema",
                0.85,
            ),
            // String termination attacks
            (
                Regex::new(r#"['"].*['"].*['"]"#).unwrap(),
                "string_termination",
                0.5,
            ),
        ];

        let sql_keywords = vec![
            "select",
            "insert",
            "update",
            "delete",
            "drop",
            "create",
            "alter",
            "exec",
            "execute",
            "union",
            "where",
            "from",
            "table",
            "database",
            "schema",
            "having",
            "group by",
            "order by",
            "limit",
            "offset",
            "join",
            "inner join",
            "left join",
            "right join",
            "outer join",
            "in",
            "not in",
            "between",
        ];

        Self {
            patterns,
            sql_keywords,
        }
    }

    /// Detect SQL injection in a string
    pub fn detect(&self, input: &str) -> SqlInjectionResult {
        // Check patterns first (fast path)
        for (regex, pattern_name, confidence) in &self.patterns {
            if let Some(m) = regex.find(input) {
                return SqlInjectionResult {
                    detected: true,
                    pattern: pattern_name.to_string(),
                    matched_value: m.as_str().to_string(),
                    confidence: *confidence,
                    technique: SqlInjectionTechnique::PatternMatch,
                };
            }
        }

        // Check for SQL keyword density
        let keyword_count = self.count_sql_keywords(input);
        let word_count = input.split_whitespace().count();

        if word_count > 0 {
            let density = keyword_count as f32 / word_count as f32;
            if density > 0.3 && keyword_count >= 2 {
                return SqlInjectionResult {
                    detected: true,
                    pattern: "high_keyword_density".to_string(),
                    matched_value: input.to_string(),
                    confidence: 0.7,
                    technique: SqlInjectionTechnique::KeywordAnalysis,
                };
            }
        }

        // Check for quote patterns that indicate injection
        if self.detect_quote_anomaly(input) {
            return SqlInjectionResult {
                detected: true,
                pattern: "quote_anomaly".to_string(),
                matched_value: input.to_string(),
                confidence: 0.65,
                technique: SqlInjectionTechnique::SyntaxAnomaly,
            };
        }

        SqlInjectionResult {
            detected: false,
            pattern: String::new(),
            matched_value: String::new(),
            confidence: 0.0,
            technique: SqlInjectionTechnique::PatternMatch,
        }
    }

    /// Detect SQL injection in a query string (special handling for key=value pairs)
    pub fn detect_in_query(&self, query: &str) -> Vec<SqlInjectionResult> {
        let mut results = Vec::new();

        for pair in query.split('&') {
            if let Some((_key, value)) = pair.split_once('=') {
                // URL decode the value
                let decoded = decode_url(value);

                // Check for SQL injection patterns
                let result = self.detect(&decoded);
                if result.detected {
                    results.push(result);
                }
            }
        }

        results
    }

    /// Count SQL keywords in input
    fn count_sql_keywords(&self, input: &str) -> usize {
        let input_lower = input.to_lowercase();
        self.sql_keywords
            .iter()
            .filter(|kw| input_lower.contains(*kw))
            .count()
    }

    /// Detect quote syntax anomalies
    fn detect_quote_anomaly(&self, input: &str) -> bool {
        let mut single_quotes = 0;
        let mut double_quotes = 0;
        let mut backticks = 0;
        let mut escaped = false;

        for c in input.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            match c {
                '\\' => escaped = true,
                '\'' => single_quotes += 1,
                '"' => double_quotes += 1,
                '`' => backticks += 1,
                _ => {}
            }
        }

        // Unmatched quotes indicate potential injection
        (single_quotes % 2 != 0 && single_quotes > 0)
            || (double_quotes % 2 != 0 && double_quotes > 0)
            || (backticks % 2 != 0 && backticks > 0)
    }
}

impl Default for SqlInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// URL decode a string
fn decode_url(s: &str) -> String {
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

    #[test]
    fn test_union_select_detection() {
        let detector = SqlInjectionDetector::new();

        let result = detector.detect("1 UNION SELECT username, password FROM users");
        assert!(result.detected);
        assert_eq!(result.pattern, "union_select");
    }

    #[test]
    fn test_or_tautology_detection() {
        let detector = SqlInjectionDetector::new();

        let result = detector.detect("id=1 OR 1=1");
        assert!(result.detected);
        assert_eq!(result.pattern, "or_condition");
    }

    #[test]
    fn test_stacked_query_detection() {
        let detector = SqlInjectionDetector::new();

        let result = detector.detect("1; DROP TABLE users");
        assert!(result.detected);
        assert_eq!(result.pattern, "stacked_query");
    }

    #[test]
    fn test_time_based_blind_detection() {
        let detector = SqlInjectionDetector::new();

        let result = detector.detect("1 AND SLEEP(5)");
        assert!(result.detected);
        assert_eq!(result.pattern, "time_blind");
    }

    #[test]
    fn test_normal_input() {
        let detector = SqlInjectionDetector::new();

        let result = detector.detect("hello world");
        assert!(!result.detected);
    }

    #[test]
    fn test_quote_anomaly_detection() {
        let detector = SqlInjectionDetector::new();

        // Odd number of quotes is suspicious
        let result = detector.detect("name='test");
        assert!(result.detected);
        assert_eq!(result.pattern, "quote_anomaly");
    }

    #[test]
    fn test_query_detection() {
        let detector = SqlInjectionDetector::new();

        let results = detector.detect_in_query("id=1 UNION SELECT * FROM users&name=test");
        assert!(!results.is_empty());
    }
}
