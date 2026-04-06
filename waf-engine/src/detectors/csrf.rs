//! CSRF Detector
//!
//! Detects Cross-Site Request Forgery attacks using header validation.
//!
//! ## What is CSRF?
//!
//! CSRF tricks authenticated users into submitting unintended requests.
//! The browser automatically includes cookies, making the request appear legitimate.
//!
//! ## Detection Methods
//!
//! 1. **Origin Header Validation**: Check `Origin` header against whitelist
//! 2. **Referer Header Validation**: Check `Referer` header against whitelist
//! 3. **Strict Mode**: Require one of these headers on state-changing requests
//!
//! ## Header-Based Detection
//!
//! - Origin header: Set by browser, more reliable than Referer
//! - Referer header: May be stripped by privacy extensions
//! - Both are automatically included in same-origin requests
//!
//! ## Configuration
//!
//! - `trusted_origins`: List of allowed origins
//! - `strict_mode`: Require header on POST/PUT/DELETE/PATCH
//!
//! ## Limitations
//!
//! CSRF tokens provide stronger protection but require application changes.
//! Header-based detection is a WAF-layer solution that works without app changes.

use waf_common::*;

/// CSRF detection result
#[derive(Debug, Clone)]
pub struct CsrfResult {
    pub detected: bool,
    pub reason: String,
    pub confidence: f32,
}

/// CSRF Detector
pub struct CsrfDetector {
    /// Trusted origins for CSRF validation
    trusted_origins: Vec<String>,
    /// Enable strict origin checking
    strict_mode: bool,
}

impl CsrfDetector {
    /// Create a new CSRF detector
    pub fn new(trusted_origins: Vec<String>) -> Self {
        Self {
            trusted_origins,
            strict_mode: true,
        }
    }

    /// Detect CSRF attack in request
    pub fn detect(&self, ctx: &RequestContext) -> CsrfResult {
        // Check Origin header
        if let Some(origin) = ctx.get_header("origin") {
            if !self.is_trusted_origin(origin) {
                return CsrfResult {
                    detected: true,
                    reason: format!("Untrusted Origin header: {}", origin),
                    confidence: 0.9,
                };
            }
        }

        // Check Referer header
        if let Some(referer) = ctx.get_header("referer") {
            if !self.is_trusted_referer(referer) {
                return CsrfResult {
                    detected: true,
                    reason: format!("Untrusted Referer header: {}", referer),
                    confidence: 0.85,
                };
            }
        }

        // If strict mode and no Origin/Referer on POST/PUT/DELETE, flag it
        if self.strict_mode {
            match ctx.method {
                HttpMethod::Post | HttpMethod::Put | HttpMethod::Delete | HttpMethod::Patch => {
                    let has_origin = ctx.get_header("origin").is_some();
                    let has_referer = ctx.get_header("referer").is_some();

                    if !has_origin && !has_referer {
                        return CsrfResult {
                            detected: true,
                            reason: "Missing Origin/Referer header on state-changing request"
                                .to_string(),
                            confidence: 0.6,
                        };
                    }
                }
                _ => {}
            }
        }

        CsrfResult {
            detected: false,
            reason: String::new(),
            confidence: 0.0,
        }
    }

    /// Check if origin is trusted
    fn is_trusted_origin(&self, origin: &str) -> bool {
        // Remove protocol and get host
        let origin_host = origin
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');

        self.trusted_origins.iter().any(|to| {
            let to_host = to
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/');

            origin_host == to_host || origin_host.ends_with(&format!(".{}", to_host))
        })
    }

    /// Check if referer is trusted
    fn is_trusted_referer(&self, referer: &str) -> bool {
        self.is_trusted_origin(referer)
    }

    /// Enable/disable strict mode
    pub fn set_strict_mode(&mut self, enabled: bool) {
        self.strict_mode = enabled;
    }
}

impl Default for CsrfDetector {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> RequestContext {
        RequestContext {
            id: "test-123".to_string(),
            method: HttpMethod::Post,
            uri: "/api/users".to_string(),
            query_string: String::new(),
            headers: vec![
                ("Origin".to_string(), "https://yourdomain.local".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            client_ip: "192.168.1.1".to_string(),
            body: Some(b"{\"name\":\"test\"}".to_vec()),
            content_type: Some("application/json".to_string()),
            timestamp: chrono::Utc::now(),
            tls: None,
            rate_limit_info: None,
        }
    }

    #[test]
    fn test_trusted_origin() {
        let detector = CsrfDetector::new(vec!["https://yourdomain.local".to_string()]);
        let ctx = create_test_context();

        let result = detector.detect(&ctx);
        assert!(!result.detected);
    }

    #[test]
    fn test_untrusted_origin() {
        let detector = CsrfDetector::new(vec!["https://yourdomain.local".to_string()]);
        let mut ctx = create_test_context();
        ctx.headers[0].1 = "https://malicious.local".to_string();

        let result = detector.detect(&ctx);
        assert!(result.detected);
    }

    #[test]
    fn test_missing_origin_strict_mode() {
        let detector = CsrfDetector::new(vec![]);
        let mut ctx = create_test_context();
        // Remove Origin header
        ctx.headers.retain(|(k, _)| k != "Origin");

        let result = detector.detect(&ctx);
        assert!(result.detected);
    }
}
