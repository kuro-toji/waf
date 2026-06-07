//! Request Context Builder
//!
//! Builds request context from HTTP requests.
//!
//! ## Context Building Process
//!
//! 1. Extract method, URI, and query string
//! 2. Convert headers to key-value pairs
//! 3. Extract client IP (considering X-Forwarded-For)
//! 4. Decode request body if present
//! 5. Determine content type
//! 6. Capture TLS info if applicable
//!
//! ## Client IP Extraction
//!
//! Client IP is determined by checking in order:
//! 1. `X-Forwarded-For` header (if from trusted proxy)
//! 2. `X-Real-IP` header
//! 3. Direct connection remote address
//!
//! Only proxies in `trusted_proxies` list can set X-Forwarded-For.
//!
//! ## Usage
//!
//! ```ignore
//! use waf_engine::RequestContextBuilder;
//! use http::{Request, Body};
//!
//! let request = Request::builder()
//!     .method("POST")
//!     .uri("/api/users")
//!     .header("Content-Type", "application/json")
//!     .body(Body::from(r#"{"name":"test"}"#))
//!     .unwrap();
//!
//! let ctx = RequestContextBuilder::new(request, "192.168.1.1".to_string())
//!     .build();
//! ```

use http::Request;
use std::net::SocketAddr;
use waf_common::*;

/// Build a request context from an HTTP request
pub struct RequestContextBuilder {
    request: Request<Vec<u8>>,
    client_ip: String,
    tls_info: Option<TlsInfo>,
}

impl RequestContextBuilder {
    /// Create a new builder with the given request
    pub fn new(request: Request<Vec<u8>>, client_ip: String) -> Self {
        Self {
            request,
            client_ip,
            tls_info: None,
        }
    }

    /// Set TLS info
    pub fn with_tls_info(mut self, tls: TlsInfo) -> Self {
        self.tls_info = Some(tls);
        self
    }

    /// Build the request context
    pub fn build(self) -> RequestContext {
        let (
            http::request::Parts {
                method,
                uri,
                version: _,
                headers,
                ..
            },
            body,
        ) = self.request.into_parts();

        // Extract URI components
        let uri_str = uri.to_string();
        let (path, query_string) = uri_str.split_once('?').unwrap_or((&uri_str, ""));

        // Convert headers to vector
        let headers_vec: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        // Determine content type
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        RequestContext {
            id: uuid::Uuid::new_v4().to_string(),
            method: HttpMethod::from(method.as_str()),
            uri: path.to_string(),
            query_string: query_string.to_string(),
            headers: headers_vec,
            client_ip: self.client_ip,
            body: if body.is_empty() { None } else { Some(body) },
            content_type,
            timestamp: chrono::Utc::now(),
            tls: self.tls_info,
            rate_limit_info: None,
        }
    }
}

/// Extract client IP from request considering X-Forwarded-For header
pub fn extract_client_ip(
    remote_addr: SocketAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &[String],
) -> String {
    // Check for X-Forwarded-For header
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // X-Forwarded-For can contain multiple IPs, first is the client
            if let Some(first_ip) = xff_str.split(',').next() {
                let ip = first_ip.trim();

                // Check if we trust this proxy chain
                let client_ip = remote_addr.ip().to_string();
                if trusted_proxies.iter().any(|tp| client_ip.starts_with(tp)) {
                    return ip.to_string();
                }
            }
        }
    }

    // Fall back to direct connection IP
    remote_addr.ip().to_string()
}

/// Normalize a string for comparison (decoding, lowercasing)
pub fn normalize_string(s: &str) -> String {
    // Decode URL encoding
    let mut decoded = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            if let (Some(a), Some(b)) = (chars.next(), chars.next()) {
                let hex = format!("{}{}", a, b);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    decoded.push(byte as char);
                } else {
                    decoded.push('%');
                    decoded.push(a);
                    decoded.push(b);
                }
            }
        } else {
            decoded.push(c);
        }
    }

    // Decode plus signs to spaces
    decoded.replace('+', " ")
}

/// Normalize HTTP header name (lowercase, trim)
pub fn normalize_header_name(name: &str) -> String {
    name.to_lowercase().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_string_url_encoding() {
        let input = "hello%20world%2Ftest";
        let result = normalize_string(input);
        assert_eq!(result, "hello world/test");
    }

    #[test]
    fn test_normalize_string_plus_sign() {
        let input = "hello+world";
        let result = normalize_string(input);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_normalize_header_name() {
        let input = "Content-Type";
        let result = normalize_header_name(input);
        assert_eq!(result, "content-type");
    }
}
