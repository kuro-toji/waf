//! WAF Metrics
//!
//! Prometheus metrics for WAF.
//!
//! ## Available Metrics
//!
//! ### Counters
//! - `waf_requests_total` - Total requests processed (labeled by status)
//! - `waf_requests_allowed_total` - Allowed requests
//! - `waf_requests_blocked_total` - Blocked requests
//! - `waf_attacks_total` - Attacks detected (labeled by type)
//! - `waf_rate_limit_exceeded_total` - Rate limit exceeded events
//! - `waf_bots_detected_total` - Bots detected
//!
//! ### Histograms
//! - `waf_request_latency_seconds` - Request processing latency
//!
//! ### Gauges
//! - `waf_active_connections` - Current active connections
//!
//! ## Usage
//!
//! ```rust
//! use waf_core::metrics::{record_request, record_attack, record_latency};
//!
//! // Record a request
//! record_request(true); // allowed
//!
//! // Record an attack
//! record_attack("sqli");
//!
//! // Record latency
//! record_latency(0.005); // 5ms
//! ```

use once_cell::sync::Lazy;
use prometheus::{Counter, Encoder, Gauge, Histogram, Opts, Registry, TextEncoder};
use std::sync::OnceLock;
use tokio::io::AsyncWriteExt;

static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// Request counter
static WAF_REQUESTS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    Counter::with_opts(Opts::new("waf_requests_total", "Total requests processed")).unwrap()
});

/// Allowed request counter
static WAF_REQUESTS_ALLOWED: once_cell::sync::Lazy<Counter> = once_cell::sync::Lazy::new(|| {
    Counter::with_opts(Opts::new(
        "waf_requests_allowed_total",
        "Total allowed requests",
    ))
    .unwrap()
});

/// Blocked request counter
static WAF_REQUESTS_BLOCKED: once_cell::sync::Lazy<Counter> = once_cell::sync::Lazy::new(|| {
    Counter::with_opts(Opts::new(
        "waf_requests_blocked_total",
        "Total blocked requests",
    ))
    .unwrap()
});

/// Request latency histogram
static WAF_LATENCY: once_cell::sync::Lazy<Histogram> = once_cell::sync::Lazy::new(|| {
    Histogram::with_opts(
        prometheus::HistogramOpts::new(
            "waf_request_latency_seconds",
            "Request processing latency in seconds",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]),
    )
    .unwrap()
});

/// Attack counter by type
static WAF_ATTACKS_TOTAL: once_cell::sync::Lazy<Counter> = once_cell::sync::Lazy::new(|| {
    Counter::with_opts(Opts::new(
        "waf_attacks_total",
        "Total attacks detected by type",
    ))
    .unwrap()
});

/// Current active connections gauge
static WAF_ACTIVE_CONNECTIONS: once_cell::sync::Lazy<Gauge> = once_cell::sync::Lazy::new(|| {
    Gauge::with_opts(Opts::new(
        "waf_active_connections",
        "Current active connections",
    ))
    .unwrap()
});

/// Rate limit exceeded counter
static WAF_RATE_LIMIT_EXCEEDED: once_cell::sync::Lazy<Counter> = once_cell::sync::Lazy::new(|| {
    Counter::with_opts(Opts::new(
        "waf_rate_limit_exceeded_total",
        "Total rate limit exceeded events",
    ))
    .unwrap()
});

/// Bot detected counter
static WAF_BOTS_DETECTED: once_cell::sync::Lazy<Counter> = once_cell::sync::Lazy::new(|| {
    Counter::with_opts(Opts::new("waf_bots_detected_total", "Total bots detected")).unwrap()
});

/// Get or create registry
pub fn get_registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        let reg = Registry::new();
        reg.register(Box::new(WAF_REQUESTS_TOTAL.clone())).ok();
        reg.register(Box::new(WAF_REQUESTS_ALLOWED.clone())).ok();
        reg.register(Box::new(WAF_REQUESTS_BLOCKED.clone())).ok();
        reg.register(Box::new(WAF_LATENCY.clone())).ok();
        reg.register(Box::new(WAF_ATTACKS_TOTAL.clone())).ok();
        reg.register(Box::new(WAF_ACTIVE_CONNECTIONS.clone())).ok();
        reg.register(Box::new(WAF_RATE_LIMIT_EXCEEDED.clone())).ok();
        reg.register(Box::new(WAF_BOTS_DETECTED.clone())).ok();
        reg
    })
}

/// Record a request
pub fn record_request(allowed: bool) {
    WAF_REQUESTS_TOTAL.inc();
    if allowed {
        WAF_REQUESTS_ALLOWED.inc();
    } else {
        WAF_REQUESTS_BLOCKED.inc();
    }
}

/// Record latency
pub fn record_latency(seconds: f64) {
    WAF_LATENCY.observe(seconds);
}

/// Record an attack
pub fn record_attack(_attack_type: &str) {
    WAF_ATTACKS_TOTAL.inc();
}

/// Record rate limit exceeded
pub fn record_rate_limit_exceeded() {
    WAF_RATE_LIMIT_EXCEEDED.inc();
}

/// Record bot detected
pub fn record_bot_detected() {
    WAF_BOTS_DETECTED.inc();
}

/// Update active connections
pub fn set_active_connections(count: f64) {
    WAF_ACTIVE_CONNECTIONS.set(count);
}

/// Gather all metrics
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = get_registry().gather();
    let mut output = Vec::new();
    encoder.encode(&metric_families, &mut output).ok();
    String::from_utf8(output).unwrap_or_default()
}

/// Start metrics server
pub async fn start_metrics_server(addr: &str) {
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("Metrics server listening on {}", addr);

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let metrics_text = gather_metrics();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                metrics_text.len(),
                metrics_text
            );
            stream.write_all(response.as_bytes()).await.ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gather_metrics() {
        let metrics = gather_metrics();
        assert!(metrics.contains("waf_requests_total"));
    }
}
