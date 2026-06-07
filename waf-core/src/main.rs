//! WAF Core - HTTP Proxy Server
//!
//! Main entry point for the WAF proxy server.
//!
//! ## Startup Process
//!
//! 1. Initialize logging with tracing-subscriber
//! 2. Load configuration from YAML file
//! 3. Initialize rule loader and load rules
//! 4. Initialize rate limiter (in-memory or Redis)
//! 5. Initialize bot detector
//! 6. Start metrics server (port 9090)
//! 7. Start WAF server (port 8080)
//!
//! ## Configuration
//!
//! Configuration is loaded from `config/waf.yaml` by default.
//! Override with `WAF_CONFIG` environment variable.

mod metrics;
mod pipeline;
mod server;
mod upstream;

use std::sync::Arc;
use waf_bot_detector::BotDetector;
use waf_common::{
    create_shared_manager, SharedAnomalyManager, ThreatFeedManager, WafConfig, WafError,
};
use waf_engine::{RuleLoader, RuleMatcher};
use waf_rate_limiter::RateLimiter;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<WafConfig>,
    pub rule_matcher: Arc<RuleMatcher>,
    pub rate_limiter: Arc<RateLimiter>,
    pub bot_detector: Arc<BotDetector>,
    pub threat_feeds: Option<Arc<ThreatFeedManager>>,
    pub anomaly_manager: SharedAnomalyManager,
    pub stats: Arc<std::sync::atomic::AtomicU64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,waf_core=debug".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting WAF Core v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path = std::env::var("WAF_CONFIG").unwrap_or_else(|_| "config/waf.yaml".to_string());
    let config = WafConfig::load_from_file(&config_path)
        .map_err(|e| format!("Failed to load config from {}: {}", config_path, e))?;

    tracing::info!(
        "Loaded config: listen={}, upstream={}",
        config.waf.listen_addr,
        config.waf.upstream_addr
    );

    // Initialize components
    let mut rule_loader = RuleLoader::new();
    rule_loader.add_file("rules/owasp-top10.yaml");
    rule_loader.add_file("rules/rate-limits.yaml");
    rule_loader.add_file("rules/bot-rules.yaml");

    let rules = rule_loader
        .load()
        .map_err(|e| format!("Failed to load rules: {}", e))?;

    tracing::info!("Loaded {} rules", rules.len());

    let rule_matcher = Arc::new(RuleMatcher::new(rules, waf_common::Severity::Medium));

    let rate_limiter_config = waf_rate_limiter::RateLimitConfig {
        algorithm: waf_rate_limiter::RateLimitAlgorithm::SlidingWindow,
        limit: config.rate_limiter.default_limit,
        window_seconds: config.rate_limiter.default_window_seconds,
        burst_size: None,
    };

    let rate_limiter = if let Some(redis_url) = &config.rate_limiter.redis_url {
        Arc::new(
            RateLimiter::with_redis(rate_limiter_config, redis_url)
                .await
                .map_err(|e| format!("Failed to connect to Redis: {}", e))?,
        )
    } else {
        Arc::new(RateLimiter::new(rate_limiter_config))
    };

    let bot_detector_config = waf_bot_detector::BotDetectorConfig {
        enabled: config.bot_detector.enabled,
        allow_known_bots: config.bot_detector.allow_search_bots,
        block_tor: config.bot_detector.block_tor,
        block_vpn: config.bot_detector.block_vpn,
        ..Default::default()
    };
    let bot_detector = Arc::new(BotDetector::new(bot_detector_config));

    let app_state = AppState {
        config: Arc::new(config),
        rule_matcher,
        rate_limiter,
        bot_detector,
        threat_feeds: None,
        anomaly_manager: create_shared_manager(),
        stats: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    };

    // Start metrics server
    tokio::spawn(async {
        metrics::start_metrics_server("127.0.0.1:9090").await;
    });

    // Start WAF server
    server::start(app_state).await?;

    Ok(())
}
