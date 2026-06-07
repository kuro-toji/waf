//! WAF Admin API Service
//!
//! REST API for WAF management.
//!
//! ## API Endpoints
//!
//! - `GET /api/rules` - List rules
//! - `POST /api/rules` - Create rule
//! - `GET /api/rules/:id` - Get rule
//! - `PUT /api/rules/:id` - Update rule
//! - `DELETE /api/rules/:id` - Delete rule
//! - `GET /api/stats` - Get statistics
//! - `GET /api/stats/attacks` - Attack breakdown
//! - `GET /api/logs` - Attack logs
//! - `GET /api/config` - Get configuration
//! - `PUT /api/config` - Update configuration
//! - `GET /health` - Health check
//!
//! ## CORS
//!
//! CORS is enabled for all origins in development.
//! In production, configure specific allowed origins.

mod api;
mod state;

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub rules: Arc<std::sync::RwLock<Vec<waf_common::Rule>>>,
    pub stats: Arc<std::sync::Mutex<Stats>>,
    pub config: Arc<std::sync::RwLock<waf_common::WafConfig>>,
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub attacks_by_type: std::collections::HashMap<String, u64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,waf_admin=debug".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting WAF Admin API");

    let state = AppState {
        rules: Arc::new(std::sync::RwLock::new(Vec::new())),
        stats: Arc::new(std::sync::Mutex::new(Stats::default())),
        config: Arc::new(std::sync::RwLock::new(waf_common::WafConfig::default())),
    };

    let app = Router::new()
        .route("/api/rules", get(api::list_rules).post(api::create_rule))
        .route(
            "/api/rules/:id",
            get(api::get_rule)
                .put(api::update_rule)
                .delete(api::delete_rule),
        )
        .route("/api/stats", get(api::get_stats))
        .route("/api/stats/attacks", get(api::get_attack_stats))
        .route("/api/stats/traffic", get(api::get_traffic_stats))
        .route("/api/logs", get(api::get_logs))
        .route("/api/config", get(api::get_config).put(api::update_config))
        .route("/health", get(api::health))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    tracing::info!("Admin API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}
