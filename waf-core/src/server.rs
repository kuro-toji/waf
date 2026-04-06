//! HTTP Server
//!
//! Axum-based HTTP server for WAF.
//!
//! ## Request Flow
//!
//! 1. Request arrives at WAF core
//! 2. TLS termination (if enabled)
//! 3. Bot detection check
//! 4. Rate limiting check
//! 5. WAF rule evaluation
//! 6. Allow/block/challenge decision
//! 7. Forward to upstream (if allowed)
//!
//! ## Endpoints
//!
//! - `GET /health` - Health check (always allowed)
//! - `GET /ready` - Readiness check with stats
//! - `GET /metrics` - Prometheus metrics
//! - `GET /_waf_challenge` - Bot challenge page
//! - `* /**` - Proxy to upstream (with WAF processing)

use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
    middleware::{self, Next},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::{pipeline::process_request, AppState};

/// Create the main router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .route("/_waf_challenge", get(challenge_handler).post(challenge_handler))
        .route("/", get(proxy_handler).post(proxy_handler))
        .route("/*path", get(proxy_handler).post(proxy_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Health check handler
async fn health_handler() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("OK"))
        .unwrap()
}

/// Readiness check handler
async fn ready_handler(State(state): State<AppState>) -> Response<Body> {
    let stats = state.stats.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!(r#"{{"ready":true,"requests_processed":{}}}"#, stats);
    
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(body))
        .unwrap()
}

/// Prometheus metrics handler
async fn metrics_handler() -> Response<Body> {
    let metrics_text = crate::metrics::gather_metrics();
    
    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4")
        .status(StatusCode::OK)
        .body(Body::from(metrics_text))
        .unwrap()
}

/// Challenge handler (for bot challenges)
async fn challenge_handler(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response<Body> {
    // Extract challenge response and validate
    let uri = request.uri();
    let query = uri.query().unwrap_or("");
    
    if query.contains("solve=") {
        // This is a challenge solution
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("Challenge solved"))
            .unwrap()
    } else {
        // Show challenge page
        let challenge_html = state.bot_detector.generate_challenge(&waf_common::RequestContext {
            id: "challenge".to_string(),
            method: waf_common::HttpMethod::Get,
            uri: uri.path().to_string(),
            query_string: String::new(),
            headers: vec![],
            client_ip: "0.0.0.0".to_string(),
            body: None,
            content_type: None,
            timestamp: chrono::Utc::now(),
            tls: None,
            rate_limit_info: None,
        });
        
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Body::from(challenge_html))
            .unwrap()
    }
}

/// Main proxy handler
async fn proxy_handler(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response<Body> {
    state.stats.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    
    match process_request(state, request).await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("Request processing error: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap()
        }
    }
}

/// Start the server
pub async fn start(state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    let addr = state.config.waf.listen_addr.parse()?;
    
    tracing::info!("WAF listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let router = create_router(state);
    
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Wait for shutdown signal
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
    tracing::info!("Shutting down...");
}