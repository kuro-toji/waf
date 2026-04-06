//! Admin API Handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::{AppState, Stats};

#[derive(Debug, Serialize)]
pub struct RuleResponse {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub enabled: bool,
    pub action: String,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub block_rate: f64,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// List all rules
pub async fn list_rules(
    State(state): State<AppState>,
) -> Json<Vec<waf_common::Rule>> {
    let rules = state.rules.read().unwrap();
    Json(rules.clone())
}

/// Get a single rule
pub async fn get_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<waf_common::Rule>, StatusCode> {
    let rules = state.rules.read().unwrap();
    rules.iter()
        .find(|r| r.id == id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Create a new rule
pub async fn create_rule(
    State(state): State<AppState>,
    Json(rule): Json<waf_common::Rule>,
) -> Json<waf_common::Rule> {
    let mut rules = state.rules.write().unwrap();
    rules.push(rule.clone());
    Json(rule)
}

/// Update a rule
pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(rule): Json<waf_common::Rule>,
) -> Result<Json<waf_common::Rule>, StatusCode> {
    let mut rules = state.rules.write().unwrap();
    if let Some(existing) = rules.iter_mut().find(|r| r.id == id) {
        *existing = rule;
        Ok(Json(existing.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Delete a rule
pub async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    let mut rules = state.rules.write().unwrap();
    let len_before = rules.len();
    rules.retain(|r| r.id != id);
    if rules.len() < len_before {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// Get overall statistics
pub async fn get_stats(
    State(state): State<AppState>,
) -> Json<StatsResponse> {
    let stats = state.stats.lock().unwrap();
    let total = stats.total_requests;
    let blocked = stats.blocked_requests;
    let block_rate = if total > 0 {
        blocked as f64 / total as f64
    } else {
        0.0
    };

    Json(StatsResponse {
        total_requests: total,
        blocked_requests: blocked,
        allowed_requests: stats.allowed_requests,
        block_rate,
    })
}

/// Get attack statistics by type
pub async fn get_attack_stats(
    State(state): State<AppState>,
) -> Json<HashMap<String, u64>> {
    let stats = state.stats.lock().unwrap();
    Json(stats.attacks_by_type.clone())
}

/// Get traffic statistics
pub async fn get_traffic_stats(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let stats = state.stats.lock().unwrap();
    
    Json(serde_json::json!({
        "requests_per_minute": 100, // Placeholder
        "bytes_transferred": 1024000, // Placeholder
        "avg_latency_ms": 5.2, // Placeholder
    }))
}

/// Get attack logs
pub async fn get_logs(
    State(_state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Json<Vec<serde_json::Value>> {
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100);
    
    // Placeholder logs
    let logs: Vec<serde_json::Value> = (0..10)
        .map(|i| serde_json::json!({
            "id": format!("log-{}", i),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "client_ip": "192.168.1.1",
            "attack_type": "sqli",
            "severity": "high"
        }))
        .collect();

    Json(logs.into_iter().skip(offset).take(limit).collect())
}

/// Get configuration
pub async fn get_config(
    State(state): State<AppState>,
) -> Json<waf_common::WafConfig> {
    let config = state.config.read().unwrap();
    Json(config.clone())
}

/// Update configuration
pub async fn update_config(
    State(state): State<AppState>,
    Json(config): Json<waf_common::WafConfig>,
) -> Json<waf_common::WafConfig> {
    let mut current = state.config.write().unwrap();
    *current = config.clone();
    Json(config)
}

/// Health check
pub async fn health() -> &'static str {
    "OK"
}