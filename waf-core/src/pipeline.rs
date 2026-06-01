//! Request Pipeline
//!
//! Processes incoming requests through WAF components.
//!
//! ## Pipeline Stages
//!
//! 1. **Context Building**: Extract request info (IP, headers, body)
//! 2. **Rate Limit Check**: Check rate limits, reject if exceeded
//! 3. **Bot Detection**: Analyze fingerprint, decide challenge/block
//! 4. **Rule Evaluation**: Run all rules, collect matches
//! 5. **Decision**: Allow, block, or challenge based on results
//! 6. **Logging**: Log attack info if blocked
//! 7. **Forward**: Forward to upstream if allowed
//!
//! ## Error Handling
//!
//! - Rate limit exceeded: Return 429 Too Many Requests
//! - Bot detected: Return 403 with challenge page if configured
//! - Rule match: Return 403 with block message
//! - Upstream error: Return 502 Bad Gateway

use axum::{body::Body, extract::Request, response::Response};
use http::{HeaderMap, StatusCode};
use std::sync::Arc;

use waf_common::*;
use crate::AppState;

/// Process incoming request through WAF pipeline
pub async fn process_request(
    state: AppState,
    mut request: Request<Body>,
) -> Result<Response<Body>, WafError> {
    let client_ip = extract_client_ip_from_request(&request, &state.config.waf.trusted_proxies);
    
    tracing::debug!("Processing request from {}: {} {}", 
        client_ip, 
        request.method(), 
        request.uri()
    );

    // Build request context
    let ctx = build_request_context(&mut request, client_ip).await?;

    // Check threat feeds (fast path - block known malicious IPs early)
    if let Some(ref threat_feeds) = state.threat_feeds {
        let client_ip_addr: std::net::IpAddr = ctx.client_ip.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
        if threat_feeds.is_blocked(&client_ip_addr).await {
            tracing::warn!(
                target: "threat_feed",
                client_ip = %ctx.client_ip,
                "Blocked request from known malicious IP"
            );
            return Ok(create_block_response(
                StatusCode::FORBIDDEN,
                "Access denied: known malicious source",
            ));
        }
    }

    // Check rate limit
    let rate_limit_result = state.rate_limiter.check(&ctx.client_ip).await?;
    if rate_limit_result.exceeded {
        tracing::warn!("Rate limit exceeded for {}", ctx.client_ip);
        return Ok(create_block_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded. Please try again later.",
        ));
    }

    // Bot detection
    let bot_result = state.bot_detector.detect(&ctx);
    if bot_result.is_bot {
        tracing::warn!("Bot detected from {}: score={}", ctx.client_ip, bot_result.score);
        state.bot_detector.update_ip_reputation(&ctx.client_ip, true);
        
        if let Action::Block { status_code, body, reason } = bot_result.recommended_action {
            tracing::info!("Blocking bot: {} - {}", ctx.client_ip, reason);
            return Ok(create_block_response(StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN), &body));
        }
    }

    // WAF rule evaluation
    let eval_result = state.rule_matcher.evaluate(&ctx);
    
    if !eval_result.allowed {
        let matched = &eval_result.matched_rules;
        if !matched.is_empty() {
            tracing::warn!(
                "Request blocked from {}: {} - {:?}",
                ctx.client_ip,
                eval_result.request_id,
                matched.iter().map(|r| &r.name).collect::<Vec<_>>()
            );

            // Log attack
            for rule in matched {
                log_attack(&ctx, rule);
            }
        }

        let action = &eval_result.action;
        if let Action::Block { status_code, body, .. } = action {
            return Ok(create_block_response(
                StatusCode::from_u16(*status_code).unwrap_or(StatusCode::FORBIDDEN),
                body,
            ));
        }
    }

    // Log allowed request (with attack info if any)
    if !eval_result.matched_rules.is_empty() {
        tracing::info!(
            "Allowed request with {} matches from {}: {}",
            eval_result.matched_rules.len(),
            ctx.client_ip,
            eval_result.request_id
        );
    }

    // Forward request to upstream
    let upstream_response = forward_to_upstream(&state, request, &ctx).await?;

    Ok(upstream_response)
}

/// Extract client IP from request
fn extract_client_ip_from_request(request: &Request<Body>, trusted_proxies: &[String]) -> String {
    let headers = request.headers();
    
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    if let Some(x_real_ip) = headers.get("x-real-ip") {
        if let Ok(ip) = x_real_ip.to_str() {
            return ip.trim().to_string();
        }
    }

    // Fallback to remote address
    "127.0.0.1".to_string()
}

/// Build request context from HTTP request
async fn build_request_context(
    request: &mut Request<Body>,
    client_ip: String,
) -> Result<RequestContext, WafError> {
    let method = HttpMethod::from(request.method().as_str());
    let uri = request.uri().path().to_string();
    let query_string = request.uri().query().unwrap_or("").to_string();
    
    let mut headers = Vec::new();
    for (key, value) in request.headers().iter() {
        if let Ok(v) = value.to_str() {
            headers.push((key.to_string(), v.to_string()));
        }
    }

    let content_type = request.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = hyper::body::to_bytes(request.body_mut()).await.ok();
    let body_vec = body.map(|b| b.to_vec());

    Ok(RequestContext {
        id: uuid::Uuid::new_v4().to_string(),
        method,
        uri,
        query_string,
        headers,
        client_ip,
        body: body_vec,
        content_type,
        timestamp: chrono::Utc::now(),
        tls: None,
        rate_limit_info: None,
    })
}

/// Create a block response
fn create_block_response(status: StatusCode, body: &str) -> Response<Body> {
    let body = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>{}</title></head>
<body>
    <h1>Access Denied</h1>
    <p>{}</p>
    <hr>
    <small>WAF Protected</small>
</body>
</html>"#,
        status.as_u16(),
        body
    );

    Response::builder()
        .status(status)
        .header("Content-Type", "text/html")
        .header("X-Frame-Options", "DENY")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(body))
        .unwrap()
}

/// Forward request to upstream server
async fn forward_to_upstream(
    state: &AppState,
    mut request: Request<Body>,
    _ctx: &RequestContext,
) -> Result<Response<Body>, WafError> {
    let upstream_addr = &state.config.waf.upstream_addr;
    
    // Build upstream URI
    let upstream_uri = format!("http://{}{}", upstream_addr, request.uri());
    
    let client = hyper_util::client::legacy::Client::builder(
        tokio::net::TcpStream::connect(upstream_addr).await?,
    ).build_http();

    // Create new request to upstream
    let (parts, body) = request.into_parts();
    let upstream_request = Request::builder()
        .method(parts.method)
        .uri(upstream_uri)
        .extension(parts.extensions)
        .body(body)
        .map_err(|e| WafError::Upstream(format!("Failed to build request: {}", e)))?;

    let response = client
        .request(upstream_request)
        .await
        .map_err(|e| WafError::Upstream(format!("Upstream request failed: {}", e)))?;

    Ok(response.map(Body::new))
}

/// Log an attack
fn log_attack(ctx: &RequestContext, rule: &Rule) {
    tracing::warn!(
        target: "attack",
        request_id = %ctx.id,
        client_ip = %ctx.client_ip,
        method = %ctx.method.as_str(),
        uri = %ctx.uri,
        rule_id = %rule.id,
        rule_name = %rule.name,
        severity = ?rule.severity,
        "Attack detected"
    );
}