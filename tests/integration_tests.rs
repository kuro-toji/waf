# WAF Integration Tests

use std::time::Duration;

#[tokio::test]
async fn test_health_endpoint() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://localhost:8080/health")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_sql_injection_blocked() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://localhost:8080/?id=1 UNION SELECT * FROM users")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    // Should be blocked with 403
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_xss_blocked() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://localhost:8080/?q=<script>alert(1)</script>")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_normal_request_allowed() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://localhost:8080/api/users")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_path_traversal_blocked() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://localhost:8080/static/../../../etc/passwd")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_rate_limit() {
    let client = reqwest::Client::new();
    let mut blocked_count = 0;

    // Send many requests
    for _ in 0..100 {
        let resp = client
            .get("http://localhost:8080/")
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            blocked_count += 1;
        }
    }

    // Should hit rate limit
    assert!(blocked_count > 0, "Rate limiting not working");
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://localhost:9090/metrics")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    
    let body = resp.text().await.unwrap();
    assert!(body.contains("waf_requests_total"));
}