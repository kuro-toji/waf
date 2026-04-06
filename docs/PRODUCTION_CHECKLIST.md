# Production Readiness Checklist

## Pre-Deployment

### Security
- [ ] TLS configured with valid certificates
- [ ] Admin API behind authentication
- [ ] Trusted proxies configured (no IP spoofing)
- [ ] Secrets stored securely (not in config files)
- [ ] Rate limiting enabled
- [ ] Bot detection enabled

### Performance
- [ ] Load tested at expected traffic levels
- [ ] Memory usage acceptable
- [ ] Latency within SLA (< 10ms p99)
- [ ] Connection pooling configured

### Reliability
- [ ] Health checks passing
- [ ] Upstream servers healthy
- [ ] Redis cluster stable (if using distributed mode)
- [ ] Logs being collected
- [ ] Metrics being collected

## Configuration

### Essential Settings
```yaml
waf:
  listen_addr: "0.0.0.0:8080"
  upstream_addr: "backend:8000"
  trusted_proxies:
    - "10.0.0.0/8"
  min_severity_to_block: "medium"
  
rate_limiter:
  enabled: true
  default_limit: 1000
  default_window_seconds: 60
  
bot_detector:
  enabled: true
  block_tor: true
  allow_search_bots: true
  
logging:
  level: "warn"
  format: "json"
```

### Network
- [ ] WAF accessible on port 8080 (HTTP)
- [ ] Admin API on port 8081 (localhost only or protected)
- [ ] Metrics on port 9090
- [ ] Upstream backend accessible

## Monitoring

### Metrics to Watch
- `waf_requests_total` - Request volume
- `waf_requests_blocked_total` - Block rate
- `waf_request_latency_seconds` - Latency percentiles
- `waf_rate_limit_exceeded_total` - Rate limit hits
- `waf_bots_detected_total` - Bot activity

### Alerts
- [ ] Block rate > 10% for 5 minutes
- [ ] Latency p99 > 100ms
- [ ] Error rate > 1%
- [ ] Memory usage > 80%

## Testing

### Smoke Tests
```bash
# Health check
curl -f http://localhost:8080/health

# Metrics
curl -f http://localhost:9090/metrics

# Block test
curl -i "http://localhost:8080/?id=1 UNION SELECT"

# Allow test  
curl -i "http://localhost:8080/api/users"
```

### Load Test
```bash
# Generate 1000 requests
for i in {1..1000}; do
  curl -s -o /dev/null http://localhost:8080/
done
```