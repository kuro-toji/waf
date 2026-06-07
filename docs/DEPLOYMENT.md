# Deployment Guide

## Quick Start (Docker)

```bash
# Clone the repository
git clone https://github.com/kuro-toji/waf.git
cd waf

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f waf-core

# Access services
# - WAF: http://localhost:8080
# - Admin API: http://localhost:8081
# - Prometheus: http://localhost:9091
# - Grafana: http://localhost:3000 (admin/admin)
```

## Configuration

### Basic Configuration

Edit `config/waf.yaml`:

```yaml
waf:
  listen_addr: "0.0.0.0:8080"
  upstream_addr: "127.0.0.1:8000"
  trusted_proxies:
    - "10.0.0.0/8"

rate_limiter:
  enabled: true
  default_limit: 1000
  default_window_seconds: 60
  redis_url: "redis://redis:6379"  # Optional

bot_detector:
  enabled: true
  block_tor: true
```

### Rule Configuration

Edit YAML files in `rules/` directory:

```yaml
rules:
  - id: sqli-001
    name: "SQL Injection Detection"
    severity: critical
    enabled: true
    conditions:
      - field: query
        match_type: regex
        value: "(?i)union.*select"
        case_insensitive: true
    action:
      type: block
      status_code: 403
      body: "Attack detected"
      reason: "SQL injection attempt"
```

## Production Deployment

### Kubernetes

1. Build Docker image:
```bash
docker build -t myregistry/waf:latest .
docker push myregistry/waf:latest
```

2. Install Helm chart:
```bash
helm install waf ./helm/waf \
  --set image.repository=myregistry/waf \
  --set image.tag=latest \
  --set redis.enabled=true
```

3. Configure via ConfigMap:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-config
data:
  waf.yaml: |
    waf:
      listen_addr: "0.0.0.0:8080"
      upstream_addr: "backend-service:8000"
```

### AWS (Terraform)

```bash
cd terraform/aws
terraform init
terraform plan
terraform apply
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Logging level | `info` |
| `WAF_CONFIG` | Config file path | `config/waf.yaml` |
| `WAF_RULES_DIR` | Rules directory | `rules/` |

## Monitoring

### Prometheus Metrics

Access at `http://localhost:9090/metrics`:

```
# HELP waf_requests_total Total requests processed
# TYPE waf_requests_total counter
waf_requests_total{status="allowed"} 12345

# HELP waf_latency_seconds Request latency histogram
# TYPE waf_latency_seconds histogram
waf_latency_seconds_bucket{le="0.01"} 10000

# HELP waf_attacks_total Attacks detected by type
# TYPE waf_attacks_total counter
waf_attacks_total{type="sqli"} 23
```

### Grafana Dashboard

Import `grafana/dashboards/waf-overview.json` into Grafana.

### Log Analysis

Logs are in JSON format for easy parsing:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "warn",
  "client_ip": "192.168.1.1",
  "method": "GET",
  "uri": "/api/users",
  "rule_id": "sqli-001",
  "attack_type": "sql_injection"
}
```

## Troubleshooting

### High Latency
- Check upstream server response times
- Reduce logging verbosity
- Enable connection pooling

### False Positives
- Review matched rules in logs
- Adjust severity thresholds
- Add whitelists for legitimate traffic

### Rate Limiting Issues
- Ensure Redis is reachable (if using distributed mode)
- Check rate limit configurations
- Verify trusted proxies list

## Performance Tuning

1. **Connection Pooling**: Increase `max_connections` in config
2. **Keep-Alive**: Adjust `keep_alive_timeout` for persistent connections
3. **Body Size**: Limit `max_body_size` to reduce memory usage
4. **Rule Optimization**: Use specific patterns instead of broad ones