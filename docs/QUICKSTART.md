# Quick Start Guide

Get WAF running in 5 minutes.

## Option 1: Docker (Recommended)

```bash
# Clone and start
git clone https://github.com/username/waf.git
cd waf

# Start all services
docker-compose up -d

# Test it's working
curl http://localhost:8080/health
# Should return: OK

# Test attack detection
curl -i "http://localhost:8080/?id=1 UNION SELECT"
# Should return 403 Forbidden

# View logs
docker-compose logs -f waf-core
```

## Option 2: Native Installation

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build WAF
cargo build --release

# Run
./target/release/waf-core --config config/waf.yaml

# In another terminal, test
curl http://localhost:8080/health
```

## What's Running?

| Service | URL | Purpose |
|---------|-----|---------|
| WAF Core | http://localhost:8080 | Main proxy with attack detection |
| Admin API | http://localhost:8081 | REST API for management |
| Prometheus | http://localhost:9091 | Metrics collection |
| Grafana | http://localhost:3000 | Dashboards (admin/admin) |
| Redis | localhost:6379 | Rate limiting storage |

## Verify Protection

Test these attacks - they should all be blocked:

```bash
# SQL Injection
curl "http://localhost:8080/?id=1' OR '1'='1"
# Expected: 403 Forbidden

# XSS
curl "http://localhost:8080/?q=<script>alert(1)</script>"
# Expected: 403 Forbidden

# Path Traversal
curl "http://localhost:8080/?file=../../etc/passwd"
# Expected: 403 Forbidden

# Command Injection
curl "http://localhost:8080/?cmd=|nc -e /bin/bash 127.0.0.1 4444"
# Expected: 403 Forbidden
```

## Next Steps

1. **Read the docs**: `docs/ARCHITECTURE.md`
2. **Configure rules**: `rules/owasp-top10.yaml`
3. **Set up monitoring**: http://localhost:3000 (admin/admin)
4. **Read API docs**: `docs/API.md`

## Common Commands

```bash
# View all logs
docker-compose logs -f

# Restart WAF
docker-compose restart waf-core

# Update rules (auto-reloads)
# Just edit rules/*.yaml and save

# Check metrics
curl http://localhost:9090/metrics

# View blocked attacks
curl http://localhost:8081/api/logs | jq
```

## Troubleshooting

**Port already in use?**
```bash
# Find what's using port 8080
lsof -i :8080

# Change WAF port in config/waf.yaml
```

**Not blocking attacks?**
```bash
# Check rules are loaded
curl http://localhost:8081/api/rules | jq 'length'

# Check logs
docker-compose logs waf-core | grep -i block
```

**Need help?**
- Check `docs/FAQ.md`
- Check `docs/TROUBLESHOOTING.md`
- Open an issue on GitHub