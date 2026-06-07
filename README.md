# WAF - Web Application Firewall

<div align="center">

**Self-hosted Web Application Firewall built in Rust**

[Rust](https://www.rust-lang.org/) • [Async I/O](https://tokio.rs/) • [OWASP Top 10](https://owasp.org/Top10/) • [Prometheus](https://prometheus.io/) • [Grafana](https://grafana.com/)

[![build](https://github.com/kuro-toji/waf/actions/workflows/build.yml/badge.svg)](https://github.com/kuro-toji/waf/actions/workflows/build.yml)
[![clippy](https://github.com/kuro-toji/waf/actions/workflows/lint.yml/badge.svg)](https://github.com/kuro-toji/waf/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## Overview

WAF is an open-source Web Application Firewall designed for teams who want visibility and control over their traffic filtering logic. It runs as a self-hosted reverse proxy, intercepting requests before they reach your application.

**What WAF provides:**
- Protection against OWASP Top 10 attacks (SQL injection, XSS, CSRF, path traversal, command injection, etc.)
- Configurable rule engine with YAML-based rule definitions
- Multiple rate limiting algorithms with distributed state via Redis
- Bot detection with fingerprinting and challenge mechanisms
- Prometheus metrics and Grafana dashboards for observability
- Hot reload for rules without service interruption

**What WAF is:**
- A rule-based request filter that you operate and maintain
- A Rust application optimized for high-throughput, low-latency filtering
- A solution for teams with the expertise to deploy and manage infrastructure

**What WAF is not:**
- A turnkey security solution requiring no operational expertise
- A replacement for comprehensive application security practices
- A service with SLA guarantees or vendor support

---

## Features

### Security

| Feature | Description |
|---------|-------------|
| **OWASP Top 10 Protection** | Detection rules for SQL injection, XSS, CSRF, path traversal, command injection, XXE, LFI, RFI, LDAP injection |
| **Bot Detection** | Client fingerprinting, IP reputation, JavaScript challenges, CAPTCHA integration |
| **Rate Limiting** | Token bucket, sliding window, leaky bucket algorithms; Redis-backed for distributed deployments |
| **Bypass Prevention** | Encoding detection, case normalization, null byte handling |

### Performance

| Feature | Description |
|---------|-------------|
| **Rust Runtime** | Memory-safe, zero-cost abstractions |
| **Async I/O** | Non-blocking request handling via Tokio |
| **Connection Pooling** | Keep-alive connections to upstream servers |
| **Hot Reload** | Rule updates without dropping active connections |

### Operations

| Feature | Description |
|---------|-------------|
| **Prometheus Metrics** | Request counts, latency histograms, attack detection rates |
| **Grafana Dashboards** | Pre-built dashboards for real-time monitoring |
| **Structured Logging** | JSON-formatted logs for ELK/Splunk integration |
| **Admin API** | RESTful interface for rule management and statistics |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Request                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        waf-core (Proxy)                         │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ TLS Handler │→ │ Bot Detector │→ │ Rate Limiter           │ │
│  └─────────────┘  └──────────────┘  └────────────────────────┘ │
│                         │                                      │
│                         ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┤
│  │                  waf-engine (Detection)                     │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │ │
│  │  │   SQLi  │ │   XSS   │ │  CSRF   │ │  More   │  ...      │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘            │ │
│  └─────────────────────────────────────────────────────────────┤
│                         │                                      │
│                         ▼                                      │
│                    Allow or Block                              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼ (if allowed)
┌─────────────────────────────────────────────────────────────────┐
│                      Upstream Server                           │
└─────────────────────────────────────────────────────────────────┘
```

### Module Structure

| Crate | Purpose |
|-------|---------|
| `waf-common` | Shared types, configuration structures, error handling |
| `waf-engine` | Rule matching engine and attack detectors |
| `waf-rate-limiter` | Rate limiting algorithms (token bucket, sliding window, leaky bucket) |
| `waf-bot-detector` | Client fingerprinting, reputation database, challenge system |
| `waf-core` | HTTP proxy server with TLS termination |
| `waf-admin` | REST API for management operations |
| `waf-dashboard` | React-based admin dashboard |

---

## Quick Start

### Docker Compose (Recommended)

```bash
git clone https://github.com/kuro-toji/waf.git
cd waf

# Start WAF with Prometheus, Grafana, and Redis
docker-compose up -d

# Verify services are running
docker-compose ps

# View WAF logs
docker-compose logs -f waf-core

# Access Grafana dashboard
open http://localhost:3000
```

### Manual Build

```bash
# Install Rust 1.75+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build release binaries
cargo build --release

# Run with configuration file
./target/release/waf-core --config config/waf.yaml
```

---

## Configuration

### Rule Definition

Rules are defined in YAML with conditions and actions:

```yaml
rules:
  - id: sqli-001
    name: "SQL Injection Detection"
    severity: critical
    match:
      type: regex
      patterns:
        - "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table)"
        - "(?i)(or\\s+1\\s*=\\s*1|and\\s+1\\s*=\\s*1|'\\s*or\\s*')"
        - "--|\\/\\*|\\*\\/"
    action: block
    reason: "SQL injection attempt detected"
```

### Global Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  upstream_url: "http://localhost:3000"

rules:
  path: "./rules"
  severity_threshold: medium

rate_limiter:
  enabled: true
  algorithm: token_bucket
  requests_per_second: 100
  burst: 200

redis:
  enabled: true
  url: "redis://localhost:6379"
```

---

## API Reference

### Management API (waf-admin)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/rules` | List all rules |
| `POST` | `/api/rules` | Create a new rule |
| `GET` | `/api/rules/{id}` | Get rule by ID |
| `PUT` | `/api/rules/{id}` | Update rule |
| `DELETE` | `/api/rules/{id}` | Delete rule |
| `GET` | `/api/stats` | Get statistics summary |
| `GET` | `/api/stats/attacks` | Get attack type breakdown |
| `GET` | `/api/logs` | Get attack logs (paginated) |
| `GET` | `/api/config` | Get current configuration |
| `PUT` | `/api/config` | Update configuration |

### Proxy Endpoints (waf-core)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/ready` | Readiness probe with stats |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/_waf_challenge` | Bot challenge page |

---

## Metrics

WAF exposes Prometheus metrics at `GET /metrics`:

```
# Request counters
waf_requests_total{status="allowed"} 12345
waf_requests_total{status="blocked"} 67

# Latency histogram
waf_latency_seconds_bucket{le="0.01"} 10000
waf_latency_seconds_bucket{le="0.1"} 12000
waf_latency_seconds_bucket{le="1"} 12500
waf_latency_seconds_bucket{le="+Inf"} 12567

# Attack detection counter
waf_attacks_total{type="sqli"} 23
waf_attacks_total{type="xss"} 15
waf_attacks_total{type="path_traversal"} 8

# Rate limiter metrics
waf_rate_limit_exceeded_total{algorithm="token_bucket"} 42
```

---

## Development

```bash
# Build all workspace crates
cargo build --release

# Run tests
cargo test --workspace

# Run linter
cargo clippy --workspace -- -D warnings

# Format code
cargo fmt --all

# Run integration tests
cargo test --test integration_tests

# Development run with debug logging
RUST_LOG=debug ./target/release/waf-core --config config/waf.yaml
```

---

## Deployment

### Kubernetes (Helm)

```bash
helm install waf ./helm/waf -n waf-system --create-namespace
```

### AWS (Terraform)

```bash
cd terraform/aws
terraform init
terraform plan
terraform apply
```

### GCP (Terraform)

```bash
cd terraform/gcp
terraform init
terraform plan
terraform apply
```

---

## Production Considerations

Before deploying WAF in production, evaluate:

1. **Rule Tuning**: Default rules may require adjustment for your application's traffic patterns
2. **Performance Testing**: Benchmark against your actual request volume and latency requirements
3. **High Availability**: Multiple WAF instances behind a load balancer with shared Redis state
4. **Monitoring**: Set up alerts for attack spikes and rate limit occurrences
5. **Logging**: Configure log rotation and storage capacity for attack logs

See [docs/PRODUCTION_CHECKLIST.md](docs/PRODUCTION_CHECKLIST.md) for deployment guidance.

---

## Documentation

| Document | Content |
|----------|---------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and component interactions |
| [ARCHITECTURE_DECISIONS.md](docs/ARCHITECTURE_DECISIONS.md) | Design decisions and tradeoffs |
| [RULES.md](docs/RULES.md) | Rule syntax and available match types |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Deployment options and configuration |
| [API.md](docs/API.md) | API endpoint reference |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |

---

## Contributing

Contributions are welcome. Please review [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, testing, and pull request process.

---

## License

MIT License. See [LICENSE](LICENSE) for full license text.
