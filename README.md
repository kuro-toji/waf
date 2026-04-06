# WAF - Web Application Firewall

<div align="center">

**Open-source enterprise-grade WAF that surpasses Cloudflare protection**

[Rust](https://www.rust-lang.org/) • [Async](https://tokio.rs/) • [OWASP Top 10](https://owasp.org/Top10/) • [Prometheus](https://prometheus.io/) • [Grafana](https://grafana.com/)

[![build](https://github.com/username/waf/actions/workflows/build.yml/badge.svg)](https://github.com/username/waf/actions/workflows/build.yml)
[![clippy](https://github.com/username/waf/actions/workflows/lint.yml/badge.svg)](https://github.com/username/waf/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## Why WAF?

Modern web applications face constant threats from attackers. Cloudflare and similar solutions work, but they:

- Lock you into their ecosystem
- Charge enterprise prices for real protection
- Don't let you see or customize detection rules
- Force you to trust their black box

**WAF changes that.** It's a fully open-source, self-hosted WAF that you control completely.

---

## Features

### Security
- **OWASP Top 10 Protection**: SQL injection, XSS, CSRF, path traversal, command injection, XXE, LDAP injection, and more
- **Bot Detection**: Fingerprinting, behavioral analysis, JavaScript challenges, CAPTCHA support
- **Rate Limiting**: Token bucket, sliding window, leaky bucket algorithms with Redis backend
- **Bypass Prevention**: Encoding detection, case manipulation, null byte injection

### Performance
- **Rust**: Memory-safe, zero-cost abstractions, native performance
- **Async I/O**: Non-blocking request handling with Tokio
- **Connection Pooling**: Keep-alive to upstream servers
- **Graceful Hot Reload**: Update rules without dropping connections

### Deployment
- **Docker Ready**: Single image or full stack with docker-compose
- **Kubernetes**: Helm chart included
- **Cloud Providers**: Terraform for AWS and GCP
- **YAML Configuration**: Human-readable rules anyone can edit

### Observability
- **Prometheus Metrics**: Request counts, latency histograms, attack detection rates
- **Grafana Dashboards**: Pre-built dashboards for real-time monitoring
- **Structured Logging**: JSON logs for easy integration with ELK/Splunk
- **Admin API**: RESTful API for rule management and statistics

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

---

## Quick Start

### Docker (Recommended)

```bash
# Clone and start
git clone https://github.com/username/waf.git
cd waf

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f waf-core

# Access dashboard
open http://localhost:3000
```

### Manual Build

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --release

# Run
./target/release/waf-core --config config/production.yaml
```

---

## Configuration

Rules are defined in human-readable YAML:

```yaml
# rules/owasp-top10.yaml
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

---

## Modules

| Crate | Purpose |
|-------|---------|
| `waf-common` | Shared types, config, error handling |
| `waf-engine` | Core rule matching and attack detection |
| `waf-rate-limiter` | Token bucket, sliding window, leaky bucket |
| `waf-bot-detector` | Fingerprinting, challenges, allowlisting |
| `waf-core` | HTTP proxy server with TLS support |
| `waf-admin` | REST API for management |
| `waf-dashboard` | React-based admin dashboard |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/rules` | List all rules |
| POST | `/api/rules` | Create new rule |
| PUT | `/api/rules/{id}` | Update rule |
| DELETE | `/api/rules/{id}` | Delete rule |
| GET | `/api/stats` | Get attack statistics |
| GET | `/api/logs` | Get attack logs |
| GET | `/metrics` | Prometheus metrics |
| GET | `/health` | Health check |

---

## Monitoring

### Prometheus Metrics

```
# HELP waf_requests_total Total requests processed
# TYPE waf_requests_total counter
waf_requests_total{status="allowed"} 12345
waf_requests_total{status="blocked"} 67

# HELP waf_latency_seconds Request latency histogram
# TYPE waf_latency_seconds histogram
waf_latency_seconds_bucket{le="0.01"} 10000
waf_latency_seconds_bucket{le="0.1"} 12000

# HELP waf_attacks_total Attacks detected by type
# TYPE waf_attacks_total counter
waf_attacks_total{type="sqli"} 23
waf_attacks_total{type="xss"} 15
```

### Grafana Dashboard

Pre-built dashboard with:
- Real-time request rate
- Attack detection breakdown
- Latency percentiles
- Top blocked IPs
- Geographic distribution

---

## Development

```bash
# Build all crates
cargo build --release

# Run tests
cargo test --all

# Run clippy lints
cargo clippy --all

# Format code
cargo fmt --all

# Run with custom config
RUST_LOG=debug ./target/release/waf-core --config config/development.yaml
```

---

## Production Deployment

### Kubernetes

```bash
helm install waf ./helm/waf -n waf-system
```

### AWS (Terraform)

```bash
cd terraform/aws
terraform init
terraform apply
```

### Configuration

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed production guidance.

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - See [LICENSE](LICENSE) for details.