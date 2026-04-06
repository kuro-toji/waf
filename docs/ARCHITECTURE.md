# Architecture

## Overview

WAF (Web Application Firewall) is a Rust-based, open-source firewall designed to protect web applications from common attacks and malicious traffic.

## Components

### waf-core
The main proxy server that intercepts HTTP requests and passes them through the WAF pipeline.

**Responsibilities:**
- HTTP request/response handling
- TLS termination
- Request routing to upstream servers
- Integration with all WAF components

### waf-engine
The core rule matching and attack detection engine.

**Responsibilities:**
- Rule loading from YAML files
- Pattern matching (regex, exact, glob, etc.)
- Multi-rule evaluation with severity thresholds
- Hot reload of rules

**Detectors:**
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Path Traversal
- Command Injection
- XXE (XML External Entity)
- LDAP Injection
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)

### waf-rate-limiter
Rate limiting with multiple algorithms.

**Algorithms:**
- Token Bucket: Allows burst traffic up to a limit
- Sliding Window: Smooth rate limiting over time windows
- Leaky Bucket: Constant rate enforcement

**Backends:**
- In-memory (single instance)
- Redis (distributed, multi-instance)

### waf-bot-detector
Bot detection through fingerprinting and challenges.

**Techniques:**
- User-Agent analysis
- Header fingerprinting
- IP reputation database (TOR, VPN, proxy detection)
- JavaScript challenges
- CAPTCHA challenges

### waf-admin
REST API for managing the WAF.

**Endpoints:**
- `/api/rules` - CRUD operations for rules
- `/api/stats` - Attack statistics
- `/api/logs` - Attack logs
- `/api/config` - Runtime configuration

### waf-dashboard
React-based admin dashboard (future).

## Request Flow

```
Client Request
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│                      waf-core                               │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ TLS Handler │→ │ Bot Detector │→ │   Rate Limiter     │ │
│  └─────────────┘  └──────────────┘  └────────────────────┘ │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────────┤
│  │                   waf-engine                            │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │
│  │  │   SQLi  │ │   XSS   │ │  CSRF   │ │  More   │  ... │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘      │
│  └─────────────────────────────────────────────────────────┤
│                         │                                   │
│                    Allow or Block                          │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼ (if allowed)
              Upstream Server
```

## Configuration

All configuration is done via YAML files:

- `config/waf.yaml` - Main WAF configuration
- `rules/owasp-top10.yaml` - OWASP Top 10 protection rules
- `rules/rate-limits.yaml` - Rate limiting configuration
- `rules/bot-rules.yaml` - Bot detection rules

## Deployment

### Docker (Recommended)
```bash
docker-compose up -d
```

### Kubernetes
```bash
helm install waf ./helm/waf
```

### Manual
```bash
cargo build --release
./target/release/waf-core --config config/waf.yaml
```