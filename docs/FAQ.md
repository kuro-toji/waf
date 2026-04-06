# WAF FAQ

## General

### What is WAF?

WAF (Web Application Firewall) is a security system that filters and monitors HTTP traffic between a web application and the Internet. It protects against attacks like SQL injection, XSS, and other OWASP Top 10 vulnerabilities.

### How is WAF different from a traditional firewall?

Traditional firewalls operate at network layers 3-4 (TCP/IP), while WAF operates at layer 7 (application layer). WAF understands HTTP/S traffic and can inspect request content for attack patterns.

### Why build another WAF when Cloudflare exists?

Cloudflare and similar services:
- Lock you into their ecosystem
- Charge enterprise prices for real protection
- Don't let you see or customize detection rules
- Force you to trust their black box

WAF is fully open-source, self-hosted, and you control everything.

## Installation

### What are the system requirements?

- Docker or native Rust toolchain
- 512MB RAM minimum (1GB recommended)
- x86_64 or ARM64 CPU
- Linux/macOS/Windows (with Docker)

### How do I install WAF?

**Docker (Recommended):**
```bash
git clone https://github.com/username/waf.git
cd waf
docker-compose up -d
```

**Native:**
```bash
cargo build --release
./target/release/waf-core --config config/waf.yaml
```

## Configuration

### How do I add custom rules?

Edit YAML files in `rules/` directory:

```yaml
rules:
  - id: custom-001
    name: "My Custom Rule"
    severity: high
    conditions:
      - field: query
        match_type: regex
        value: "suspicious_pattern"
    action:
      type: block
      status_code: 403
      body: "Blocked"
      reason: "Custom rule matched"
```

### How does hot reload work?

Rules are automatically reloaded when YAML files change. The watcher checks every 2 seconds.

### How do I whitelist an IP?

Add to rule's `whitelist_ips` or configure in `config/waf.yaml`:
```yaml
waf:
  trusted_proxies:
    - "10.0.0.0/8"
```

## Performance

### How many requests can WAF handle?

Single instance: ~100,000 requests/sec with 50 rules.
With Redis: Linear scaling with cluster size.

### What's the latency impact?

~1-2ms added latency for typical requests. Health checks add <0.1ms.

### Does WAF support clustering?

Yes, with Redis backend for shared rate limiting state.

## Troubleshooting

### Requests are being blocked that shouldn't be

1. Check logs for matched rule: `docker-compose logs waf-core`
2. Lower severity threshold in config: `min_severity_to_block: "high"`
3. Add whitelists for legitimate traffic patterns

### Rate limiting not working

1. Verify Redis connection: `redis-cli ping`
2. Check `redis_url` in config matches your Redis instance
3. Ensure firewall allows WAF to reach Redis

### Bot challenges not displaying

1. Verify JavaScript is enabled in user's browser
2. Check `challenge_timeout` setting
3. Ensure `/metrics` doesn't get challenged (add to whitelist)

## Security

### Can WAF be bypassed?

No security system is 100% foolproof. WAF reduces risk but must be part of defense-in-depth:
- Keep software and rules updated
- Follow secure coding practices
- Regular penetration testing
- Monitor logs for new attack patterns

### Does WAF handle HTTPS?

Yes, but TLS termination is performed at WAF. Upstream should either:
1. Be on private network (HTTP acceptable)
2. Also terminate TLS (double encryption)

### How does WAF handle encrypted traffic?

If TLS is terminated at WAF, traffic is decrypted for inspection. For end-to-end encryption, consider:
- WAF as transparent proxy (limited inspection)
- Application-level encryption inspection (complex)