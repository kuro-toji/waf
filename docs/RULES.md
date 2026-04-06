# Rule Writing Guide

## Overview

WAF rules are defined in YAML files and loaded at startup. Rules support hot reload.

## Rule Structure

```yaml
rules:
  - id: rule-001
    name: "Human-readable rule name"
    description: "Optional description"
    severity: critical  # critical, high, medium, low, info
    enabled: true
    priority: 100      # Higher = evaluated first
    tags:              # Categorization
      - sqli
      - owasp
    whitelist_ips:     # IPs that bypass this rule
      - "10.0.0.0/8"
      - "192.168.1.100"
    conditions:         # All must match (AND logic)
      - field: query
        match_type: regex
        value: "pattern"
        case_insensitive: false
    action:
      type: block      # block, allow, challenge, log
      status_code: 403
      body: "Blocked message"
      reason: "Why it was blocked"
```

## Fields

### MatchField Types

| Field | Description |
|-------|-------------|
| `uri` | Request path |
| `query` | Query string |
| `body` | Request body |
| `method` | HTTP method |
| `client_ip` | Client IP address |
| `header` | HTTP header (specify name) |
| `user_agent` | User-Agent header |
| `referer` | Referer header |
| `cookie` | Cookie value (specify name) |
| `json_body` | JSON body key (specify name) |
| `form_data` | Form field (specify name) |

### MatchType Types

| Type | Description | Example |
|------|-------------|---------|
| `regex` | Regular expression | `(?i)union.*select` |
| `exact` | Exact string match | `/admin` |
| `contains` | Substring match | `eval` |
| `starts_with` | Prefix match | `/api/` |
| `ends_with` | Suffix match | `.php` |
| `glob` | Glob pattern | `*.sql` |
| `ip_range` | CIDR notation | `192.168.0.0/16` |

## Severity Levels

| Level | Value | Usage |
|-------|-------|-------|
| `critical` | 4 | Immediate block, active exploitation |
| `high` | 3 | Block, likely malicious |
| `medium` | 2 | Challenge, could be suspicious |
| `low` | 1 | Log only, minor issues |
| `info` | 0 | Informational |

## Actions

### Block
```yaml
action:
  type: block
  status_code: 403
  body: "Access denied"
  reason: "SQL injection detected"
```

### Allow
```yaml
action:
  type: allow
```

### Challenge (Bot Detection)
```yaml
action:
  type: challenge
  challenge_type: javascript  # javascript, captcha, ratelimit
  timeout: 300              # Challenge timeout in seconds
```

### Log Only
```yaml
action:
  type: log
  level: "warn"            # trace, debug, info, warn, error
  message: "Suspicious activity"
```

## Examples

### SQL Injection Detection
```yaml
- id: sqli-001
  name: "SQL Injection Detection"
  severity: critical
  conditions:
    - field: query
      match_type: regex
      value: "(?i)(union.*select|select.*from|insert.*into)"
    - field: query
      match_type: regex
      value: "['\"].*['\"].*['\"]"
  action:
    type: block
    status_code: 403
    body: "SQL injection detected"
    reason: "SQL injection pattern match"
```

### XSS Detection
```yaml
- id: xss-001
  name: "XSS Script Tag Detection"
  severity: critical
  conditions:
    - field: query
      match_type: regex
      value: "<script[^>]*>.*?</script>"
    - field: body
      match_type: regex
      value: "javascript\\s*:"
  action:
    type: block
    status_code: 403
    body: "XSS attack detected"
    reason: "Script injection pattern"
```

### Path Traversal
```yaml
- id: path-001
  name: "Path Traversal Detection"
  severity: high
  conditions:
    - field: uri
      match_type: regex
      value: "\\.\\.\\/"
    - field: query
      match_type: regex
      value: "\\.\\.[\\\\/]"
  action:
    type: block
    status_code: 403
    body: "Path traversal detected"
    reason: "Directory traversal pattern"
```

### Whitelist Example
```yaml
- id: admin-001
  name: "Admin Access"
  severity: low
  whitelist_ips:
    - "10.0.0.0/8"
    - "192.168.1.50"
  conditions:
    - field: uri
      match_type: starts_with
      value: "/admin"
  action:
    type: log
    level: "info"
    message: "Admin access from whitelisted IP"
```

## Testing Rules

1. Start WAF in verbose mode:
```bash
RUST_LOG=debug ./waf-core --config config/waf.yaml
```

2. Send test requests:
```bash
curl -i "http://localhost:8080/?id=1 UNION SELECT * FROM users"
```

3. Check logs for matches:
```json
{"level":"warn","rule_id":"sqli-001","matched_value":"UNION SELECT"}
```