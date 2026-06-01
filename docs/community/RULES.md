# WAF Community Rules

This directory contains community-contributed rules for the WAF. Rules follow the OWASP CRS model with GitHub-based collaboration.

## Directory Structure

```
rules/
├── community/          # Community-contributed rules
│   ├── sqli/          # SQL injection detection
│   ├── xss/           # Cross-site scripting
│   ├── lfi/           # Local file inclusion
│   ├── rce/           # Remote code execution
│   ├── scanner/       # Scanner/crawler detection
│   └── other/         # Miscellaneous rules
├── experimental/      # Rules under testing
└── .meta/             # Rule metadata
```

## Rule Format

Rules are defined in YAML with the following structure:

```yaml
id: community-0001
name: "Community SQL Injection Detection"
description: |
  Detects common SQL injection patterns based on community reports.
  This rule covers UNION-based injection attempts.
severity: high
category: sqli
author: community
version: "1.0"
tags:
  - sql
  - injection
  - community
rules:
  - pattern: "UNION\\s+SELECT"
    type: regex
    confidence: 80
  - pattern: "(\\bor\\b|\\band\\b).*=.*\\d+"
    type: regex
    confidence: 60
actions:
  - score: 15
  - log: true
```

## Rule Categories

| Category | Description | Typical Severity |
|----------|-------------|------------------|
| `sqli` | SQL Injection attempts | High |
| `xss` | Cross-Site Scripting | High |
| `lfi` | Local File Inclusion | Medium-High |
| `rce` | Remote Code Execution | Critical |
| `rfi` | Remote File Inclusion | Critical |
| `scanner` | Scanner/Crawler detection | Low |
| `xxe` | XML External Entity | High |
| `csrf` | Cross-Site Request Forgery | Medium |
| `path_traversal` | Path Traversal attacks | Medium-High |

## Severity Levels

- **Critical (4)**: Immediate threat, auto-block recommended
- **High (3)**: Significant threat, block on medium-high sensitivity
- **Medium (2)**: Potential threat, block on high sensitivity
- **Low (1)**: Minor issue, logging only
- **Info (0)**: Informational, no action

## Confidence Scores

- **100**: Exact match, extremely reliable
- **80-99**: High confidence, safe to block
- **60-79**: Medium confidence, may cause false positives
- **40-59**: Low confidence, log only
- **0-39**: Experimental, needs review

## Submission Process

1. Fork the repository
2. Create a new branch: `community/rules/<rule-name>`
3. Add your rule to the appropriate category
4. Include tests in `tests/community/`
5. Submit a pull request
6. Address review feedback
7. Rule will be merged after approval

See [CONTRIBUTING.md](../.github/CONTRIBUTING.md) for full guidelines.

## Rule Testing

All community rules must include test cases:

```yaml
tests:
  - name: "Basic UNION SELECT detection"
    input: "id=1 UNION SELECT 1,2,3"
    expected_match: true
  - name: "Legitimate query"
    input: "id=1"
    expected_match: false
```

Run tests with:
```bash
cargo test --package waf-engine -- community
```

## Rule Lifecycle

1. **Experimental**: New rules, may have issues
2. **Testing**: Validated but needs more coverage
3. **Stable**: Production-ready
4. **Deprecated**: Being replaced or removed

## Quality Requirements

For a rule to be merged:
- [ ] Valid YAML syntax
- [ ] Test cases covering common and edge cases
- [ ] No false positives on legitimate traffic
- [ ] Clear documentation
- [ ] Unique rule ID
- [ ] Proper category assignment