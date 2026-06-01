# Contributing to WAF Rules

Thank you for your interest in contributing to the WAF community rules!

## How to Contribute

### 1. Fork and Clone

```bash
# Fork via GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/waf.git
cd waf
```

### 2. Create a Branch

```bash
# Create a branch for your rule
git checkout -b community/rules/your-rule-name
```

### 3. Write Your Rule

Rules are YAML files placed in `rules/community/<category>/`.

**Required fields:**
- `id`: Unique identifier (e.g., `community-0001`)
- `name`: Human-readable name
- `description`: What the rule detects
- `severity`: Critical, High, Medium, Low, Info
- `category`: sqli, xss, lfi, rce, etc.
- `author`: Your name or handle
- `rules`: List of patterns to match
- `tests`: At least 3 test cases

**Recommended fields:**
- `tags`: Searchable keywords
- `references`: CVE numbers, blog posts, etc.
- `whitelist`: Known safe patterns

### 4. Test Your Rule

```bash
# Run community rule tests
cargo test --package waf-engine -- community

# Validate YAML syntax
cargo test --package waf-engine -- yaml_syntax
```

### 5. Commit and Push

```bash
git add rules/community/<category>/your-rule.yaml
git commit -m "feat(rules): add community rule for <what it detects>

- Add <rule-name> rule
- Covers <patterns detected>
- Includes <N> test cases
- Addresses <CVE/issue if applicable>"
git push origin community/rules/your-rule-name
```

### 6. Submit Pull Request

1. Go to GitHub and click "New Pull Request"
2. Select your branch
3. Fill in the PR template

## Pull Request Template

```markdown
## Rule Summary
Brief description of what this rule detects.

## Category
[ ] SQL Injection (sqli)
[ ] Cross-Site Scripting (xss)
[ ] Remote Code Execution (rce)
[ ] Local File Inclusion (lfi)
[ ] Other: __________

## Severity
[ ] Critical (4)
[ ] High (3)
[ ] Medium (2)
[ ] Low (1)

## Coverage
List CVEs or specific attack patterns covered.

## Test Cases
How many test cases included? ___

## Checklist
- [ ] Rule follows YAML schema
- [ ] At least 3 test cases included
- [ ] Tests pass locally
- [ ] No false positives on common frameworks
- [ ] Documentation complete
```

## Review Process

1. **Automated checks** run on your PR (YAML validation, tests)
2. **Maintainer review** within 7 days
3. **Community feedback** welcome
4. **Approval and merge** when ready

## Rule Quality Standards

### Good Rules
- Detect a specific attack pattern
- Include comprehensive test cases
- Have clear documentation
- Have minimal false positives
- Follow naming conventions

### Poor Rules
- Match too broadly (catches legitimate traffic)
- Missing test cases
- Overlapping with existing rules
- Undocumented patterns

## Common Issues

### False Positives
If your rule matches legitimate traffic, add whitelist conditions or increase confidence threshold.

### Overlapping Rules
Check existing rules in the same category before submitting.

### Missing Test Cases
Include both positive (should match) and negative (should not match) tests.

## Getting Help

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Join community chat (link in README)

## License

By contributing rules, you agree your contributions are licensed under the same license as the project.