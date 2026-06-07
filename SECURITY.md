# Security Policy

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Send an email to security@kuro-toji.local with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

3. Expect acknowledgment within 48 hours

4. Expect detailed response within 7 days

5. Once fixed, you'll be credited (if you want) in the security advisory

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Known Limitations

### WAF Bypass Potential

While we strive to provide comprehensive protection, no WAF can guarantee 100% security:

- **Rule-based detection**: Complex encoding may bypass some patterns
- **Protocol-level attacks**: Some attacks target infrastructure, not application
- **Business logic flaws**: WAF cannot detect logic errors in your application

### Best Practices

1. **Defense in Depth**: WAF is one layer, not the only layer
2. **Regular Updates**: Keep WAF rules and software updated
3. **Monitoring**: Review logs and alerts regularly
4. **Testing**: Periodically test with penetration testing tools
5. **HTTPS**: Always use TLS in production

## Security Configuration

### Hardening Checklist

- [ ] Change default ports (8080, 8081, 9090)
- [ ] Enable TLS for all traffic
- [ ] Configure trusted proxy list
- [ ] Set appropriate rate limits
- [ ] Enable bot detection
- [ ] Block TOR exit nodes (if acceptable)
- [ ] Use strict Content-Security-Policy headers
- [ ] Enable request logging for audit

### Network Security

- Place WAF in front of application servers
- Restrict upstream access to application servers only
- Use private networking for backend communication
- Enable firewall rules for WAF management

## Compliance

WAF can help with compliance requirements:

### GDPR
- Rate limiting helps prevent data scraping
- Attack detection logs support audit requirements

### PCI-DSS
- WAF protects web applications from common attacks
- Regular rule updates address new vulnerabilities

### SOC 2
- Logging supports audit trails
- Bot detection prevents automated attacks