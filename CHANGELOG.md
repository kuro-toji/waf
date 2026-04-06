# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Project structure with Cargo workspace
- waf-common crate with shared types
- waf-engine crate for rule matching
- waf-rate-limiter with 3 algorithms (token bucket, sliding window, leaky bucket)
- waf-bot-detector with fingerprinting and challenges
- waf-core HTTP proxy server
- waf-admin REST API service
- waf-dashboard React application
- OWASP Top 10 protection rules (SQLi, XSS, CSRF, path traversal, command injection, XXE, LDAP injection, LFI, RFI)
- Rate limiting configuration
- Bot detection rules with known bot allowlisting
- Docker and docker-compose setup
- Helm chart for Kubernetes
- Terraform configurations for AWS and GCP
- Prometheus metrics and Grafana dashboard
- Installation script for Linux systems
- Stress testing and integration test suites
- Contributing guidelines

## [0.1.0] - 2024-01-15

### Added
- Initial project setup
- Core WAF functionality
- Basic attack detection
- Rate limiting
- Admin API

[Unreleased]: https://github.com/username/waf/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/username/waf/releases/tag/v0.1.0