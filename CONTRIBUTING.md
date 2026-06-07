# Contributing to WAF

Thank you for your interest in contributing to WAF!

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
1. Search existing issues to avoid duplicates
2. Check if the issue is reproducible
3. Include:
   - WAF version
   - Rust version (`rustc --version`)
   - Steps to reproduce
   - Expected vs actual behavior
   - Full error output if applicable

### Suggesting Features

1. Check existing issues and PRs
2. Describe the problem you're solving
3. Explain why this feature would benefit the project
4. Provide examples or mockups if applicable

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `cargo test --workspace`
6. Run lints: `cargo clippy --workspace -- -D warnings`
7. Format: `cargo fmt --all`
8. Commit with clear messages
9. Push to your fork
10. Open a Pull Request

### Code Style

- Follow Rust idioms and conventions
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Write documentation for public APIs
- Add unit tests for new modules

### Commit Messages

Format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- style: Formatting
- refactor: Code refactoring
- test: Adding tests
- chore: Maintenance tasks

Example:
```
feat(waf-engine): Add SQL injection time-based blind detection

Implemented BENCHMARK and SLEEP pattern detection for time-based
blind SQL injection attacks. Added test cases for various patterns.

Closes #123
```

## Development Setup

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone repository
git clone https://github.com/kuro-toji/waf.git
cd waf

# Build
cargo build --release --workspace

# Run tests
cargo test --workspace --all-targets

# Run with debug logging
RUST_LOG=debug cargo run --bin waf-core
```

## Project Structure

```
waf/
├── waf-common/      # Shared types and utilities
├── waf-engine/      # Rule matching and attack detection
├── waf-rate-limiter/ # Rate limiting algorithms
├── waf-bot-detector/ # Bot detection
├── waf-core/        # Main proxy server
├── waf-admin/       # Admin API
├── waf-dashboard/   # React dashboard
├── rules/           # Default rule YAML files
├── config/          # Configuration files
├── docs/            # Documentation
└── tests/           # Integration tests
```

## Areas to Contribute

- **Detectors**: Add new attack detection modules
- **Performance**: Optimize hot paths and reduce allocations
- **Documentation**: Improve docs and examples
- **Testing**: Add comprehensive test coverage
- **CI/CD**: Improve GitHub Actions workflows
- **Dashboard**: Enhance the React admin UI

## Questions?

Open an issue for discussion before starting large changes.