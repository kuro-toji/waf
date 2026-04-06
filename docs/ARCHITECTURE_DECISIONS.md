# WAF Architecture Decision Records

## ADR-001: Use Rust for Core Implementation

### Status
Accepted

### Context
We need to build a high-performance, memory-safe WAF that can handle high traffic loads while providing comprehensive attack detection.

### Decision
Use Rust as the primary implementation language for all core components.

### Rationale
- **Performance**: Rust provides near-C performance with zero-cost abstractions
- **Memory Safety**: Rust's ownership system prevents memory leaks and buffer overflows
- **Concurrency**: Fearless async/await with Tokio enables high concurrency
- **Ecosystem**: Rich ecosystem for web frameworks (Axum, Hyper), parsing (regex, serde)

### Consequences
- Steeper learning curve for contributors
- Slower initial development compared to Go or Python
- Excellent production performance and safety

## ADR-002: Modular Crate Structure

### Status
Accepted

### Context
Different components (engine, rate limiter, bot detector) have different release cycles and dependencies.

### Decision
Split WAF into multiple Cargo workspace crates:
- `waf-common`: Shared types and configuration
- `waf-engine`: Rule matching and detection
- `waf-rate-limiter`: Rate limiting algorithms
- `waf-bot-detector`: Bot detection
- `waf-core`: HTTP proxy server
- `waf-admin`: Admin API

### Rationale
- Independent versioning
- Smaller dependency surface per crate
- Clear boundaries between components
- Easier testing of individual components

### Consequences
- More complex build configuration
- Cross-crate dependencies need careful management
- Workspace-level CI/CD required

## ADR-003: YAML for Rule Configuration

### Status
Accepted

### Context
Rules need to be configurable by operators without recompiling the WAF.

### Decision
Use YAML files for all rule configuration with hot reload support.

### Rationale
- Human-readable and editable
- Git-friendly for version control
- Industry standard for Kubernetes/ingress configs
- Easy to generate programmatically

### Consequences
- Need YAML parsing dependency (serde_yaml)
- Rule validation at load time required
- Slightly slower than code-based rules

## ADR-004: Prometheus for Metrics

### Status
Accepted

### Context
Need standardized metrics for monitoring and alerting.

### Decision
Expose metrics in Prometheus format at `/metrics` endpoint.

### Rationale
- Industry standard for metrics
- Excellent tooling (Grafana, Alertmanager)
- Kubernetes native integration
- Low overhead

### Consequences
- Prometheus dependency for full feature set
- Grafana dashboard for visualization
- External monitoring stack required

## ADR-005: Redis for Distributed Rate Limiting

### Status
Accepted

### Context
Multi-instance deployments need shared rate limiting state.

### Decision
Support both in-memory (single instance) and Redis (distributed) backends.

### Rationale
- Redis is widely adopted
- Lua scripts enable atomic operations
- Clustering for horizontal scaling
- Battle-tested in production

### Consequences
- Redis becomes infrastructure dependency for multi-instance
- Additional configuration required
- Network latency impact on rate limiting