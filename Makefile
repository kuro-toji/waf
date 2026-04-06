.PHONY: build test lint clean run docker-build docker-up docker-down

# Build all crates
build:
	cargo build --release --workspace

# Run tests
test:
	cargo test --workspace --all-targets

# Run clippy linter
lint:
	cargo clippy --workspace --all-targets -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/

# Run waf-core locally
run:
	RUST_LOG=debug cargo run --bin waf-core

# Run admin service
run-admin:
	RUST_LOG=debug cargo run --bin waf-admin

# Build Docker image
docker-build:
	docker build -t ghcr.io/username/waf:latest .

# Start all services with docker-compose
docker-up:
	docker-compose up -d

# Stop all services
docker-down:
	docker-compose down

# View logs
logs:
	docker-compose logs -f

# Run integration tests
test-integration:
	docker-compose up -d
	sleep 5
	curl -i "http://localhost:8080/health"
	curl -i "http://localhost:8080/?id=1' UNION SELECT"
	docker-compose down

# Benchmark
benchmark:
	@echo "Running basic benchmark..."
	@for i in {1..100}; do curl -s -o /dev/null http://localhost:8080/; done
	@echo "100 requests completed"

# Generate docs
docs:
	cargo doc --workspace --no-deps

# Format and check
check: fmt lint test

# Production build
prod: fmt lint test build

# Development with hot reload
dev:
	RUST_LOG=debug cargo run --bin waf-core

# Generate coverage report
coverage:
	cargo install cargo-tarpaulin
	cargo tarpaulin --output-html --output-xml

# Security audit
audit:
	cargo install cargo-audit
	cargo audit

# Update dependencies
update:
	cargo update
	cargo update --manifest-path waf-common/Cargo.toml
	cargo update --manifest-path waf-engine/Cargo.toml
	cargo update --manifest-path waf-rate-limiter/Cargo.toml
	cargo update --manifest-path waf-bot-detector/Cargo.toml
	cargo update --manifest-path waf-core/Cargo.toml
	cargo update --manifest-path waf-admin/Cargo.toml

# Build dashboard
build-dashboard:
	cd waf-dashboard && npm install && npm run build

# Deploy to Kubernetes
k8s-deploy:
	helm upgrade --install waf ./helm/waf --namespace waf-system --create-namespace

# Delete from Kubernetes
k8s-delete:
	helm delete waf --namespace waf-system

# View metrics
metrics:
	curl -s http://localhost:9090/metrics | head -50

# Prometheus targets
prometheus-targets:
	curl -s http://localhost:9091/api/v1/targets | jq .