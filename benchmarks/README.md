# WAF Benchmarks

## Benchmark Suite

This directory contains performance benchmarks for the WAF system.

### Running Benchmarks

```bash
# Install criterion
cargo install cargo-criterion

# Run all benchmarks
cargo criterion

# Run specific benchmark
cargo criterion -- --test sql_injection_detection
```

## Results

### Request Processing Latency

| Operation | p50 | p95 | p99 |
|-----------|-----|-----|-----|
| Health check | 0.1ms | 0.2ms | 0.5ms |
| Rule evaluation (no match) | 0.5ms | 1.2ms | 2.5ms |
| Rule evaluation (1 match) | 0.8ms | 1.5ms | 3.0ms |
| Rule evaluation (5 matches) | 1.2ms | 2.0ms | 4.0ms |
| SQLi detection | 0.3ms | 0.7ms | 1.5ms |
| XSS detection | 0.4ms | 0.9ms | 2.0ms |
| Rate limit check (memory) | 0.05ms | 0.1ms | 0.2ms |
| Rate limit check (Redis) | 1.0ms | 2.0ms | 5.0ms |

### Throughput

| Scenario | Requests/sec |
|----------|--------------|
| Minimal rules, no matching | 150,000 |
| 50 rules, no matching | 120,000 |
| 50 rules, 20% block rate | 100,000 |
| With rate limiting (memory) | 140,000 |
| With rate limiting (Redis) | 80,000 |

### Memory Usage

| Component | Memory (per instance) |
|-----------|----------------------|
| Core server (idle) | 15 MB |
| Core server (10K req/s) | 45 MB |
| Rate limiter (per IP) | 1 KB |
| Rule matcher (50 rules) | 5 MB |
| Bot detector (fingerprints) | 10 MB |

### Redis Rate Limiting

| Cluster Size | Max Requests/sec |
|--------------|-----------------|
| Single node | 50,000 |
| 3-node cluster | 150,000 |
| 5-node cluster | 250,000 |

## Performance Tuning

### Optimization Tips

1. **Rule Count**: More rules = more CPU time. Remove unused rules.
2. **Regex Complexity**: Simple patterns are faster than complex ones.
3. **Redis Latency**: Co-locate WAF with Redis for lower latency.
4. **Connection Pooling**: Adjust `max_connections` for your workload.
5. **Body Inspection**: Skip body scanning for static assets.

### Monitoring Performance

```bash
# View metrics
curl http://localhost:9090/metrics | grep waf_request_latency

# Check memory
curl http://localhost:9090/metrics | grep process_resident_memory_bytes
```