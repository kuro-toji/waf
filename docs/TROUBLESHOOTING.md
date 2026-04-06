# Troubleshooting Guide

## Common Issues

### WAF Not Starting

**Symptom**: `Failed to bind to address` error

**Solutions**:
1. Check if port is already in use: `lsof -i :8080`
2. Change listen address in config: `waf.listen_addr: "0.0.0.0:8081"`
3. Check permissions (root required for ports < 1024)

**Symptom**: `Failed to load config` error

**Solutions**:
1. Verify YAML syntax: `yaml -c config/waf.yaml`
2. Check file permissions: `chmod 644 config/waf.yaml`
3. Verify paths are absolute or relative to working directory

### Requests Not Being Blocked

**Symptom**: SQL injection requests are not blocked

**Diagnosis**:
1. Check rule is enabled: `curl http://localhost:8081/api/rules | jq '.[] | select(.id=="sqli-001") | .enabled'`
2. Check severity threshold: Ensure `min_severity_to_block` is not too high
3. Check logs: `docker-compose logs waf-core 2>&1 | grep sqli`

**Solutions**:
1. Enable rule if disabled
2. Lower severity threshold
3. Add custom rule with lower threshold

**Symptom**: XSS attacks not detected

**Diagnosis**:
1. Check body scanning is enabled
2. Verify Content-Type handling
3. Check rule patterns are correct

### Rate Limiting Not Working

**Symptom**: Too many requests getting through

**Diagnosis**:
1. Check Redis connection: `redis-cli ping`
2. Verify rate limit config: `curl http://localhost:8081/api/config | jq '.rate_limiter'`
3. Check rate limit algorithm is set

**Solutions**:
1. If using Redis, verify network connectivity
2. Restart WAF to reset in-memory counters
3. Check for conflicting rate limit rules

### High Latency

**Symptom**: Requests taking > 100ms

**Diagnosis**:
1. Check upstream response time
2. Review rule count (more rules = more CPU)
3. Check for regex complexity

**Solutions**:
1. Optimize upstream server
2. Remove unused rules
3. Simplify regex patterns (avoid catastrophic backtracking)

### Memory Usage High

**Symptom**: WAF using > 500MB RAM

**Diagnosis**:
1. Check rule count (each rule uses memory)
2. Review regex cache size
3. Check connection pool settings

**Solutions**:
1. Reduce rule count
2. Restart WAF periodically
3. Adjust connection pool size

## Performance Issues

### Slow Rule Loading

**Symptom**: Rules take > 10 seconds to load

**Cause**: Large rule files or slow disk I/O

**Solution**: Use smaller rule files, SSD storage

### High CPU Usage

**Symptom**: CPU at 100% consistently

**Cause**: Too many rules, complex regex, high traffic

**Solution**:
1. Profile with `cargo flamegraph`
2. Simplify rules
3. Scale horizontally

## Log Analysis

### Finding Attack Patterns

```bash
# Find SQL injection attempts
docker-compose logs | grep -i "sqli" | jq .

# Find blocked IPs
docker-compose logs | grep "blocked" | jq '.client_ip'

# Attack statistics
docker-compose logs | grep "attack" | awk '{print $NF}' | sort | uniq -c
```

## Getting Help

1. Check FAQ: `docs/FAQ.md`
2. Search existing issues: `github.com/username/waf/issues`
3. Create new issue with debug info:

```bash
# Gather debug information
echo "=== WAF Version ==="
cargo tree | grep waf

echo "=== Config ==="
cat config/waf.yaml

echo "=== Recent Logs ==="
docker-compose logs --tail=100
```