//! Redis Backend for Rate Limiting
//!
//! Distributed rate limiting using Redis.
//!
//! ## Why Redis?
//!
//! For multi-instance WAF deployments, rate limiting state must be
//! shared across all instances. Redis provides:
//! - Atomic operations for accurate counting
//! - Low latency (<1ms for local Redis)
//! - TTL support for automatic cleanup
//! - Clustering for horizontal scaling
//!
//! ## Algorithms Supported
//!
//! 1. **Sliding Window**: Sorted set with timestamps
//! 2. **Token Bucket**: Atomic increment/decrement with Lua scripts
//!
//! ## Lua Scripts
//!
//! Redis backends use Lua scripts for atomic operations:
//! - Sliding window: Add timestamp, remove expired, count
//! - Token bucket: Check tokens, consume if available
//!
//! This ensures accurate counting even under high concurrency.
//!
//! ## Key Structure
//!
//! Keys are prefixed with `waf:ratelimit:` to avoid collisions.
//! Key format: `waf:ratelimit:{ip}:{endpoint}` for per-IP-per-endpoint.

use crate::TokenBucketState;
use redis::{AsyncCommands, Client};
use tokio::sync::RwLock;
use waf_common::*;

const RATE_LIMIT_PREFIX: &str = "waf:ratelimit:";

/// Redis-backed rate limiter
pub struct RedisRateLimiter {
    client: Client,
    /// Reserved for a local in-process fallback used when Redis is unreachable.
    /// Not yet wired into the public API; kept here to anchor the planned
    /// graceful-degradation path.
    #[allow(dead_code)]
    local_buckets: RwLock<std::collections::HashMap<String, TokenBucketState>>,
}

impl RedisRateLimiter {
    /// Create a new Redis rate limiter
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = Client::open(redis_url)
            .map_err(|e| WafError::Redis(format!("Failed to connect: {}", e)))?;

        // Test connection
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| WafError::Redis(format!("Failed to get connection: {}", e)))?;

        redis::cmd("PING")
            .query_async::<_, String>(&mut conn)
            .await
            .map_err(|e| WafError::Redis(format!("Failed to ping: {}", e)))?;

        Ok(Self {
            client,
            local_buckets: RwLock::new(std::collections::HashMap::new()),
        })
    }

    /// Check rate limit using sliding window in Redis
    pub async fn check_sliding_window(
        &self,
        key: &str,
        limit: u64,
        window_seconds: u64,
    ) -> Result<RateLimitInfo> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let redis_key = format!("{}{}", RATE_LIMIT_PREFIX, key);

        let now = chrono::Utc::now().timestamp();
        let window_start = now - window_seconds as i64;

        // Lua script for atomic sliding window
        let script = r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window_start = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local window = tonumber(ARGV[4])
            
            -- Remove old entries
            redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
            
            -- Count current requests
            local count = redis.call('ZCARD', key)
            
            if count < limit then
                -- Add new request
                redis.call('ZADD', key, now, now .. '-' .. redis.call('INCR', key .. ':counter'))
                redis.call('EXPIRE', key, window)
                return {1, limit - count - 1, window}
            else
                return {0, 0, window}
            end
        "#;

        let result: Vec<i64> = redis::Script::new(script)
            .key(&redis_key)
            .arg(now)
            .arg(window_start)
            .arg(limit)
            .arg(window_seconds)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| WafError::Redis(format!("Script error: {}", e)))?;

        let allowed = result[0] == 1;
        let remaining = result[1] as u64;

        Ok(RateLimitInfo {
            request_count: limit - remaining,
            limit,
            window_seconds,
            remaining,
            exceeded: !allowed,
            reset_at: chrono::Utc::now() + chrono::Duration::seconds(window_seconds as i64),
        })
    }

    /// Check rate limit using token bucket in Redis
    pub async fn check_token_bucket(
        &self,
        key: &str,
        capacity: u64,
        refill_rate: f64,
    ) -> Result<RateLimitInfo> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let redis_key = format!("{}{}", RATE_LIMIT_PREFIX, key);

        let now = chrono::Utc::now().timestamp_millis() as f64;

        // Lua script for atomic token bucket
        let script = r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local capacity = tonumber(ARGV[2])
            local refill_rate = tonumber(ARGV[3])
            
            local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
            local tokens = tonumber(bucket[1])
            local last_refill = tonumber(bucket[2])
            
            if tokens == nil then
                tokens = capacity
                last_refill = now
            end
            
            -- Refill tokens
            local elapsed = (now - last_refill) / 1000.0
            tokens = math.min(capacity, tokens + elapsed * refill_rate)
            last_refill = now
            
            if tokens >= 1.0 then
                tokens = tokens - 1.0
                redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
                redis.call('EXPIRE', key, 60)
                return {1, tokens, capacity}
            else
                redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
                redis.call('EXPIRE', key, 60)
                return {0, tokens, capacity}
            end
        "#;

        let result: Vec<f64> = redis::Script::new(script)
            .key(&redis_key)
            .arg(now)
            .arg(capacity)
            .arg(refill_rate)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| WafError::Redis(format!("Script error: {}", e)))?;

        let allowed = result[0] == 1.0;
        let tokens = result[1];

        Ok(RateLimitInfo {
            request_count: (capacity as f64 - tokens) as u64,
            limit: capacity,
            window_seconds: 1,
            remaining: tokens as u64,
            exceeded: !allowed,
            reset_at: chrono::Utc::now()
                + chrono::Duration::milliseconds(((1.0 - tokens) / refill_rate * 1000.0) as i64),
        })
    }

    /// Reset rate limit for a key
    pub async fn reset(&self, key: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let redis_key = format!("{}{}", RATE_LIMIT_PREFIX, key);

        conn.del::<_, ()>(&redis_key)
            .await
            .map_err(|e| WafError::Redis(format!("Failed to delete: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Integration tests would go here
    // They require a running Redis instance
}
