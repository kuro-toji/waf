//! Rate Limiter
//!
//! Unified rate limiting interface.
//!
//! ## Supported Algorithms
//!
//! 1. **Token Bucket**: Allows bursts, smooth long-term rate
//! 2. **Sliding Window**: Smooth limiting without boundary bursts
//! 3. **Leaky Bucket**: Constant rate output regardless of input
//!
//! ## Backends
//!
//! - **In-Memory**: Fast, single-instance only
//! - **Redis**: Distributed, multi-instance support
//!
//! ## Configuration
//!
//! ```ignore
//! let config = RateLimitConfig {
//!     algorithm: RateLimitAlgorithm::SlidingWindow,
//!     limit: 1000,           // requests per window
//!     window_seconds: 60,    // window size
//!     burst_size: Some(100), // for token bucket/leaky bucket
//! };
//!
//! let limiter = RateLimiter::new(config);
//! let result = limiter.check("192.168.1.1").await?;
//! ```

use super::{LeakyBucket, RedisRateLimiter, SlidingWindow, TokenBucket};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use waf_common::*;

/// Rate limiting algorithm
#[derive(Debug, Clone)]
pub enum RateLimitAlgorithm {
    TokenBucket,
    SlidingWindow,
    LeakyBucket,
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub algorithm: RateLimitAlgorithm,
    pub limit: u64,
    pub window_seconds: u64,
    pub burst_size: Option<u64>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            algorithm: RateLimitAlgorithm::SlidingWindow,
            limit: 100,
            window_seconds: 60,
            burst_size: None,
        }
    }
}

/// Unified rate limiter
pub struct RateLimiter {
    config: RateLimitConfig,
    redis: Option<Arc<RedisRateLimiter>>,
    local_limiters: RwLock<HashMap<String, LocalLimiter>>,
}

/// Local limiter wrapper
enum LocalLimiter {
    TokenBucket(TokenBucket),
    SlidingWindow(SlidingWindow),
    LeakyBucket(LeakyBucket),
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            redis: None,
            local_limiters: RwLock::new(HashMap::new()),
        }
    }

    /// Create with Redis backend
    pub async fn with_redis(config: RateLimitConfig, redis_url: &str) -> Result<Self> {
        let redis = Some(Arc::new(RedisRateLimiter::new(redis_url).await?));

        Ok(Self {
            config,
            redis,
            local_limiters: RwLock::new(HashMap::new()),
        })
    }

    /// Check rate limit for a key
    pub async fn check(&self, key: &str) -> Result<RateLimitInfo> {
        // Use Redis if available
        if let Some(redis) = &self.redis {
            match self.config.algorithm {
                RateLimitAlgorithm::TokenBucket => {
                    let burst = self.config.burst_size.unwrap_or(self.config.limit);
                    return redis
                        .check_token_bucket(key, burst, self.config.limit as f64)
                        .await;
                }
                RateLimitAlgorithm::SlidingWindow | RateLimitAlgorithm::LeakyBucket => {
                    return redis
                        .check_sliding_window(key, self.config.limit, self.config.window_seconds)
                        .await;
                }
            }
        }

        // Fall back to local limiter
        self.check_local(key)
    }

    /// Check rate limit locally
    fn check_local(&self, key: &str) -> Result<RateLimitInfo> {
        let mut limiters = self.local_limiters.write();

        let limiter =
            limiters
                .entry(key.to_string())
                .or_insert_with(|| match self.config.algorithm {
                    RateLimitAlgorithm::TokenBucket => {
                        let burst = self.config.burst_size.unwrap_or(self.config.limit);
                        LocalLimiter::TokenBucket(TokenBucket::new(burst, self.config.limit as f64))
                    }
                    RateLimitAlgorithm::SlidingWindow => LocalLimiter::SlidingWindow(
                        SlidingWindow::new(self.config.limit, self.config.window_seconds),
                    ),
                    RateLimitAlgorithm::LeakyBucket => {
                        let burst = self.config.burst_size.unwrap_or(self.config.limit);
                        LocalLimiter::LeakyBucket(LeakyBucket::new(burst, self.config.limit as f64))
                    }
                });

        let result = match limiter {
            LocalLimiter::TokenBucket(bucket) => {
                let allowed = bucket.try_consume();
                RateLimitInfo {
                    request_count: bucket.tokens() as u64,
                    limit: self.config.limit,
                    window_seconds: 1,
                    remaining: bucket.tokens() as u64,
                    exceeded: !allowed,
                    reset_at: chrono::Utc::now() + chrono::Duration::seconds(1),
                }
            }
            LocalLimiter::SlidingWindow(window) => {
                let _allowed = window.check();
                window.get_info()
            }
            LocalLimiter::LeakyBucket(bucket) => {
                let _allowed = bucket.try_add();
                bucket.get_info()
            }
        };

        Ok(result)
    }

    /// Reset rate limit for a key
    pub async fn reset(&self, key: &str) -> Result<()> {
        if let Some(redis) = &self.redis {
            redis.reset(key).await?;
        }

        let mut limiters = self.local_limiters.write();
        limiters.remove(key);

        Ok(())
    }

    /// Clear all local limiters
    pub fn clear_local(&self) {
        let mut limiters = self.local_limiters.write();
        limiters.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_token_bucket() {
        let config = RateLimitConfig {
            algorithm: RateLimitAlgorithm::TokenBucket,
            limit: 10,
            window_seconds: 1,
            burst_size: Some(10),
        };

        let limiter = RateLimiter::new(config);

        // Use up all tokens
        for _ in 0..10 {
            let result = limiter.check("test").await.unwrap();
            assert!(!result.exceeded);
        }

        // Should be rate limited
        let result = limiter.check("test").await.unwrap();
        assert!(result.exceeded);
    }

    #[test]
    fn test_local_sliding_window() {
        let config = RateLimitConfig {
            algorithm: RateLimitAlgorithm::SlidingWindow,
            limit: 5,
            window_seconds: 60,
            burst_size: None,
        };

        let limiter = RateLimiter::new(config);

        // Use up all requests
        for _ in 0..5 {
            let _result = std::time::Duration::from_millis(10);
            let _ = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(limiter.check("test"));
        }
    }
}
