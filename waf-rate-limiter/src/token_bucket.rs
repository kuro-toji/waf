//! Token Bucket Rate Limiter
//!
//! Token bucket algorithm implementation for rate limiting.
//!
//! ## Algorithm Overview
//!
//! The token bucket algorithm allows burst traffic up to a maximum
//! (bucket capacity) while enforcing an average rate (refill rate).
//!
//! - Bucket holds tokens, each token allows one request
//! - Tokens refill at a constant rate (refill_rate per second)
//! - When a request arrives, it consumes a token if available
//! - If no tokens available, request is rate limited
//!
//! ## Parameters
//!
//! - **capacity**: Maximum tokens in bucket (burst size)
//! - **refill_rate**: Tokens added per second (average rate)
//!
//! ## Use Cases
//!
//! - API rate limiting with burst allowance
//! - Per-user limiting with burst tolerance
//! - Smooth long-term rate with burst flexibility
//!
//! ## Usage
//!
//! ```rust
//! use waf_rate_limiter::TokenBucket;
//!
//! let mut bucket = TokenBucket::new(100, 10.0); // 100 tokens, 10/sec refill
//!
//! // Try to consume a token
//! if bucket.try_consume() {
//!     println!("Request allowed");
//! } else {
//!     println!("Rate limited");
//! }
//! ```

use std::time::{Duration, Instant};
use waf_common::*;

/// Token bucket state
#[derive(Debug, Clone)]
pub struct TokenBucketState {
    /// Current number of tokens
    pub tokens: f64,
    /// Last refilled time
    pub last_refill: Instant,
    /// Maximum tokens
    pub capacity: u64,
    /// Refill rate (tokens per second)
    pub refill_rate: f64,
}

/// Token bucket rate limiter
pub struct TokenBucket {
    /// Maximum tokens in bucket
    capacity: u64,
    /// Tokens added per second
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
    /// Current tokens
    tokens: f64,
}

impl TokenBucket {
    /// Create a new token bucket
    pub fn new(capacity: u64, refill_rate: f64) -> Self {
        Self {
            capacity,
            refill_rate,
            last_refill: Instant::now(),
            tokens: capacity as f64,
        }
    }

    /// Create from state
    pub fn from_state(state: TokenBucketState) -> Self {
        Self {
            capacity: state.capacity,
            refill_rate: state.refill_rate,
            tokens: state.tokens,
            last_refill: state.last_refill,
        }
    }

    /// Try to consume a token
    pub fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Try to consume multiple tokens
    pub fn try_consume_n(&mut self, n: u64) -> bool {
        self.refill();

        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let seconds = elapsed.as_secs_f64();

        let new_tokens = seconds * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// Get current token count
    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    /// Get time until full
    pub fn time_until_full(&self) -> Duration {
        let needed = self.capacity as f64 - self.tokens;
        let seconds = needed / self.refill_rate;
        Duration::from_secs_f64(seconds)
    }

    /// Get state for serialization
    pub fn get_state(&self) -> TokenBucketState {
        TokenBucketState {
            tokens: self.tokens,
            last_refill: self.last_refill,
            capacity: self.capacity,
            refill_rate: self.refill_rate,
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(10, 1.0); // 10 tokens, 1 per second

        // Consume all tokens
        for _ in 0..10 {
            assert!(bucket.try_consume());
        }

        // Should be exhausted
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(5, 10.0); // 5 tokens, 10 per second

        // Consume some tokens
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());

        // Small wait should refill
        std::thread::sleep(Duration::from_millis(200));

        // Should have tokens again
        assert!(bucket.try_consume());
    }
}
