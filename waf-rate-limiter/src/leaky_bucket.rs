//! Leaky Bucket Rate Limiter
//!
//! Leaky bucket algorithm implementation for constant-rate limiting.
//!
//! ## Algorithm Overview
//!
//! The leaky bucket algorithm enforces a constant output rate regardless
//! of burst input. Think of a bucket with a hole in the bottom.
//!
//! - Water (requests) flow into the bucket
//! - Water leaks out at a constant rate (leak_rate)
//! - If bucket is full, water (requests) are dropped
//!
//! ## Parameters
//!
//! - **capacity**: Maximum bucket size (burst capacity)
//! - **leak_rate**: Requests that leak per second (constant rate)
//!
//! ## Use Cases
//!
//! - Constant rate API limiting
//! - Traffic shaping for stable output
//! - Strict rate enforcement without burst

use std::time::{Duration, Instant};
use waf_common::*;

/// Leaky bucket rate limiter
pub struct LeakyBucket {
    /// Maximum bucket size (burst capacity)
    capacity: u64,
    /// Leak rate (requests per second)
    leak_rate: f64,
    /// Current bucket level
    level: f64,
    /// Last leak time
    last_leak: Instant,
}

impl LeakyBucket {
    /// Create a new leaky bucket
    pub fn new(capacity: u64, leak_rate: f64) -> Self {
        Self {
            capacity,
            leak_rate,
            level: 0.0,
            last_leak: Instant::now(),
        }
    }

    /// Try to add a request to the bucket
    pub fn try_add(&mut self) -> bool {
        self.leak();

        if self.level < self.capacity as f64 {
            self.level += 1.0;
            true
        } else {
            false
        }
    }

    /// Leak water over time
    fn leak(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_leak).as_secs_f64();

        let leaked = elapsed * self.leak_rate;
        self.level = (self.level - leaked).max(0.0);
        self.last_leak = now;
    }

    /// Get current bucket level
    pub fn level(&self) -> f64 {
        self.leak();
        self.level
    }

    /// Get time until bucket is empty
    pub fn time_until_empty(&self) -> Duration {
        let seconds = self.level / self.leak_rate;
        Duration::from_secs_f64(seconds)
    }

    /// Get rate limit info
    pub fn get_info(&self) -> RateLimitInfo {
        RateLimitInfo {
            request_count: self.level as u64,
            limit: self.capacity,
            window_seconds: 1,
            remaining: (self.capacity as f64 - self.level()) as u64,
            exceeded: self.level >= self.capacity as f64,
            reset_at: chrono::Utc::now()
                + chrono::Duration::seconds(self.time_until_empty().as_secs() as i64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaky_bucket_basic() {
        let mut bucket = LeakyBucket::new(5, 1.0);

        // Add up to capacity
        for _ in 0..5 {
            assert!(bucket.try_add());
        }

        // Should be full
        assert!(!bucket.try_add());
    }

    #[test]
    fn test_leaky_bucket_leak() {
        let mut bucket = LeakyBucket::new(10, 10.0); // 10 per second

        // Fill bucket
        for _ in 0..10 {
            bucket.try_add();
        }

        // Wait for leak
        std::thread::sleep(Duration::from_millis(200));

        // Should have leaked some
        let level = bucket.level();
        assert!(level < 10.0);
    }
}
