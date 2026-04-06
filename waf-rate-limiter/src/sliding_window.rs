//! Sliding Window Rate Limiter
//!
//! Sliding window algorithm implementation for smooth rate limiting.
//!
//! ## Algorithm Overview
//!
//! The sliding window provides even smoother rate limiting than fixed windows
//! by considering all requests within the last N seconds, not just the current window.
//!
//! - Maintains a queue of request timestamps
//! - On each request, removes expired timestamps
//! - Counts remaining requests in the window
//! - Allows request if count < limit, else rate limits
//!
//! ## Advantages Over Fixed Window
//!
//! - No burst at window boundaries
//! - Smoother traffic shaping
//! - More accurate limiting
//!
//! ## Use Cases
//!
//! - Smooth API rate limiting
//! - Prevention of request spikes
//! - Accurate per-second limiting

use std::collections::VecDeque;
use std::time::{Duration, Instant};
use waf_common::*;

/// Sliding window rate limiter
pub struct SlidingWindow {
    /// Maximum requests in window
    max_requests: u64,
    /// Window size in seconds
    window_seconds: u64,
    /// Request timestamps
    requests: VecDeque<Instant>,
}

impl SlidingWindow {
    /// Create a new sliding window
    pub fn new(max_requests: u64, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
            requests: VecDeque::new(),
        }
    }

    /// Check if request is allowed and record it
    pub fn check(&mut self) -> bool {
        self.cleanup();

        if self.requests.len() < self.max_requests as usize {
            self.requests.push_back(Instant::now());
            true
        } else {
            false
        }
    }

    /// Get number of requests in current window
    pub fn count(&self) -> u64 {
        self.requests.len() as u64
    }

    /// Get remaining requests
    pub fn remaining(&self) -> u64 {
        self.max_requests.saturating_sub(self.count())
    }

    /// Get time until oldest request expires
    pub fn time_until_reset(&self) -> Option<Duration> {
        self.requests.front().map(|oldest| {
            let window = Duration::from_secs(self.window_seconds);
            let elapsed = oldest.elapsed();
            if elapsed >= window {
                Duration::ZERO
            } else {
                window - elapsed
            }
        })
    }

    /// Clean up expired requests
    fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(self.window_seconds);
        while self.requests.front().map(|t| *t < cutoff).unwrap_or(false) {
            self.requests.pop_front();
        }
    }

    /// Reset the window
    pub fn reset(&mut self) {
        self.requests.clear();
    }

    /// Get rate limit info
    pub fn get_info(&self) -> RateLimitInfo {
        self.cleanup();
        RateLimitInfo {
            request_count: self.count(),
            limit: self.max_requests,
            window_seconds: self.window_seconds,
            remaining: self.remaining(),
            exceeded: self.count() >= self.max_requests,
            reset_at: chrono::Utc::now()
                + chrono::Duration::seconds(
                    self.time_until_reset().unwrap_or_default().as_secs() as i64
                ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sliding_window_basic() {
        let mut window = SlidingWindow::new(5, 60);

        // Should allow up to 5 requests
        for _ in 0..5 {
            assert!(window.check());
        }

        // 6th should be blocked
        assert!(!window.check());
    }

    #[test]
    fn test_sliding_window_expiry() {
        let mut window = SlidingWindow::new(2, 1);

        assert!(window.check());
        assert!(window.check());
        assert!(!window.check());

        // After 1 second, should allow again
        std::thread::sleep(Duration::from_secs(2));

        assert!(window.check());
    }
}
