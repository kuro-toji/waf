// Benchmark helper functions for WAF performance testing

use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Simulate request processing with given latency
pub fn simulate_request(latency_ms: u64) {
    std::thread::sleep(Duration::from_millis(latency_ms));
}

/// Measure throughput
pub fn measure_throughput<F>(duration_secs: u64, mut f: F) -> usize
where
    F: FnMut() -> bool,
{
    let counter = Arc::new(AtomicUsize::new(0));
    let end_time = Instant::now() + Duration::from_secs(duration_secs);
    
    let mut successes = 0;
    
    while Instant::now() < end_time {
        if f() {
            successes += 1;
        }
    }
    
    successes
}

/// Calculate percentiles from a collection of durations
pub fn calculate_percentiles(durations: &[Duration]) -> (Duration, Duration, Duration) {
    if durations.is_empty() {
        return (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    }
    
    let mut sorted = durations.to_vec();
    sorted.sort();
    
    let p50_idx = durations.len() * 50 / 100;
    let p95_idx = durations.len() * 95 / 100;
    let p99_idx = durations.len() * 99 / 100;
    
    (
        sorted[p50_idx],
        sorted[p95_idx.min(sorted.len() - 1)],
        sorted[p99_idx.min(sorted.len() - 1)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measure_throughput() {
        let count = measure_throughput(1, || true);
        assert!(count >= 900); // Should get at least 900 in 1 second with fast operations
    }

    #[test]
    fn test_percentiles() {
        let durations = vec![
            Duration::from_millis(1),
            Duration::from_millis(5),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(100),
        ];
        
        let (p50, p95, p99) = calculate_percentiles(&durations);
        assert_eq!(p50, Duration::from_millis(10));
    }
}