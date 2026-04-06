# WAF Stress Testing Suite

use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct StressTestConfig {
    pub target_url: String,
    pub num_requests: usize,
    pub concurrency: usize,
    pub slow: bool,  // Simulate slow requests
}

pub struct StressTestResults {
    pub total_requests: usize,
    pub successful: usize,
    pub failed: usize,
    pub blocked: usize,
    pub duration_ms: u64,
    pub requests_per_second: f64,
}

pub fn run_stress_test(config: StressTestConfig) -> StressTestResults {
    let start = Instant::now();
    let counter = Arc::new(AtomicUsize::new(0));
    let success = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let blocked = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Launch concurrent workers
    let handles: Vec<_> = (0..config.concurrency)
        .map(|i| {
            let counter = counter.clone();
            let success = success.clone();
            let failed = failed.clone();
            let blocked = blocked.clone();
            let stop = stop.clone();
            let config = config.clone();

            std::thread::spawn(move || {
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .unwrap();

                let requests_per_worker = config.num_requests / config.concurrency;

                for j in 0..requests_per_worker {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    counter.fetch_add(1, Ordering::Relaxed);

                    // Build attack URL
                    let url = match i % 5 {
                        0 => format!("{}?id=1 UNION SELECT * FROM users", config.target_url),
                        1 => format!("{}?q=<script>alert(1)</script>", config.target_url),
                        2 => format!("{}?file=../../etc/passwd", config.target_url),
                        3 => format!("{}?cmd=|nc -e /bin/bash", config.target_url),
                        _ => config.target_url.clone(),
                    };

                    match client.get(&url).send() {
                        Ok(resp) => {
                            if resp.status().as_u16() == 403 {
                                blocked.fetch_add(1, Ordering::Relaxed);
                            } else {
                                success.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    if config.slow {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            })
        })
        .collect();

    // Wait for completion
    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();

    StressTestResults {
        total_requests: counter.load(Ordering::Relaxed),
        successful: success.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
        blocked: blocked.load(Ordering::Relaxed),
        duration_ms: duration.as_millis() as u64,
        requests_per_second: counter.load(Ordering::Relaxing) as f64 / duration.as_secs_f64(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stress_config() {
        let config = StressTestConfig {
            target_url: "http://localhost:8080".to_string(),
            num_requests: 1000,
            concurrency: 10,
            slow: false,
        };
        assert_eq!(config.num_requests, 1000);
    }
}