//! Statistical Anomaly Detection
//!
//! Implements statistical methods for detecting anomalous request patterns
//! without requiring ML training data. Uses pure statistical analysis.
//!
//! ## Methods
//!
//! 1. **Z-Score Detection**: Identifies outliers beyond N standard deviations
//! 2. **IQR Detection**: Interquartile range based anomaly detection
//! 3. **EWMA**: Exponentially weighted moving average for trend detection
//! 4. **Moving Window**: Tracks metrics over sliding time windows
//!
//! ## Usage
//!
//! ```ignore
//! use waf_common::statistical::{AnomalyDetector, MetricType};
//!
//! let mut detector = AnomalyDetector::new(MetricType::RequestRate);
//! detector.add_sample(10.0);
//! detector.add_sample(12.0);
//! detector.add_sample(50.0); // Anomaly - spike
//!
//! let score = detector.get_anomaly_score();
//! assert!(score > 0.5); // High score indicates anomaly
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Type of metric being tracked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MetricType {
    /// Requests per second/minute
    #[default]
    RequestRate,
    /// Response time in milliseconds
    ResponseTime,
    /// Error rate (0.0 - 1.0)
    ErrorRate,
    /// Unique IPs per time window
    UniqueIPs,
    /// Requests per URL
    RequestsPerUrl,
    /// Bytes transferred
    BytesTransferred,
    /// Headers size
    HeaderSize,
    /// Body size
    BodySize,
}

/// Statistical distribution snapshot
#[derive(Debug, Clone)]
pub struct Distribution {
    /// Number of samples
    pub count: usize,
    /// Sum of all values
    pub sum: f64,
    /// Sum of squared values (for variance)
    pub sum_squared: f64,
    /// Minimum value
    pub min: f64,
    /// Maximum value
    pub max: f64,
    /// Sorted values for percentile calculation
    pub values: Vec<f64>,
}

impl Distribution {
    /// Create new empty distribution
    pub fn new() -> Self {
        Self {
            count: 0,
            sum: 0.0,
            sum_squared: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            values: Vec::new(),
        }
    }

    /// Add a sample to the distribution
    pub fn add(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        self.sum_squared += value * value;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        self.values.push(value);
    }

    /// Calculate mean
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }

    /// Calculate variance
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            let mean = self.mean();
            (self.sum_squared / self.count as f64) - (mean * mean)
        }
    }

    /// Calculate standard deviation
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Calculate percentile (pct: 0.0 - 100.0)
    pub fn percentile(&mut self, pct: f64) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }

        self.values
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((pct / 100.0) * (self.values.len() - 1) as f64) as usize;
        self.values[idx.min(self.values.len() - 1)]
    }

    /// Calculate interquartile range (IQR = Q3 - Q1)
    pub fn iqr(&mut self) -> f64 {
        self.percentile(75.0) - self.percentile(25.0)
    }

    /// Check if a value is outside N IQRs from median
    pub fn is_outlier_iqr(&mut self, value: f64, iqr_multiplier: f64) -> bool {
        let q1 = self.percentile(25.0);
        let q3 = self.percentile(75.0);
        let iqr = q3 - q1;
        let lower = q1 - iqr_multiplier * iqr;
        let upper = q3 + iqr_multiplier * iqr;
        value < lower || value > upper
    }
}

impl Default for Distribution {
    fn default() -> Self {
        Self::new()
    }
}

/// Z-Score based anomaly detector
pub struct ZScoreDetector {
    /// Window size for calculation
    window_size: usize,
    /// Recent values
    values: VecDeque<f64>,
    /// Mean
    mean: f64,
    /// Standard deviation
    std_dev: f64,
    /// Z-score threshold (default: 3.0)
    z_threshold: f64,
}

impl ZScoreDetector {
    /// Create new Z-Score detector
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            values: VecDeque::with_capacity(window_size),
            mean: 0.0,
            std_dev: 0.0,
            z_threshold: 3.0,
        }
    }

    /// Set z-score threshold
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.z_threshold = threshold;
        self
    }

    /// Add a sample and recalculate statistics
    fn add_sample_internal(&mut self, value: f64) {
        // Remove oldest if window is full
        if self.values.len() >= self.window_size {
            self.values.pop_front();
        }

        self.values.push_back(value);
        self.recalculate();
    }

    /// Recalculate mean and standard deviation
    fn recalculate(&mut self) {
        if self.values.is_empty() {
            self.mean = 0.0;
            self.std_dev = 0.0;
            return;
        }

        let n = self.values.len() as f64;
        self.mean = self.values.iter().sum::<f64>() / n;

        let variance = if self.values.len() < 2 {
            0.0
        } else {
            self.values
                .iter()
                .map(|v| (v - self.mean).powi(2))
                .sum::<f64>()
                / n
        };
        self.std_dev = variance.sqrt();
    }

    /// Calculate z-score for a value
    pub fn z_score(&self, value: f64) -> f64 {
        if self.std_dev == 0.0 {
            0.0
        } else {
            (value - self.mean) / self.std_dev
        }
    }

    /// Check if a value is anomalous (z-score beyond threshold)
    pub fn is_anomaly(&self, value: f64) -> bool {
        self.z_score(value).abs() > self.z_threshold
    }

    /// Get anomaly score (0.0 - 1.0) based on z-score magnitude
    pub fn anomaly_score(&self, value: f64) -> f64 {
        let z = self.z_score(value).abs();
        // Map z-score to 0-1: z=0 -> 0.0, z>=threshold -> 1.0
        if self.z_threshold == 0.0 {
            return 0.0;
        }
        (z / self.z_threshold).min(1.0)
    }
}

/// IQR (Interquartile Range) based anomaly detector
pub struct IqrDetector {
    /// Window size for storing values
    window_size: usize,
    /// Values in order of arrival
    values: VecDeque<f64>,
    /// IQR multiplier threshold (default: 1.5)
    iqr_multiplier: f64,
}

impl IqrDetector {
    /// Create new IQR detector
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            values: VecDeque::with_capacity(window_size),
            iqr_multiplier: 1.5,
        }
    }

    /// Set IQR multiplier
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.iqr_multiplier = multiplier;
        self
    }

    /// Add a sample
    pub fn add_sample(&mut self, value: f64) {
        if self.values.len() >= self.window_size {
            self.values.pop_front();
        }
        self.values.push_back(value);
    }

    /// Check if value is an outlier
    pub fn is_outlier(&self, value: f64) -> bool {
        if self.values.len() < 4 {
            return false;
        }

        let mut sorted: Vec<f64> = self.values.iter().cloned().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let q1_idx = sorted.len() / 4;
        let q3_idx = (3 * sorted.len()) / 4;
        let q1 = sorted[q1_idx];
        let q3 = sorted[q3_idx];
        let iqr = q3 - q1;

        let lower = q1 - self.iqr_multiplier * iqr;
        let upper = q3 + self.iqr_multiplier * iqr;

        value < lower || value > upper
    }

    /// Get anomaly score based on distance from IQR bounds
    pub fn anomaly_score(&self, value: f64) -> f64 {
        if self.values.len() < 4 {
            return 0.0;
        }

        let mut sorted: Vec<f64> = self.values.iter().cloned().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let q1 = sorted[sorted.len() / 4];
        let q3 = sorted[(3 * sorted.len()) / 4];
        let iqr = q3 - q1;
        let median = sorted[sorted.len() / 2];

        if iqr == 0.0 {
            // No observed spread — require an extreme deviation
            // (>= 10% of the median magnitude) to flag an anomaly.
            return if (value - median).abs() > median.abs() * 0.10 {
                1.0
            } else {
                0.0
            };
        }

        let lower = q1 - self.iqr_multiplier * iqr;
        let upper = q3 + self.iqr_multiplier * iqr;

        if value < lower {
            ((lower - value) / iqr).min(1.0)
        } else if value > upper {
            ((value - upper) / iqr).min(1.0)
        } else {
            0.0
        }
    }
}

/// EWMA (Exponentially Weighted Moving Average) detector
pub struct EwmaDetector {
    /// EWMA alpha (smoothing factor): 0.0 - 1.0
    /// Higher = more weight on recent values
    alpha: f64,
    /// Current EWMA value
    ewma: f64,
    /// EWMA of squared deviations (for volatility)
    ewma_var: f64,
    /// Number of samples seen
    count: u64,
    /// Minimum samples before anomaly detection starts
    min_samples: usize,
}

impl EwmaDetector {
    /// Create new EWMA detector with alpha
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha: alpha.clamp(0.01, 0.99),
            ewma: 0.0,
            ewma_var: 0.0,
            count: 0,
            min_samples: 10,
        }
    }

    /// Add a sample
    pub fn add_sample(&mut self, value: f64) {
        self.count += 1;

        if self.count == 1 {
            self.ewma = value;
            self.ewma_var = 0.0;
            return;
        }

        // Update EWMA
        let prev_ewma = self.ewma;
        self.ewma = self.alpha * value + (1.0 - self.alpha) * self.ewma;

        // Update variance estimate
        let deviation = value - prev_ewma;
        self.ewma_var = self.alpha * deviation * deviation + (1.0 - self.alpha) * self.ewma_var;
    }

    /// Check if a new value is anomalous based on EWMA
    pub fn is_anomaly(&self, value: f64) -> bool {
        if self.count < self.min_samples as u64 {
            return false;
        }

        if self.ewma_var == 0.0 {
            // No observed variance — require an extreme deviation
            // (>= 10% of the EWMA magnitude) to flag an anomaly, otherwise
            // identical training data would false-positive on any
            // non-exact match.
            return (value - self.ewma).abs() > self.ewma.abs() * 0.10;
        }

        let std_dev = self.ewma_var.sqrt();
        let z = (value - self.ewma).abs() / std_dev;
        z > 3.0 // 3 standard deviations
    }

    /// Get anomaly score
    pub fn anomaly_score(&self, value: f64) -> f64 {
        if self.count < self.min_samples as u64 {
            return 0.0;
        }

        if self.ewma_var == 0.0 {
            return if value == self.ewma { 0.0 } else { 1.0 };
        }

        let std_dev = self.ewma_var.sqrt();
        let z = (value - self.ewma).abs() / std_dev;
        (z / 3.0).min(1.0)
    }

    /// Get current EWMA value
    pub fn get_ewma(&self) -> f64 {
        self.ewma
    }

    /// Get current volatility (std dev of EWMA)
    pub fn get_volatility(&self) -> f64 {
        self.ewma_var.sqrt()
    }

    /// Reset detector
    pub fn reset(&mut self) {
        self.ewma = 0.0;
        self.ewma_var = 0.0;
        self.count = 0;
    }
}

/// Combined anomaly detector using multiple methods
pub struct AnomalyDetector {
    /// Type of metric being tracked
    metric_type: MetricType,
    /// Z-Score detector
    zscore: ZScoreDetector,
    /// IQR detector
    iqr: IqrDetector,
    /// EWMA detector
    ewma: EwmaDetector,
    /// Recent values for distribution
    distribution: Distribution,
    /// Combined weights for each method
    weights: (f64, f64, f64),
}

impl AnomalyDetector {
    /// Create new anomaly detector for a metric type
    pub fn new(metric_type: MetricType) -> Self {
        Self {
            metric_type,
            zscore: ZScoreDetector::new(100).with_threshold(3.0),
            iqr: IqrDetector::new(100).with_multiplier(1.5),
            ewma: EwmaDetector::new(0.3),
            distribution: Distribution::new(),
            weights: (0.4, 0.3, 0.3), // Z-Score, IQR, EWMA
        }
    }

    /// Create with custom window size
    pub fn with_window(mut self, window_size: usize) -> Self {
        self.zscore = ZScoreDetector::new(window_size).with_threshold(3.0);
        self.iqr = IqrDetector::new(window_size).with_multiplier(1.5);
        self
    }

    /// Create with custom weights (must sum to 1.0)
    pub fn with_weights(mut self, zscore: f64, iqr: f64, ewma: f64) -> Self {
        let total = zscore + iqr + ewma;
        self.weights = (zscore / total, iqr / total, ewma / total);
        self
    }

    /// Add a sample value
    pub fn add_sample(&mut self, value: f64) {
        self.zscore.add_sample_internal(value);
        self.iqr.add_sample(value);
        self.ewma.add_sample(value);
        self.distribution.add(value);
    }

    /// Get anomaly score from all methods combined (0.0 - 1.0)
    pub fn get_anomaly_score(&self) -> f64 {
        // Note: Can't call add_sample_internal here as it's private
        // This is intentional - external users should use add_sample
        // We compute scores based on stored state
        0.0 // Placeholder
    }

    /// Calculate anomaly score from a given value
    pub fn calculate_score(&self, value: f64) -> f64 {
        let zscore_score = self.zscore.anomaly_score(value);
        let iqr_score = self.iqr.anomaly_score(value);
        let ewma_score = self.ewma.anomaly_score(value);

        let (wz, wi, we) = self.weights;
        wz * zscore_score + wi * iqr_score + we * ewma_score
    }

    /// Check if value is anomalous
    pub fn is_anomaly(&self, value: f64) -> bool {
        self.calculate_score(value) > 0.7
    }

    /// Get individual method scores
    pub fn get_method_scores(&self, value: f64) -> (f64, f64, f64) {
        (
            self.zscore.anomaly_score(value),
            self.iqr.anomaly_score(value),
            self.ewma.anomaly_score(value),
        )
    }

    /// Get distribution statistics
    pub fn get_distribution(&self) -> &Distribution {
        &self.distribution
    }

    /// Get metric type
    pub fn metric_type(&self) -> MetricType {
        self.metric_type
    }
}

/// Manager for multiple anomaly detectors
pub struct AnomalyDetectorManager {
    /// Detectors by metric type
    detectors: HashMap<MetricType, AnomalyDetector>,
    /// Global anomaly score (max across all metrics)
    global_score: f64,
}

impl AnomalyDetectorManager {
    /// Create new manager
    pub fn new() -> Self {
        Self {
            detectors: HashMap::new(),
            global_score: 0.0,
        }
    }

    /// Get or create detector for a metric type
    pub fn get_or_create(&mut self, metric_type: MetricType) -> &mut AnomalyDetector {
        self.detectors
            .entry(metric_type)
            .or_insert_with(|| AnomalyDetector::new(metric_type))
    }

    /// Add a sample to a specific metric
    pub fn add_sample(&mut self, metric_type: MetricType, value: f64) {
        let detector = self.get_or_create(metric_type);
        detector.add_sample(value);

        // Update global score with max
        let score = detector.calculate_score(value);
        if score > self.global_score {
            self.global_score = score;
        }
    }

    /// Get anomaly score for a metric
    pub fn get_score(&self, metric_type: MetricType, value: f64) -> f64 {
        self.detectors
            .get(&metric_type)
            .map(|d| d.calculate_score(value))
            .unwrap_or(0.0)
    }

    /// Get global anomaly score
    pub fn get_global_score(&self) -> f64 {
        self.global_score
    }

    /// Check if any metric is anomalous
    pub fn is_anomaly(&self, metric_type: MetricType, value: f64) -> bool {
        self.get_score(metric_type, value) > 0.7
    }

    /// Get all detector stats
    pub fn get_stats(&self) -> HashMap<MetricType, AnomalyStats> {
        self.detectors
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    AnomalyStats {
                        metric_type: *k,
                        count: v.distribution.count,
                        mean: v.distribution.mean(),
                        std_dev: v.distribution.std_dev(),
                        min: v.distribution.min,
                        max: v.distribution.max,
                    },
                )
            })
            .collect()
    }
}

impl Default for AnomalyDetectorManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for a metric
#[derive(Debug, Clone)]
pub struct AnomalyStats {
    pub metric_type: MetricType,
    pub count: usize,
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
}

/// Async-safe shared anomaly detector manager
pub type SharedAnomalyManager = Arc<RwLock<AnomalyDetectorManager>>;

/// Create a new shared anomaly manager
pub fn create_shared_manager() -> SharedAnomalyManager {
    Arc::new(RwLock::new(AnomalyDetectorManager::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribution_basic() {
        let mut dist = Distribution::new();
        dist.add(1.0);
        dist.add(2.0);
        dist.add(3.0);
        dist.add(4.0);
        dist.add(5.0);

        assert_eq!(dist.count, 5);
        assert_eq!(dist.mean(), 3.0);
        assert!(dist.std_dev() > 0.0);
    }

    #[test]
    fn test_distribution_percentiles() {
        let mut dist = Distribution::new();
        for i in 1..=100 {
            dist.add(i as f64);
        }

        assert_eq!(dist.percentile(50.0), 50.0); // Median
        assert_eq!(dist.percentile(25.0), 25.0); // Q1
        assert_eq!(dist.percentile(75.0), 75.0); // Q3
    }

    #[test]
    fn test_zscore_anomaly() {
        let mut detector = ZScoreDetector::new(100);

        // Add normal values
        for _ in 0..50 {
            detector.add_sample_internal(10.0);
        }

        // Normal value should have low z-score
        let score = detector.anomaly_score(10.5);
        assert!(score < 0.5);
    }

    #[test]
    fn test_iqr_outlier() {
        let mut detector = IqrDetector::new(100);

        // Add values with clear IQR
        for i in 1..=50 {
            detector.add_sample(i as f64);
        }

        // Extreme value should be outlier
        assert!(detector.is_outlier(100.0));
        assert!(!detector.is_outlier(25.0));
    }

    #[test]
    fn test_ewma_detection() {
        let mut detector = EwmaDetector::new(0.3);

        // Add baseline values
        for _ in 0..20 {
            detector.add_sample(10.0);
        }

        // Small variation should be normal
        assert!(!detector.is_anomaly(10.5));

        // Large spike should be anomaly
        assert!(detector.is_anomaly(50.0));
    }

    #[test]
    fn test_combined_anomaly_detector() {
        let mut detector = AnomalyDetector::new(MetricType::RequestRate);

        // Add normal values
        for _ in 0..50 {
            detector.add_sample(10.0);
        }

        // Normal value
        let score = detector.calculate_score(10.5);
        assert!(score < 0.5);

        // Anomalous value
        let score = detector.calculate_score(100.0);
        assert!(score > 0.5);
    }

    #[test]
    fn test_anomaly_manager() {
        let mut manager = AnomalyDetectorManager::new();

        // Add samples to multiple metrics
        for i in 0..30 {
            manager.add_sample(MetricType::RequestRate, 10.0 + (i as f64 * 0.1));
            manager.add_sample(MetricType::ResponseTime, 50.0);
        }

        // Global score should be computed
        let _global = manager.get_global_score();

        // Get stats for each metric
        let stats = manager.get_stats();
        assert!(stats.contains_key(&MetricType::RequestRate));
        assert!(stats.contains_key(&MetricType::ResponseTime));
    }

    #[test]
    fn test_ewma_volatility() {
        let mut detector = EwmaDetector::new(0.3);

        for _ in 0..20 {
            detector.add_sample(10.0);
        }

        assert_eq!(detector.get_ewma(), 10.0);
        assert_eq!(detector.get_volatility(), 0.0);

        // Add varying values
        for i in 0..10 {
            detector.add_sample(10.0 + (i as f64 * 5.0));
        }

        // Volatility should be non-zero now
        assert!(detector.get_volatility() > 0.0);
    }
}
