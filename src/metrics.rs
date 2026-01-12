//! WAF Metrics and Analytics
//!
//! Provides comprehensive metrics collection for monitoring and alerting:
//! - Request/response counters
//! - Detection statistics
//! - Latency histograms
//! - Attack categorization
//!
//! Supports multiple export formats:
//! - Prometheus text format
//! - JSON format
//! - OpenTelemetry (future)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Metrics configuration
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Enable per-rule metrics
    pub per_rule_metrics: bool,
    /// Enable latency histograms
    pub latency_histograms: bool,
    /// Histogram bucket boundaries (ms)
    pub histogram_buckets: Vec<f64>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_rule_metrics: true,
            latency_histograms: true,
            histogram_buckets: vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0],
        }
    }
}

/// WAF metrics collector
pub struct WafMetrics {
    config: MetricsConfig,

    // Request counters
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    requests_logged: AtomicU64,
    requests_allowed: AtomicU64,

    // Detection counters
    detections_total: AtomicU64,

    // Per-rule counters
    detections_by_rule: RwLock<HashMap<u32, u64>>,

    // Per-attack-type counters
    attacks_by_type: RwLock<HashMap<String, u64>>,

    // Per-source counters (top offenders)
    attacks_by_source: RwLock<HashMap<String, u64>>,

    // Latency tracking
    latency_histogram: RwLock<Histogram>,

    // Phase timing
    phase_latencies: RwLock<HashMap<String, Histogram>>,

    // Error counters
    errors_total: AtomicU64,
    errors_by_type: RwLock<HashMap<String, u64>>,

    // Start time for uptime calculation
    start_time: Instant,
}

impl WafMetrics {
    /// Create a new metrics collector
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config: config.clone(),
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_logged: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            detections_total: AtomicU64::new(0),
            detections_by_rule: RwLock::new(HashMap::new()),
            attacks_by_type: RwLock::new(HashMap::new()),
            attacks_by_source: RwLock::new(HashMap::new()),
            latency_histogram: RwLock::new(Histogram::new(config.histogram_buckets.clone())),
            phase_latencies: RwLock::new(HashMap::new()),
            errors_total: AtomicU64::new(0),
            errors_by_type: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }

    /// Record a request
    pub fn record_request(&self, decision: RequestDecision) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        match decision {
            RequestDecision::Blocked => {
                self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            }
            RequestDecision::Logged => {
                self.requests_logged.fetch_add(1, Ordering::Relaxed);
            }
            RequestDecision::Allowed => {
                self.requests_allowed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record detections
    pub fn record_detections(&self, detections: &[DetectionRecord]) {
        let count = detections.len() as u64;
        self.detections_total.fetch_add(count, Ordering::Relaxed);

        if self.config.per_rule_metrics {
            let mut by_rule = self.detections_by_rule.write();
            for detection in detections {
                *by_rule.entry(detection.rule_id).or_insert(0) += 1;
            }
        }

        let mut by_type = self.attacks_by_type.write();
        for detection in detections {
            *by_type.entry(detection.attack_type.clone()).or_insert(0) += 1;
        }
    }

    /// Record source IP for attack tracking
    pub fn record_attack_source(&self, source: &str) {
        let mut by_source = self.attacks_by_source.write();
        *by_source.entry(source.to_string()).or_insert(0) += 1;
    }

    /// Record inspection latency
    pub fn record_latency(&self, duration: Duration) {
        if self.config.latency_histograms {
            let ms = duration.as_secs_f64() * 1000.0;
            let mut histogram = self.latency_histogram.write();
            histogram.observe(ms);
        }
    }

    /// Record phase-specific latency
    pub fn record_phase_latency(&self, phase: &str, duration: Duration) {
        if self.config.latency_histograms {
            let ms = duration.as_secs_f64() * 1000.0;
            let mut latencies = self.phase_latencies.write();
            let histogram = latencies
                .entry(phase.to_string())
                .or_insert_with(|| Histogram::new(self.config.histogram_buckets.clone()));
            histogram.observe(ms);
        }
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
        let mut errors = self.errors_by_type.write();
        *errors.entry(error_type.to_string()).or_insert(0) += 1;
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Export metrics in Prometheus text format
    pub fn prometheus(&self) -> String {
        let mut output = String::new();

        // Request metrics
        output.push_str("# HELP waf_requests_total Total number of requests processed\n");
        output.push_str("# TYPE waf_requests_total counter\n");
        output.push_str(&format!(
            "waf_requests_total {}\n",
            self.requests_total.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP waf_requests_blocked Total number of blocked requests\n");
        output.push_str("# TYPE waf_requests_blocked counter\n");
        output.push_str(&format!(
            "waf_requests_blocked {}\n",
            self.requests_blocked.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP waf_requests_logged Total number of logged requests\n");
        output.push_str("# TYPE waf_requests_logged counter\n");
        output.push_str(&format!(
            "waf_requests_logged {}\n",
            self.requests_logged.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP waf_requests_allowed Total number of allowed requests\n");
        output.push_str("# TYPE waf_requests_allowed counter\n");
        output.push_str(&format!(
            "waf_requests_allowed {}\n",
            self.requests_allowed.load(Ordering::Relaxed)
        ));

        // Detection metrics
        output.push_str("# HELP waf_detections_total Total number of attack detections\n");
        output.push_str("# TYPE waf_detections_total counter\n");
        output.push_str(&format!(
            "waf_detections_total {}\n",
            self.detections_total.load(Ordering::Relaxed)
        ));

        // Attacks by type
        output.push_str("# HELP waf_attacks_by_type Attacks detected by type\n");
        output.push_str("# TYPE waf_attacks_by_type counter\n");
        let by_type = self.attacks_by_type.read();
        for (attack_type, count) in by_type.iter() {
            output.push_str(&format!(
                "waf_attacks_by_type{{type=\"{}\"}} {}\n",
                attack_type, count
            ));
        }

        // Detections by rule
        if self.config.per_rule_metrics {
            output.push_str("# HELP waf_detections_by_rule Detections by rule ID\n");
            output.push_str("# TYPE waf_detections_by_rule counter\n");
            let by_rule = self.detections_by_rule.read();
            for (rule_id, count) in by_rule.iter() {
                output.push_str(&format!(
                    "waf_detections_by_rule{{rule_id=\"{}\"}} {}\n",
                    rule_id, count
                ));
            }
        }

        // Latency histogram
        if self.config.latency_histograms {
            output.push_str("# HELP waf_inspection_latency_ms Request inspection latency in milliseconds\n");
            output.push_str("# TYPE waf_inspection_latency_ms histogram\n");
            let histogram = self.latency_histogram.read();
            for (bound, count) in histogram.buckets() {
                output.push_str(&format!(
                    "waf_inspection_latency_ms_bucket{{le=\"{}\"}} {}\n",
                    bound, count
                ));
            }
            output.push_str(&format!(
                "waf_inspection_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
                histogram.count()
            ));
            output.push_str(&format!(
                "waf_inspection_latency_ms_sum {}\n",
                histogram.sum()
            ));
            output.push_str(&format!(
                "waf_inspection_latency_ms_count {}\n",
                histogram.count()
            ));
        }

        // Error metrics
        output.push_str("# HELP waf_errors_total Total number of errors\n");
        output.push_str("# TYPE waf_errors_total counter\n");
        output.push_str(&format!(
            "waf_errors_total {}\n",
            self.errors_total.load(Ordering::Relaxed)
        ));

        // Uptime
        output.push_str("# HELP waf_uptime_seconds Seconds since WAF started\n");
        output.push_str("# TYPE waf_uptime_seconds gauge\n");
        output.push_str(&format!("waf_uptime_seconds {}\n", self.uptime_secs()));

        output
    }

    /// Export metrics as JSON
    pub fn json(&self) -> serde_json::Value {
        let histogram = self.latency_histogram.read();
        let by_type = self.attacks_by_type.read();
        let by_rule = self.detections_by_rule.read();
        let by_source = self.attacks_by_source.read();
        let errors = self.errors_by_type.read();

        serde_json::json!({
            "requests": {
                "total": self.requests_total.load(Ordering::Relaxed),
                "blocked": self.requests_blocked.load(Ordering::Relaxed),
                "logged": self.requests_logged.load(Ordering::Relaxed),
                "allowed": self.requests_allowed.load(Ordering::Relaxed)
            },
            "detections": {
                "total": self.detections_total.load(Ordering::Relaxed),
                "by_type": by_type.clone(),
                "by_rule": by_rule.iter().map(|(k, v)| (k.to_string(), *v)).collect::<HashMap<String, u64>>()
            },
            "top_offenders": by_source.iter()
                .take(10)
                .map(|(k, v)| (k.clone(), *v))
                .collect::<HashMap<String, u64>>(),
            "latency": {
                "p50_ms": histogram.percentile(50.0),
                "p90_ms": histogram.percentile(90.0),
                "p99_ms": histogram.percentile(99.0),
                "mean_ms": histogram.mean(),
                "count": histogram.count()
            },
            "errors": {
                "total": self.errors_total.load(Ordering::Relaxed),
                "by_type": errors.clone()
            },
            "uptime_seconds": self.uptime_secs()
        })
    }

    /// Get summary statistics
    pub fn summary(&self) -> MetricsSummary {
        let histogram = self.latency_histogram.read();

        MetricsSummary {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_blocked: self.requests_blocked.load(Ordering::Relaxed),
            requests_logged: self.requests_logged.load(Ordering::Relaxed),
            requests_allowed: self.requests_allowed.load(Ordering::Relaxed),
            detections_total: self.detections_total.load(Ordering::Relaxed),
            latency_p50_ms: histogram.percentile(50.0),
            latency_p99_ms: histogram.percentile(99.0),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            uptime_secs: self.uptime_secs(),
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.requests_total.store(0, Ordering::Relaxed);
        self.requests_blocked.store(0, Ordering::Relaxed);
        self.requests_logged.store(0, Ordering::Relaxed);
        self.requests_allowed.store(0, Ordering::Relaxed);
        self.detections_total.store(0, Ordering::Relaxed);
        self.errors_total.store(0, Ordering::Relaxed);

        self.detections_by_rule.write().clear();
        self.attacks_by_type.write().clear();
        self.attacks_by_source.write().clear();
        self.errors_by_type.write().clear();

        *self.latency_histogram.write() =
            Histogram::new(self.config.histogram_buckets.clone());
    }
}

impl Default for WafMetrics {
    fn default() -> Self {
        Self::new(MetricsConfig::default())
    }
}

/// Request decision for metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDecision {
    Blocked,
    Logged,
    Allowed,
}

/// Detection record for metrics
#[derive(Debug, Clone)]
pub struct DetectionRecord {
    pub rule_id: u32,
    pub attack_type: String,
}

/// Summary of metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub requests_total: u64,
    pub requests_blocked: u64,
    pub requests_logged: u64,
    pub requests_allowed: u64,
    pub detections_total: u64,
    pub latency_p50_ms: f64,
    pub latency_p99_ms: f64,
    pub errors_total: u64,
    pub uptime_secs: u64,
}

/// Simple histogram implementation
struct Histogram {
    buckets: Vec<(f64, u64)>,
    sum: f64,
    count: u64,
    values: Vec<f64>, // For percentile calculation
}

impl Histogram {
    fn new(bucket_bounds: Vec<f64>) -> Self {
        let buckets = bucket_bounds.into_iter().map(|b| (b, 0u64)).collect();
        Self {
            buckets,
            sum: 0.0,
            count: 0,
            values: Vec::new(),
        }
    }

    fn observe(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;
        self.values.push(value);

        // Keep values bounded for memory
        if self.values.len() > 10000 {
            self.values.remove(0);
        }

        for (bound, count) in &mut self.buckets {
            if value <= *bound {
                *count += 1;
            }
        }
    }

    fn buckets(&self) -> impl Iterator<Item = (f64, u64)> + '_ {
        self.buckets.iter().copied()
    }

    fn sum(&self) -> f64 {
        self.sum
    }

    fn count(&self) -> u64 {
        self.count
    }

    fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }

    fn percentile(&self, p: f64) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }

        let mut sorted = self.values.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_recording() {
        let metrics = WafMetrics::default();

        metrics.record_request(RequestDecision::Allowed);
        metrics.record_request(RequestDecision::Blocked);
        metrics.record_request(RequestDecision::Logged);
        metrics.record_request(RequestDecision::Allowed);

        let summary = metrics.summary();
        assert_eq!(summary.requests_total, 4);
        assert_eq!(summary.requests_blocked, 1);
        assert_eq!(summary.requests_logged, 1);
        assert_eq!(summary.requests_allowed, 2);
    }

    #[test]
    fn test_detection_recording() {
        let metrics = WafMetrics::default();

        metrics.record_detections(&[
            DetectionRecord {
                rule_id: 941100,
                attack_type: "xss".to_string(),
            },
            DetectionRecord {
                rule_id: 942100,
                attack_type: "sqli".to_string(),
            },
            DetectionRecord {
                rule_id: 941100,
                attack_type: "xss".to_string(),
            },
        ]);

        let summary = metrics.summary();
        assert_eq!(summary.detections_total, 3);

        let json = metrics.json();
        let by_type = json["detections"]["by_type"].as_object().unwrap();
        assert_eq!(by_type["xss"], 2);
        assert_eq!(by_type["sqli"], 1);
    }

    #[test]
    fn test_latency_recording() {
        let metrics = WafMetrics::default();

        for ms in [1, 2, 3, 4, 5, 10, 20, 50, 100] {
            metrics.record_latency(Duration::from_millis(ms));
        }

        let summary = metrics.summary();
        assert!(summary.latency_p50_ms > 0.0);
        assert!(summary.latency_p99_ms > 0.0);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = WafMetrics::default();

        metrics.record_request(RequestDecision::Blocked);
        metrics.record_detections(&[DetectionRecord {
            rule_id: 941100,
            attack_type: "xss".to_string(),
        }]);

        let prom = metrics.prometheus();
        assert!(prom.contains("waf_requests_total 1"));
        assert!(prom.contains("waf_requests_blocked 1"));
        assert!(prom.contains("waf_detections_total 1"));
    }

    #[test]
    fn test_json_export() {
        let metrics = WafMetrics::default();

        metrics.record_request(RequestDecision::Allowed);

        let json = metrics.json();
        assert_eq!(json["requests"]["total"], 1);
        assert_eq!(json["requests"]["allowed"], 1);
    }

    #[test]
    fn test_error_recording() {
        let metrics = WafMetrics::default();

        metrics.record_error("timeout");
        metrics.record_error("parse_error");
        metrics.record_error("timeout");

        let summary = metrics.summary();
        assert_eq!(summary.errors_total, 3);
    }

    #[test]
    fn test_reset() {
        let metrics = WafMetrics::default();

        metrics.record_request(RequestDecision::Blocked);
        metrics.record_detections(&[DetectionRecord {
            rule_id: 1,
            attack_type: "test".to_string(),
        }]);

        metrics.reset();

        let summary = metrics.summary();
        assert_eq!(summary.requests_total, 0);
        assert_eq!(summary.detections_total, 0);
    }

    #[test]
    fn test_histogram_percentiles() {
        let mut hist = Histogram::new(vec![1.0, 5.0, 10.0]);

        for i in 1..=100 {
            hist.observe(i as f64);
        }

        assert!(hist.percentile(50.0) >= 49.0 && hist.percentile(50.0) <= 51.0);
        assert!(hist.percentile(99.0) >= 98.0);
    }

    #[test]
    fn test_attack_source_tracking() {
        let metrics = WafMetrics::default();

        metrics.record_attack_source("192.168.1.100");
        metrics.record_attack_source("192.168.1.100");
        metrics.record_attack_source("10.0.0.1");

        let json = metrics.json();
        let offenders = json["top_offenders"].as_object().unwrap();
        assert_eq!(offenders["192.168.1.100"], 2);
        assert_eq!(offenders["10.0.0.1"], 1);
    }
}
