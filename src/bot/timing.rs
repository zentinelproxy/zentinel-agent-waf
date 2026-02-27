//! Request Timing Analyzer
//!
//! Detects bot-like behavior based on request timing patterns:
//! - Requests too fast (inhuman speed)
//! - Perfectly regular intervals (automation)
//! - Burst patterns (attack tools)

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Timing analysis configuration
#[derive(Debug, Clone)]
pub struct TimingConfig {
    /// Minimum interval between requests (ms)
    pub min_interval_ms: u64,
    /// Window size for tracking requests
    pub window_size: usize,
    /// Maximum requests in window before flagging
    pub max_requests_in_window: usize,
    /// Window duration in seconds
    pub window_duration_secs: u64,
    /// Threshold for regular interval detection (ms variance)
    pub regularity_threshold_ms: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            min_interval_ms: 100,
            window_size: 100,
            max_requests_in_window: 50,
            window_duration_secs: 60,
            regularity_threshold_ms: 50,
        }
    }
}

/// Result of timing analysis
#[derive(Debug, Clone)]
pub struct TimingDetection {
    /// Reason for detection
    pub reason: String,
    /// Confidence score (0-100)
    pub score: u8,
}

/// Per-IP request history
#[derive(Debug)]
struct RequestHistory {
    /// Timestamps of recent requests
    timestamps: Vec<Instant>,
    /// Last request time
    last_request: Option<Instant>,
}

impl RequestHistory {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            last_request: None,
        }
    }

    fn add_request(&mut self, now: Instant, max_size: usize, window_duration: Duration) {
        // Remove old entries
        self.timestamps
            .retain(|t| now.duration_since(*t) < window_duration);

        // Add new timestamp
        if self.timestamps.len() < max_size {
            self.timestamps.push(now);
        } else {
            // Remove oldest and add new
            self.timestamps.remove(0);
            self.timestamps.push(now);
        }

        self.last_request = Some(now);
    }

    fn request_count(&self) -> usize {
        self.timestamps.len()
    }

    fn time_since_last(&self, now: Instant) -> Option<Duration> {
        self.last_request.map(|last| now.duration_since(last))
    }

    fn intervals(&self) -> Vec<Duration> {
        if self.timestamps.len() < 2 {
            return Vec::new();
        }

        self.timestamps
            .windows(2)
            .map(|w| w[1].duration_since(w[0]))
            .collect()
    }
}

/// Request timing analyzer
pub struct TimingAnalyzer {
    config: TimingConfig,
    /// Per-IP request history
    history: HashMap<String, RequestHistory>,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl TimingAnalyzer {
    /// Create a new timing analyzer
    pub fn new(config: TimingConfig) -> Self {
        Self {
            config,
            history: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Check a request for timing anomalies
    pub fn check_request(&mut self, source_ip: &str) -> Option<TimingDetection> {
        let now = Instant::now();

        // Periodic cleanup
        if now.duration_since(self.last_cleanup) > Duration::from_secs(300) {
            self.cleanup(now);
        }

        let window_duration = Duration::from_secs(self.config.window_duration_secs);

        // Get or create history for this IP
        let history = self
            .history
            .entry(source_ip.to_string())
            .or_insert_with(RequestHistory::new);

        // Check interval since last request
        let interval_info = history
            .time_since_last(now)
            .map(|interval| interval.as_millis() as u64);

        // Handle the different cases
        match interval_info {
            Some(interval_ms) if interval_ms < self.config.min_interval_ms => {
                // Too fast - add request and return detection
                history.add_request(now, self.config.window_size, window_duration);
                Some(TimingDetection {
                    reason: format!(
                        "Request too fast: {}ms (min: {}ms)",
                        interval_ms, self.config.min_interval_ms
                    ),
                    score: if interval_ms < 10 { 60 } else { 40 },
                })
            }
            Some(_) => {
                // Normal timing - add request and check for patterns
                history.add_request(now, self.config.window_size, window_duration);

                // Extract data needed for pattern checks
                let intervals = history.intervals();
                let request_count = history.request_count();

                // Drop the mutable borrow of self.history before checking patterns
                self.check_regularity_from_intervals(&intervals)
                    .or_else(|| self.check_burst_from_count(request_count))
            }
            None => {
                // First request from this IP
                history.add_request(now, self.config.window_size, window_duration);
                None
            }
        }
    }

    /// Check for suspiciously regular intervals from extracted interval data
    fn check_regularity_from_intervals(&self, intervals: &[Duration]) -> Option<TimingDetection> {
        if intervals.len() < 5 {
            return None;
        }

        // Calculate variance in intervals
        let intervals_ms: Vec<u64> = intervals.iter().map(|d| d.as_millis() as u64).collect();
        let mean = intervals_ms.iter().sum::<u64>() / intervals_ms.len() as u64;

        let variance = intervals_ms
            .iter()
            .map(|&x| {
                let diff = x.abs_diff(mean);
                diff * diff
            })
            .sum::<u64>()
            / intervals_ms.len() as u64;

        let std_dev = (variance as f64).sqrt() as u64;

        // Very low variance = automation
        if std_dev < self.config.regularity_threshold_ms && mean < 5000 {
            Some(TimingDetection {
                reason: format!(
                    "Suspiciously regular intervals: mean={}ms, stddev={}ms",
                    mean, std_dev
                ),
                score: 45,
            })
        } else {
            None
        }
    }

    /// Check for burst patterns from extracted count
    fn check_burst_from_count(&self, request_count: usize) -> Option<TimingDetection> {
        if request_count >= self.config.max_requests_in_window {
            Some(TimingDetection {
                reason: format!(
                    "Request burst: {} requests in {}s window",
                    request_count, self.config.window_duration_secs
                ),
                score: 50,
            })
        } else {
            None
        }
    }

    /// Clean up old entries
    fn cleanup(&mut self, now: Instant) {
        let window_duration = Duration::from_secs(self.config.window_duration_secs * 2);

        self.history.retain(|_, history| {
            history
                .last_request
                .map(|last| now.duration_since(last) < window_duration)
                .unwrap_or(false)
        });

        self.last_cleanup = now;
    }

    /// Get the number of tracked IPs
    pub fn tracked_ips(&self) -> usize {
        self.history.len()
    }
}

impl Default for TimingAnalyzer {
    fn default() -> Self {
        Self::new(TimingConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_too_fast_detection() {
        let config = TimingConfig {
            min_interval_ms: 100,
            ..Default::default()
        };
        let mut analyzer = TimingAnalyzer::new(config);

        // First request - no detection
        let result = analyzer.check_request("192.168.1.1");
        assert!(result.is_none());

        // Immediate second request - too fast
        let result = analyzer.check_request("192.168.1.1");
        assert!(result.is_some());
        assert!(result.unwrap().reason.contains("too fast"));
    }

    #[test]
    fn test_normal_timing() {
        let config = TimingConfig {
            min_interval_ms: 10,
            max_requests_in_window: 100,
            ..Default::default()
        };
        let mut analyzer = TimingAnalyzer::new(config);

        // First request
        analyzer.check_request("192.168.1.1");

        // Wait a bit
        sleep(Duration::from_millis(20));

        // Second request should be fine
        let result = analyzer.check_request("192.168.1.1");
        assert!(result.is_none() || !result.as_ref().unwrap().reason.contains("too fast"));
    }

    #[test]
    fn test_different_ips_independent() {
        let mut analyzer = TimingAnalyzer::new(TimingConfig::default());

        // First request from IP 1
        analyzer.check_request("192.168.1.1");

        // First request from IP 2 - should be independent
        let result = analyzer.check_request("192.168.1.2");
        assert!(result.is_none());
    }

    #[test]
    fn test_burst_detection() {
        let config = TimingConfig {
            min_interval_ms: 1, // Allow fast requests
            max_requests_in_window: 5,
            window_duration_secs: 60,
            ..Default::default()
        };
        let mut analyzer = TimingAnalyzer::new(config);

        // Send many requests
        for i in 0..10 {
            let result = analyzer.check_request("192.168.1.1");
            if i >= 5 {
                // Should detect burst after max_requests_in_window
                assert!(result.is_some(), "Should detect burst at request {}", i);
            }
        }
    }
}
