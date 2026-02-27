//! Bot Detection Module
//!
//! Detects and classifies bots beyond simple User-Agent matching:
//! - User-Agent signature analysis
//! - Request timing patterns (too fast = bot)
//! - TLS fingerprint anomalies (JA3/JA4)
//! - Header anomalies (missing expected headers)
//! - Known bot/crawler identification
//!
//! # Rule ID Ranges
//!
//! - 97000-97099: Bot signature rules
//! - 97100-97199: Behavioral rules
//! - 97200-97299: Good bot verification

pub mod signatures;
pub mod timing;

pub use signatures::{BotSignature, BotSignatureDb};
pub use timing::{TimingAnalyzer, TimingConfig};

use std::collections::HashMap;

use crate::detection::Detection;
use crate::rules::AttackType;

/// Bot detection configuration
#[derive(Debug, Clone)]
pub struct BotConfig {
    /// Enable bot signature detection
    pub signature_detection: bool,
    /// Enable timing-based detection
    pub timing_detection: bool,
    /// Enable header anomaly detection
    pub header_anomaly_detection: bool,
    /// Minimum time between requests (ms) before flagging
    pub min_request_interval_ms: u64,
    /// Allow known good bots (Google, Bing, etc.)
    pub allow_good_bots: bool,
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            signature_detection: true,
            timing_detection: true,
            header_anomaly_detection: true,
            min_request_interval_ms: 100,
            allow_good_bots: true,
        }
    }
}

/// Bot classification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotClassification {
    /// Appears to be a human user
    Human,
    /// Known good bot (search engines, etc.)
    GoodBot { name: String },
    /// Suspected bad bot
    BadBot {
        confidence: u8,
        reasons: Vec<String>,
    },
    /// Unable to determine
    Unknown,
}

impl BotClassification {
    /// Check if this is a bad bot
    pub fn is_bad_bot(&self) -> bool {
        matches!(self, BotClassification::BadBot { .. })
    }

    /// Get confidence level for bad bots
    pub fn bad_bot_confidence(&self) -> Option<u8> {
        match self {
            BotClassification::BadBot { confidence, .. } => Some(*confidence),
            _ => None,
        }
    }
}

/// Bot detector
pub struct BotDetector {
    config: BotConfig,
    signatures: BotSignatureDb,
    timing: TimingAnalyzer,
}

impl BotDetector {
    /// Create a new bot detector
    pub fn new(config: BotConfig) -> Self {
        Self {
            timing: TimingAnalyzer::new(TimingConfig {
                min_interval_ms: config.min_request_interval_ms,
                ..Default::default()
            }),
            signatures: BotSignatureDb::new(),
            config,
        }
    }

    /// Analyze a request for bot characteristics
    pub fn analyze(
        &mut self,
        user_agent: Option<&str>,
        headers: &HashMap<String, Vec<String>>,
        source_ip: Option<&str>,
        tls_fingerprint: Option<&str>,
    ) -> (BotClassification, Vec<Detection>) {
        let mut detections = Vec::new();
        let mut reasons = Vec::new();
        let mut confidence = 0u8;

        // Check User-Agent signatures
        if self.config.signature_detection {
            if let Some(ua) = user_agent {
                match self.signatures.classify_user_agent(ua) {
                    BotSignature::GoodBot(name) => {
                        if self.config.allow_good_bots {
                            return (BotClassification::GoodBot { name }, detections);
                        }
                    }
                    BotSignature::BadBot(name, score) => {
                        confidence = confidence.saturating_add(score);
                        reasons.push(format!("Known bad bot: {}", name));
                        detections.push(Detection {
                            rule_id: 97001,
                            rule_name: format!("Bad Bot Signature: {}", name),
                            attack_type: AttackType::ScannerDetection,
                            matched_value: truncate(ua, 100),
                            location: "header:User-Agent".to_string(),
                            base_score: 6,
                            tags: vec!["bot".to_string(), "signature".to_string()],
                        });
                    }
                    BotSignature::SuspiciousBot(name, score) => {
                        confidence = confidence.saturating_add(score);
                        reasons.push(format!("Suspicious UA: {}", name));
                        detections.push(Detection {
                            rule_id: 97002,
                            rule_name: format!("Suspicious Bot: {}", name),
                            attack_type: AttackType::ScannerDetection,
                            matched_value: truncate(ua, 100),
                            location: "header:User-Agent".to_string(),
                            base_score: 4,
                            tags: vec!["bot".to_string(), "suspicious".to_string()],
                        });
                    }
                    BotSignature::Unknown => {}
                }

                // Check for empty or missing UA
                if ua.is_empty() {
                    confidence = confidence.saturating_add(30);
                    reasons.push("Empty User-Agent".to_string());
                    detections.push(Detection {
                        rule_id: 97003,
                        rule_name: "Empty User-Agent".to_string(),
                        attack_type: AttackType::ScannerDetection,
                        matched_value: "".to_string(),
                        location: "header:User-Agent".to_string(),
                        base_score: 5,
                        tags: vec!["bot".to_string(), "empty-ua".to_string()],
                    });
                }
            } else {
                confidence = confidence.saturating_add(40);
                reasons.push("Missing User-Agent".to_string());
                detections.push(Detection {
                    rule_id: 97004,
                    rule_name: "Missing User-Agent".to_string(),
                    attack_type: AttackType::ScannerDetection,
                    matched_value: "".to_string(),
                    location: "header:User-Agent".to_string(),
                    base_score: 6,
                    tags: vec!["bot".to_string(), "missing-ua".to_string()],
                });
            }
        }

        // Check header anomalies
        if self.config.header_anomaly_detection {
            let anomalies = self.check_header_anomalies(headers, user_agent);
            for (anomaly, score) in anomalies {
                confidence = confidence.saturating_add(score);
                reasons.push(anomaly.clone());
                detections.push(Detection {
                    rule_id: 97100,
                    rule_name: format!("Header Anomaly: {}", anomaly),
                    attack_type: AttackType::ScannerDetection,
                    matched_value: anomaly,
                    location: "headers".to_string(),
                    base_score: 4,
                    tags: vec!["bot".to_string(), "header-anomaly".to_string()],
                });
            }
        }

        // Check timing (requires source IP)
        if self.config.timing_detection {
            if let Some(ip) = source_ip {
                if let Some(timing_detection) = self.timing.check_request(ip) {
                    confidence = confidence.saturating_add(timing_detection.score);
                    reasons.push(timing_detection.reason.clone());
                    detections.push(Detection {
                        rule_id: 97101,
                        rule_name: "Request Timing Anomaly".to_string(),
                        attack_type: AttackType::ScannerDetection,
                        matched_value: timing_detection.reason,
                        location: "timing".to_string(),
                        base_score: 5,
                        tags: vec!["bot".to_string(), "timing".to_string()],
                    });
                }
            }
        }

        // Check TLS fingerprint
        if let Some(fp) = tls_fingerprint {
            if let Some((reason, score)) = self.signatures.check_tls_fingerprint(fp) {
                confidence = confidence.saturating_add(score);
                reasons.push(reason.clone());
                detections.push(Detection {
                    rule_id: 97102,
                    rule_name: "TLS Fingerprint Anomaly".to_string(),
                    attack_type: AttackType::ScannerDetection,
                    matched_value: reason,
                    location: "tls".to_string(),
                    base_score: 5,
                    tags: vec!["bot".to_string(), "tls-fingerprint".to_string()],
                });
            }
        }

        // Determine classification
        let classification = if confidence >= 70 {
            BotClassification::BadBot {
                confidence,
                reasons,
            }
        } else if confidence >= 30 {
            BotClassification::Unknown
        } else {
            BotClassification::Human
        };

        (classification, detections)
    }

    /// Check for header anomalies
    fn check_header_anomalies(
        &self,
        headers: &HashMap<String, Vec<String>>,
        user_agent: Option<&str>,
    ) -> Vec<(String, u8)> {
        let mut anomalies = Vec::new();

        // Check for missing Accept header (browsers always send it)
        if !headers.contains_key("Accept") && !headers.contains_key("accept") {
            anomalies.push(("Missing Accept header".to_string(), 15));
        }

        // Check for missing Accept-Language (browsers send it)
        if !headers.contains_key("Accept-Language") && !headers.contains_key("accept-language") {
            anomalies.push(("Missing Accept-Language header".to_string(), 10));
        }

        // Check for browser UA but missing browser-specific headers
        if let Some(ua) = user_agent {
            let ua_lower = ua.to_lowercase();
            let is_browser = ua_lower.contains("mozilla")
                || ua_lower.contains("chrome")
                || ua_lower.contains("safari")
                || ua_lower.contains("firefox")
                || ua_lower.contains("edge");

            if is_browser {
                // Browsers send these headers
                if !headers.contains_key("Accept-Encoding")
                    && !headers.contains_key("accept-encoding")
                {
                    anomalies.push(("Browser UA without Accept-Encoding".to_string(), 20));
                }

                // Check for Connection header
                if !headers.contains_key("Connection") && !headers.contains_key("connection") {
                    anomalies.push(("Browser UA without Connection header".to_string(), 10));
                }
            }
        }

        // Check for weird header combinations
        if headers.contains_key("X-Forwarded-For") || headers.contains_key("x-forwarded-for") {
            // Having X-Forwarded-For without going through a proxy is suspicious
            // (though this depends on architecture)
        }

        anomalies
    }
}

/// Truncate a string for display
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_user_agent() {
        let mut detector = BotDetector::new(BotConfig::default());
        let headers = HashMap::new();

        let (classification, detections) = detector.analyze(None, &headers, None, None);
        assert!(matches!(
            classification,
            BotClassification::BadBot { .. } | BotClassification::Unknown
        ));
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_empty_user_agent() {
        let mut detector = BotDetector::new(BotConfig::default());
        let headers = HashMap::new();

        let (classification, detections) = detector.analyze(Some(""), &headers, None, None);
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_normal_browser() {
        let mut detector = BotDetector::new(BotConfig::default());
        let mut headers = HashMap::new();
        headers.insert("Accept".to_string(), vec!["text/html".to_string()]);
        headers.insert("Accept-Language".to_string(), vec!["en-US".to_string()]);
        headers.insert("Accept-Encoding".to_string(), vec!["gzip".to_string()]);
        headers.insert("Connection".to_string(), vec!["keep-alive".to_string()]);

        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let (classification, _) = detector.analyze(Some(ua), &headers, None, None);

        // Should be human or unknown, not bad bot
        assert!(
            !matches!(classification, BotClassification::BadBot { confidence, .. } if confidence >= 70)
        );
    }

    #[test]
    fn test_good_bot_detection() {
        let mut detector = BotDetector::new(BotConfig::default());
        let headers = HashMap::new();

        let ua = "Googlebot/2.1 (+http://www.google.com/bot.html)";
        let (classification, _) = detector.analyze(Some(ua), &headers, None, None);

        assert!(matches!(classification, BotClassification::GoodBot { .. }));
    }
}
