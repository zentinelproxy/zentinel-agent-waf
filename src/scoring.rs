//! Anomaly Scoring System
//!
//! Calculates cumulative risk scores from WAF detections to reduce false positives.
//! Instead of binary block/allow decisions, scores are accumulated and compared
//! against thresholds.

use crate::config::ScoringConfig;
use crate::detection::{AnomalyScore, Detection, WafDecision};
use crate::rules::Rule;

/// Calculate anomaly score from detections
pub fn calculate(detections: &[Detection], rules: &[Rule], config: &ScoringConfig) -> AnomalyScore {
    let mut score = AnomalyScore::new();

    for detection in detections {
        // Get location weight
        let location_weight = config.location_weights.get(&detection.location);

        // Get severity weight from the rule
        let severity_weight = rules
            .iter()
            .find(|r| r.id == detection.rule_id)
            .map(|r| r.severity.multiplier())
            .unwrap_or(1.0);

        // Get category weight if configured
        let category_weight = config
            .category_weights
            .get(&detection.attack_type.to_string())
            .copied()
            .unwrap_or(1.0);

        let combined_weight = severity_weight * category_weight;
        score.add(detection, location_weight, combined_weight);
    }

    score
}

/// Make a decision based on score and config
pub fn decide(
    detections: &[Detection],
    rules: &[Rule],
    config: &ScoringConfig,
    block_mode: bool,
) -> WafDecision {
    if detections.is_empty() {
        return WafDecision::Allow;
    }

    // If scoring is disabled, fall back to binary mode
    if !config.enabled {
        return if block_mode {
            WafDecision::Block {
                score: AnomalyScore::new(),
            }
        } else {
            WafDecision::AllowWithWarning {
                score: AnomalyScore::new(),
            }
        };
    }

    let score = calculate(detections, rules, config);

    if block_mode && score.should_block(config.block_threshold) {
        WafDecision::Block { score }
    } else if score.should_log(config.log_threshold) {
        WafDecision::AllowWithWarning { score }
    } else {
        WafDecision::Allow
    }
}

/// Score calculation utilities
pub mod utils {
    /// Calculate what score would be needed to trigger blocking
    pub fn score_to_block(current: u32, threshold: u32) -> u32 {
        threshold.saturating_sub(current)
    }

    /// Format score for display
    pub fn format_score(score: u32, threshold: u32) -> String {
        let percentage = (score as f32 / threshold as f32 * 100.0).min(100.0);
        format!("{}/{} ({:.0}%)", score, threshold, percentage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{AttackType, Confidence, RuleBuilder, Severity};

    fn make_test_rules() -> Vec<Rule> {
        vec![
            RuleBuilder::new(942100, "SQLi Union")
                .attack_type(AttackType::SqlInjection)
                .severity(Severity::Critical)
                .confidence(Confidence::High)
                .pattern(r"(?i)UNION\s+SELECT")
                .base_score(9)
                .build()
                .unwrap(),
            RuleBuilder::new(942140, "SQLi Comment")
                .attack_type(AttackType::SqlInjection)
                .severity(Severity::Low)
                .confidence(Confidence::Low)
                .pattern(r"--")
                .base_score(3)
                .build()
                .unwrap(),
        ]
    }

    fn make_detection(rule_id: u32, base_score: u32, location: &str) -> Detection {
        Detection {
            rule_id,
            rule_name: format!("Rule {}", rule_id),
            attack_type: AttackType::SqlInjection,
            matched_value: "test".to_string(),
            location: location.to_string(),
            base_score,
            tags: vec![],
        }
    }

    #[test]
    fn test_calculate_score() {
        let rules = make_test_rules();
        let config = ScoringConfig::default();

        let detections = vec![
            make_detection(942100, 9, "query"), // 9 * 1.5 (query) * 2.0 (critical) = 27
        ];

        let score = calculate(&detections, &rules, &config);
        assert_eq!(score.total, 27);
    }

    #[test]
    fn test_multiple_detections() {
        let rules = make_test_rules();
        let config = ScoringConfig::default();

        let detections = vec![
            make_detection(942100, 9, "query"), // 27
            make_detection(942140, 3, "query"), // 3 * 1.5 * 0.7 = 3.15 -> 3
        ];

        let score = calculate(&detections, &rules, &config);
        assert_eq!(score.total, 30);
    }

    #[test]
    fn test_decide_block() {
        let rules = make_test_rules();
        let config = ScoringConfig {
            enabled: true,
            block_threshold: 25,
            log_threshold: 10,
            ..Default::default()
        };

        let detections = vec![make_detection(942100, 9, "query")]; // 27

        let decision = decide(&detections, &rules, &config, true);
        assert!(decision.is_block());
    }

    #[test]
    fn test_decide_allow_with_warning() {
        let rules = make_test_rules();
        let config = ScoringConfig {
            enabled: true,
            block_threshold: 50,
            log_threshold: 10,
            ..Default::default()
        };

        let detections = vec![make_detection(942140, 3, "header:test")]; // 3 * 1.0 * 0.7 = 2.1 -> 2

        let decision = decide(&detections, &rules, &config, true);
        // Score is 2, below log threshold of 10, so should be Allow
        assert!(!decision.is_block());
    }

    #[test]
    fn test_decide_no_detections() {
        let rules = make_test_rules();
        let config = ScoringConfig::default();

        let decision = decide(&[], &rules, &config, true);
        assert!(!decision.is_block());
    }

    #[test]
    fn test_scoring_disabled() {
        let rules = make_test_rules();
        let config = ScoringConfig {
            enabled: false,
            ..Default::default()
        };

        let detections = vec![make_detection(942140, 1, "header:test")];

        // With scoring disabled, any detection should block in block mode
        let decision = decide(&detections, &rules, &config, true);
        assert!(decision.is_block());
    }
}
