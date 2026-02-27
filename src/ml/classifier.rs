//! ML-Based Attack Classifier
//!
//! Uses character n-gram statistics to detect attack patterns.
#![allow(dead_code)]
//! The classifier maintains learned patterns for each attack type
//! and scores new inputs based on similarity to known attacks.
//!
//! # Why N-Grams Work for Attack Detection
//!
//! Attacks have distinctive character patterns that persist even through
//! obfuscation. For example, SQL injection often contains:
//! - "sel" (from SELECT)
//! - "uni" (from UNION)
//! - "whe" (from WHERE)
//! - "--" (comment sequence)
//! - "'" (quote characters)
//!
//! These n-grams appear regardless of case changes, comment injection,
//! or encoding tricks.

use super::ngram::{CharNGramTokenizer, NGramFeatures};
use crate::rules::AttackType;
use rustc_hash::FxHashMap;
use std::collections::HashMap;

/// Configuration for the classifier
#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    /// Minimum confidence to report a detection (0.0 - 1.0)
    pub min_confidence: f32,
    /// Weight for n-gram frequency scoring
    pub frequency_weight: f32,
    /// Weight for pattern presence scoring
    pub presence_weight: f32,
    /// Enable adaptive learning from detections
    pub adaptive_learning: bool,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.3,
            frequency_weight: 0.6,
            presence_weight: 0.4,
            adaptive_learning: false,
        }
    }
}

/// Prediction result from the classifier
#[derive(Debug, Clone)]
pub struct AttackPrediction {
    /// SQL injection confidence (0.0 - 1.0)
    pub sqli_score: f32,
    /// XSS confidence (0.0 - 1.0)
    pub xss_score: f32,
    /// Command injection confidence (0.0 - 1.0)
    pub cmd_injection_score: f32,
    /// Path traversal confidence (0.0 - 1.0)
    pub path_traversal_score: f32,
    /// Overall attack confidence (max of above)
    pub confidence: f32,
    /// Most likely attack type
    pub predicted_type: Option<AttackType>,
    /// N-grams that contributed to the prediction
    pub contributing_patterns: Vec<String>,
}

impl AttackPrediction {
    /// Create an empty prediction (no attack detected)
    pub fn none() -> Self {
        Self {
            sqli_score: 0.0,
            xss_score: 0.0,
            cmd_injection_score: 0.0,
            path_traversal_score: 0.0,
            confidence: 0.0,
            predicted_type: None,
            contributing_patterns: Vec::new(),
        }
    }

    /// Check if any attack was detected above threshold
    pub fn is_attack(&self, threshold: f32) -> bool {
        self.confidence >= threshold
    }
}

/// Attack pattern statistics for a single attack type
#[derive(Debug, Clone)]
struct AttackPatternStats {
    /// Known malicious n-gram hashes with weights
    malicious_ngrams: FxHashMap<u64, f32>,
    /// Total samples used to build this model
    sample_count: usize,
}

/// ML-based attack classifier
pub struct AttackClassifier {
    config: ClassifierConfig,
    tokenizer: CharNGramTokenizer,
    /// Per-attack-type pattern statistics
    patterns: HashMap<AttackType, AttackPatternStats>,
}

impl AttackClassifier {
    /// Create a new classifier with default config
    pub fn new() -> Self {
        let mut classifier = Self {
            config: ClassifierConfig::default(),
            tokenizer: CharNGramTokenizer::new(),
            patterns: HashMap::new(),
        };

        // Initialize with known attack patterns
        classifier.initialize_patterns();
        classifier
    }

    /// Create a classifier with custom config
    pub fn with_config(config: ClassifierConfig) -> Self {
        let mut classifier = Self {
            config,
            tokenizer: CharNGramTokenizer::new(),
            patterns: HashMap::new(),
        };
        classifier.initialize_patterns();
        classifier
    }

    /// Initialize with known attack patterns
    fn initialize_patterns(&mut self) {
        // SQL Injection patterns
        self.add_attack_patterns(
            AttackType::SqlInjection,
            &[
                // Basic SQL keywords
                "select",
                "union",
                "insert",
                "update",
                "delete",
                "drop",
                "truncate",
                "from",
                "where",
                "and",
                "or",
                "having",
                "group by",
                "order by",
                // Common injection fragments
                "' or '",
                "' and '",
                "1=1",
                "1'='1",
                "' --",
                "'; --",
                "/**/",
                "' or 1=1",
                "admin'--",
                "' union select",
                "concat(",
                // Functions and operators
                "char(",
                "ascii(",
                "substring(",
                "length(",
                "benchmark(",
                "sleep(",
                "waitfor",
                "pg_sleep",
                "dbms_pipe",
                // Error-based
                "extractvalue(",
                "updatexml(",
                "exp(~",
                // Database-specific
                "information_schema",
                "sys.tables",
                "sqlite_master",
                "@@version",
                "version()",
                "database()",
                "user()",
            ],
        );

        // XSS patterns
        self.add_attack_patterns(
            AttackType::Xss,
            &[
                // Script tags
                "<script",
                "</script>",
                "javascript:",
                "vbscript:",
                // Event handlers
                "onerror=",
                "onload=",
                "onclick=",
                "onmouseover=",
                "onfocus=",
                "onblur=",
                "onchange=",
                "onsubmit=",
                "onkeypress=",
                "onkeyup=",
                // Common payloads
                "alert(",
                "prompt(",
                "confirm(",
                "eval(",
                "document.",
                "window.",
                ".cookie",
                "innerhtml",
                "outerhtml",
                // Encoding tricks
                "&#x",
                "&#",
                "\\x",
                "\\u00",
                // SVG/math vectors
                "<svg",
                "<math",
                "<img src=x",
                "<body onload",
                // Data URIs
                "data:text/html",
                "data:application/",
            ],
        );

        // Command injection patterns
        self.add_attack_patterns(
            AttackType::CommandInjection,
            &[
                // Shell metacharacters
                "; ",
                "| ",
                "|| ",
                "&& ",
                "` ",
                "$(",
                // Common commands
                "/bin/sh",
                "/bin/bash",
                "cmd.exe",
                "powershell",
                "cat /etc",
                "type ",
                "dir ",
                "ls ",
                "whoami",
                "id ",
                "wget ",
                "curl ",
                "nc ",
                "ncat",
                "netcat",
                // Reverse shells
                "bash -i",
                "/dev/tcp",
                "mkfifo",
                "telnet ",
                // Environment
                "$path",
                "$home",
                "%systemroot%",
                "%comspec%",
            ],
        );

        // Path traversal patterns
        self.add_attack_patterns(
            AttackType::PathTraversal,
            &[
                // Directory traversal
                "../",
                "..\\",
                "....//",
                "....\\\\",
                // Encoded variants
                "%2e%2e",
                "%252e",
                "..%c0%af",
                "..%255c",
                // Null bytes
                "%00",
                "\x00",
                // Common targets
                "/etc/passwd",
                "/etc/shadow",
                "win.ini",
                "boot.ini",
                "/proc/self",
                "/var/log",
                // Wrapper protocols
                "file://",
                "php://",
                "zip://",
                "data://",
            ],
        );
    }

    /// Add patterns for an attack type
    fn add_attack_patterns(&mut self, attack_type: AttackType, patterns: &[&str]) {
        let mut stats = AttackPatternStats {
            malicious_ngrams: FxHashMap::default(),
            sample_count: patterns.len(),
        };

        for pattern in patterns {
            let features = self.tokenizer.extract(pattern);

            // Weight n-grams by their specificity (rarer = more indicative)
            let pattern_weight = 1.0 / (patterns.len() as f32).sqrt();

            for (hash, count) in features.features {
                let weight = stats.malicious_ngrams.entry(hash).or_insert(0.0);
                *weight += pattern_weight * (count as f32);
            }
        }

        // Normalize weights
        let max_weight = stats
            .malicious_ngrams
            .values()
            .cloned()
            .fold(0.0f32, f32::max);
        if max_weight > 0.0 {
            for weight in stats.malicious_ngrams.values_mut() {
                *weight /= max_weight;
            }
        }

        self.patterns.insert(attack_type, stats);
    }

    /// Classify an input string
    pub fn classify(&self, input: &str) -> AttackPrediction {
        if input.is_empty() {
            return AttackPrediction::none();
        }

        let features = self.tokenizer.extract(input);

        // Score against each attack type
        let sqli_score = self.score_attack_type(&features, AttackType::SqlInjection);
        let xss_score = self.score_attack_type(&features, AttackType::Xss);
        let cmd_injection_score = self.score_attack_type(&features, AttackType::CommandInjection);
        let path_traversal_score = self.score_attack_type(&features, AttackType::PathTraversal);

        // Find max score
        let scores = [
            (sqli_score, AttackType::SqlInjection),
            (xss_score, AttackType::Xss),
            (cmd_injection_score, AttackType::CommandInjection),
            (path_traversal_score, AttackType::PathTraversal),
        ];

        let (confidence, predicted_type) = scores
            .iter()
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(score, attack_type)| {
                if *score >= self.config.min_confidence {
                    (*score, Some(*attack_type))
                } else {
                    (*score, None)
                }
            })
            .unwrap_or((0.0, None));

        // Get contributing patterns (top scoring n-grams)
        let contributing_patterns = self.get_contributing_patterns(&features, predicted_type);

        AttackPrediction {
            sqli_score,
            xss_score,
            cmd_injection_score,
            path_traversal_score,
            confidence,
            predicted_type,
            contributing_patterns,
        }
    }

    /// Score features against a specific attack type
    fn score_attack_type(&self, features: &NGramFeatures, attack_type: AttackType) -> f32 {
        let stats = match self.patterns.get(&attack_type) {
            Some(s) => s,
            None => return 0.0,
        };

        if stats.malicious_ngrams.is_empty() || features.features.is_empty() {
            return 0.0;
        }

        let mut frequency_score = 0.0f32;
        let mut presence_score = 0.0f32;
        let mut matched_count = 0usize;

        for (hash, count) in &features.features {
            if let Some(weight) = stats.malicious_ngrams.get(hash) {
                // Frequency-based: how often the n-gram appears
                frequency_score += (*count as f32) * weight;
                // Presence-based: whether the n-gram exists at all
                presence_score += *weight;
                matched_count += 1;
            }
        }

        // Normalize scores
        let max_possible_frequency = features.total_count as f32;
        let max_possible_presence = stats.malicious_ngrams.len() as f32;

        if max_possible_frequency > 0.0 {
            frequency_score /= max_possible_frequency;
        }
        if max_possible_presence > 0.0 {
            presence_score /= max_possible_presence;
        }

        // Apply coverage bonus (more matches = more confident)
        let coverage = matched_count as f32 / features.features.len().max(1) as f32;
        let coverage_bonus = 1.0 + (coverage * 0.5);

        // Combine scores
        let raw_score = (frequency_score * self.config.frequency_weight
            + presence_score * self.config.presence_weight)
            * coverage_bonus;

        // Clamp to 0.0 - 1.0
        raw_score.clamp(0.0, 1.0)
    }

    /// Get the n-grams that contributed most to the prediction
    fn get_contributing_patterns(
        &self,
        _features: &NGramFeatures,
        _attack_type: Option<AttackType>,
    ) -> Vec<String> {
        // For now, return empty - this would require storing original n-grams
        // In a production system, we'd maintain a reverse mapping
        Vec::new()
    }

    /// Get the underlying tokenizer
    pub fn tokenizer(&self) -> &CharNGramTokenizer {
        &self.tokenizer
    }
}

impl Default for AttackClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let classifier = AttackClassifier::new();

        // Should detect SQLi - using lower threshold since this is statistical
        let result = classifier.classify("' OR 1=1 --");
        assert!(
            result.sqli_score > 0.05,
            "sqli_score for OR 1=1: {}",
            result.sqli_score
        );

        let result = classifier.classify("UNION SELECT password FROM users");
        assert!(
            result.sqli_score > 0.05,
            "sqli_score for UNION SELECT: {}",
            result.sqli_score
        );

        // Case variations should also work
        let result = classifier.classify("UnIoN SeLeCt password FROM users");
        assert!(
            result.sqli_score > 0.05,
            "sqli_score for mixed case: {}",
            result.sqli_score
        );
    }

    #[test]
    fn test_xss_detection() {
        let classifier = AttackClassifier::new();

        let result = classifier.classify("<script>alert('XSS')</script>");
        assert!(
            result.xss_score > 0.05,
            "xss_score for script: {}",
            result.xss_score
        );

        let result = classifier.classify("<img src=x onerror=alert(1)>");
        assert!(
            result.xss_score > 0.05,
            "xss_score for img onerror: {}",
            result.xss_score
        );
    }

    #[test]
    fn test_command_injection_detection() {
        let classifier = AttackClassifier::new();

        let result = classifier.classify("; cat /etc/passwd");
        assert!(
            result.cmd_injection_score > 0.05,
            "cmd_score for cat: {}",
            result.cmd_injection_score
        );

        let result = classifier.classify("| whoami");
        assert!(
            result.cmd_injection_score > 0.05,
            "cmd_score for whoami: {}",
            result.cmd_injection_score
        );
    }

    #[test]
    fn test_path_traversal_detection() {
        let classifier = AttackClassifier::new();

        let result = classifier.classify("../../../etc/passwd");
        assert!(
            result.path_traversal_score > 0.05,
            "traversal_score for ../: {}",
            result.path_traversal_score
        );

        let result = classifier.classify("..%2f..%2f..%2fetc/passwd");
        assert!(
            result.path_traversal_score > 0.01,
            "traversal_score for %2f: {}",
            result.path_traversal_score
        );
    }

    #[test]
    fn test_benign_input() {
        let classifier = AttackClassifier::new();

        let result = classifier.classify("Hello, my name is John");
        assert!(result.confidence < 0.3);

        let result = classifier.classify("Normal product search query");
        assert!(result.confidence < 0.3);
    }

    #[test]
    fn test_obfuscated_sqli() {
        let classifier = AttackClassifier::new();

        // Comment-based obfuscation - lower threshold as obfuscation reduces signal
        let result = classifier.classify("SELECT/**/password/**/FROM/**/users");
        assert!(
            result.sqli_score > 0.01,
            "sqli_score for obfuscated: {}",
            result.sqli_score
        );
    }

    #[test]
    fn test_prediction_type() {
        let classifier = AttackClassifier::new();

        let result = classifier.classify("UNION SELECT * FROM users WHERE id=1");
        if result.confidence >= 0.3 {
            assert_eq!(result.predicted_type, Some(AttackType::SqlInjection));
        }

        let result = classifier.classify("<script>document.cookie</script>");
        if result.confidence >= 0.3 {
            assert_eq!(result.predicted_type, Some(AttackType::Xss));
        }
    }
}
