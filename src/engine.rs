//! WAF Engine
//!
//! The core detection engine that evaluates rules against incoming requests.
//! Uses automata-based multi-pattern matching for efficient rule evaluation,
//! with optional ML-based detection for catching attack variations.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, info};

use crate::api::{ApiSecurityInspector, ApiSecurityConfig as ApiConfig, GraphQLConfig, JwtConfig};
use crate::automata::AutomataEngine;
use crate::bot::{BotConfig, BotDetector};
use crate::config::WafConfig;
use crate::credential::{CredentialConfig, CredentialProtection};
use crate::detection::Detection;
use crate::ml::{AttackClassifier, FingerprintBaseline, PayloadSimilarity, RequestFingerprint};
use crate::rules::{self, AttackType, Rule};
use crate::sensitive::{SensitiveDataConfig, SensitiveDataDetector};

/// WAF engine - the core detection component
pub struct WafEngine {
    /// Active rules (filtered by config)
    rules: Vec<Rule>,
    /// Automata engine for efficient multi-pattern matching
    automata: AutomataEngine,
    /// Current configuration
    pub config: WafConfig,
    /// ML attack classifier (optional)
    classifier: Option<AttackClassifier>,
    /// Payload similarity detector (optional)
    similarity: Option<PayloadSimilarity>,
    /// Request fingerprint baseline (for learning)
    fingerprint_baseline: RwLock<FingerprintBaseline>,
    /// API security inspector (GraphQL, JSON, JWT)
    api_inspector: ApiSecurityInspector,
    /// Bot detector
    bot_detector: RwLock<BotDetector>,
    /// Credential stuffing protection
    credential_protection: RwLock<CredentialProtection>,
    /// Sensitive data detector
    sensitive_detector: SensitiveDataDetector,
}

impl WafEngine {
    /// Create a new WAF engine with the given configuration
    pub fn new(config: WafConfig) -> Result<Self> {
        // Load all rules based on category settings and paranoia level
        let all_rules = rules::load_rules(&config)?;

        // Apply rule management filters
        let rules = rules::filter_rules(
            &all_rules,
            config.rules.enabled.as_deref(),
            &config.rules.disabled,
        );

        // Compile automata engine for efficient multi-pattern matching
        let automata = AutomataEngine::compile(&rules, config.paranoia_level)?;

        // Initialize ML components if enabled
        let classifier = if config.ml.classifier_enabled {
            info!("ML attack classifier enabled");
            Some(AttackClassifier::new())
        } else {
            None
        };

        let similarity = if config.ml.similarity_enabled {
            info!("Payload similarity detection enabled");
            Some(PayloadSimilarity::new())
        } else {
            None
        };

        // Initialize API security inspector
        let api_inspector = ApiSecurityInspector::new(ApiConfig {
            graphql_enabled: config.api_security.graphql_enabled,
            json_enabled: config.api_security.json_enabled,
            jwt_enabled: config.api_security.jwt_enabled,
            graphql: GraphQLConfig {
                block_introspection: config.api_security.block_introspection,
                max_depth: config.api_security.graphql_max_depth,
                ..Default::default()
            },
            jwt: JwtConfig {
                block_none_algorithm: config.api_security.jwt_block_none,
                ..Default::default()
            },
        });

        // Initialize bot detector
        let bot_detector = BotDetector::new(BotConfig {
            signature_detection: config.bot_detection.enabled,
            timing_detection: config.bot_detection.timing_detection,
            header_anomaly_detection: config.bot_detection.header_anomaly_detection,
            allow_good_bots: config.bot_detection.allow_good_bots,
            min_request_interval_ms: config.bot_detection.min_request_interval_ms,
        });

        // Initialize credential protection
        let credential_protection = CredentialProtection::new(CredentialConfig {
            velocity_detection: config.credential_protection.enabled,
            max_failures_per_ip: config.credential_protection.max_failures_per_ip,
            max_failures_per_user: config.credential_protection.max_failures_per_user,
            window_secs: config.credential_protection.window_secs,
            login_paths: config.credential_protection.login_paths.clone(),
            ..Default::default()
        });

        // Initialize sensitive data detector
        let sensitive_detector = SensitiveDataDetector::new(SensitiveDataConfig {
            credit_card_detection: config.sensitive_data.credit_card_detection,
            ssn_detection: config.sensitive_data.ssn_detection,
            api_key_detection: config.sensitive_data.api_key_detection,
            private_key_detection: config.sensitive_data.private_key_detection,
            ..Default::default()
        });

        info!(
            rules_count = rules.len(),
            paranoia_level = config.paranoia_level,
            automata_groups = automata.group_count(),
            automata_enabled = automata.is_enabled(),
            ml_classifier = config.ml.classifier_enabled,
            ml_fingerprinting = config.ml.fingerprinting_enabled,
            ml_similarity = config.ml.similarity_enabled,
            api_security_graphql = config.api_security.graphql_enabled,
            api_security_jwt = config.api_security.jwt_enabled,
            bot_detection = config.bot_detection.enabled,
            credential_protection = config.credential_protection.enabled,
            sensitive_data = config.sensitive_data.enabled,
            "WAF engine initialized"
        );

        Ok(Self {
            rules,
            automata,
            config,
            classifier,
            similarity,
            fingerprint_baseline: RwLock::new(FingerprintBaseline::new()),
            api_inspector,
            bot_detector: RwLock::new(bot_detector),
            credential_protection: RwLock::new(credential_protection),
            sensitive_detector,
        })
    }

    /// Get all active rules
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Check a value against all applicable rules for a location
    ///
    /// Uses automata-based multi-pattern matching when available for O(n) input
    /// scanning instead of O(n*m) sequential rule iteration. Also runs ML-based
    /// detection if enabled.
    pub fn check(&self, value: &str, location: &str) -> Vec<Detection> {
        let mut detections = if self.automata.is_enabled() {
            self.check_with_automata(value, location)
        } else {
            self.check_sequential(value, location)
        };

        // Add ML-based detections if enabled
        detections.extend(self.check_ml(value, location));

        detections
    }

    /// Run ML-based detection on a value
    fn check_ml(&self, value: &str, location: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // ML classifier detection
        if let Some(ref classifier) = self.classifier {
            let prediction = classifier.classify(value);

            if prediction.is_attack(self.config.ml.min_confidence) {
                if let Some(attack_type) = prediction.predicted_type {
                    let base_score = (prediction.confidence * 10.0 * self.config.ml.score_weight) as u32;

                    debug!(
                        confidence = prediction.confidence,
                        attack_type = %attack_type,
                        location = location,
                        "ML classifier detection"
                    );

                    detections.push(Detection {
                        rule_id: 99000 + ml_attack_type_id(attack_type),
                        rule_name: format!("ML-{}", attack_type),
                        attack_type,
                        matched_value: truncate_value(value, 100),
                        location: location.to_string(),
                        base_score,
                        tags: vec!["ml-classifier".to_string()],
                    });
                }
            }
        }

        // Payload similarity detection
        if let Some(ref similarity) = self.similarity {
            let result = similarity.analyze(value);

            if result.is_suspicious {
                let attack_type = match result.category {
                    Some(crate::ml::similarity::PayloadCategory::SqlInjection) => AttackType::SqlInjection,
                    Some(crate::ml::similarity::PayloadCategory::Xss) => AttackType::Xss,
                    Some(crate::ml::similarity::PayloadCategory::CommandInjection) => AttackType::CommandInjection,
                    Some(crate::ml::similarity::PayloadCategory::PathTraversal) => AttackType::PathTraversal,
                    _ => AttackType::ProtocolAttack, // Use ProtocolAttack as catch-all
                };

                let base_score = (result.max_similarity * 8.0 * self.config.ml.score_weight) as u32;

                debug!(
                    similarity = result.max_similarity,
                    attack_type = %attack_type,
                    location = location,
                    "Payload similarity detection"
                );

                detections.push(Detection {
                    rule_id: 99100 + ml_attack_type_id(attack_type),
                    rule_name: format!("ML-Similarity-{}", attack_type),
                    attack_type,
                    matched_value: truncate_value(value, 100),
                    location: location.to_string(),
                    base_score,
                    tags: vec!["ml-similarity".to_string()],
                });
            }
        }

        detections
    }

    /// Check using automata-based multi-pattern matching (optimized path)
    fn check_with_automata(&self, value: &str, location: &str) -> Vec<Detection> {
        let matches = self.automata.find_all(value, location, self.config.paranoia_level);

        matches
            .into_iter()
            .filter_map(|m| {
                // Get rule metadata from automata engine
                let metadata = self.automata.get_rule_metadata(m.rule_id)?;

                // Extract matched text from input
                let matched_value = value
                    .get(m.start..m.end)
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                Some(Detection {
                    rule_id: m.rule_id,
                    rule_name: metadata.name.clone(),
                    attack_type: metadata.attack_type,
                    matched_value,
                    location: location.to_string(),
                    base_score: metadata.base_score,
                    tags: metadata.tags.clone(),
                })
            })
            .collect()
    }

    /// Check using sequential rule iteration (fallback path)
    fn check_sequential(&self, value: &str, location: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for rule in &self.rules {
            // Check if rule applies to this location
            if !rule.applies_to(location) {
                continue;
            }

            if rule.pattern.is_match(value) {
                let matched = rule
                    .pattern
                    .find(value)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                detections.push(Detection {
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    attack_type: rule.attack_type,
                    matched_value: matched,
                    location: location.to_string(),
                    base_score: rule.base_score,
                    tags: rule.tags.clone(),
                });
            }
        }

        detections
    }

    /// Check entire request (path, query, headers)
    pub fn check_request(
        &self,
        path: &str,
        query: Option<&str>,
        headers: &HashMap<String, Vec<String>>,
    ) -> Vec<Detection> {
        let mut all_detections = Vec::new();

        // Check path
        all_detections.extend(self.check(path, "path"));

        // Check query string
        if let Some(q) = query {
            all_detections.extend(self.check(q, "query"));
        }

        // Check headers
        for (name, values) in headers {
            let location = format!("header:{}", name);
            for value in values {
                all_detections.extend(self.check(value, &location));
            }
        }

        all_detections
    }

    /// Check if path should be excluded from inspection
    pub fn is_excluded(&self, path: &str) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|p| path.starts_with(p))
    }

    /// Get rule by ID
    pub fn get_rule(&self, id: u32) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Check if an exclusion applies to the current request context
    pub fn check_exclusion(
        &self,
        rule_id: u32,
        path: &str,
        _source_ip: Option<&str>,
        _method: Option<&str>,
        _headers: Option<&HashMap<String, Vec<String>>>,
    ) -> bool {
        let rule = match self.get_rule(rule_id) {
            Some(r) => r,
            None => return false,
        };

        for exclusion in &self.config.rules.exclusions {
            // Check if exclusion applies to this rule
            let rule_matches = exclusion
                .rules
                .iter()
                .any(|s| s.matches(rule_id, &rule.tags));

            if !rule_matches {
                continue;
            }

            // Check path condition
            if let Some(paths) = &exclusion.conditions.paths {
                if paths.iter().any(|p| path.starts_with(p)) {
                    debug!(rule_id = rule_id, path = path, "Rule excluded by path");
                    return true;
                }
            }

            // Additional conditions (IP, method, headers) can be added here
        }

        false
    }

    /// Analyze request fingerprint for anomalies
    ///
    /// Returns anomaly detections if fingerprinting is enabled and the request
    /// deviates significantly from learned baselines.
    pub fn check_fingerprint(
        &self,
        path: &str,
        query: Option<&str>,
        headers: &HashMap<String, Vec<String>>,
        body_size: Option<usize>,
        method: &str,
    ) -> Vec<Detection> {
        if !self.config.ml.fingerprinting_enabled {
            return Vec::new();
        }

        let fingerprint = RequestFingerprint::from_request(
            method,
            path,
            query,
            headers,
            body_size,
        );

        // Get anomaly score from baseline
        let result = self.fingerprint_baseline
            .read()
            .map(|baseline| baseline.anomaly_score(path, &fingerprint))
            .ok();

        let mut detections = Vec::new();

        if let Some(result) = result {
            if result.is_anomalous(self.config.ml.anomaly_threshold) {
                let base_score = (result.score * 5.0 * self.config.ml.score_weight) as u32;

                debug!(
                    anomaly_score = result.score,
                    factors = ?result.factors,
                    path = path,
                    "Request fingerprint anomaly detected"
                );

                detections.push(Detection {
                    rule_id: 99200,
                    rule_name: "ML-Fingerprint-Anomaly".to_string(),
                    attack_type: AttackType::ProtocolAttack, // Use ProtocolAttack for anomalies
                    matched_value: format!("anomaly_score={:.2}", result.score),
                    location: "request".to_string(),
                    base_score,
                    tags: vec!["ml-fingerprint".to_string()],
                });
            }
        }

        // Learn from this request (update baseline)
        if let Ok(mut baseline) = self.fingerprint_baseline.write() {
            baseline.learn(path, &fingerprint);
        }

        detections
    }

    /// Check request for API security issues (GraphQL, JSON, JWT)
    pub fn check_api(
        &self,
        path: &str,
        content_type: Option<&str>,
        body: Option<&str>,
        auth_header: Option<&str>,
    ) -> Vec<Detection> {
        self.api_inspector.inspect(path, content_type, body, auth_header)
    }

    /// Check request for bot characteristics
    ///
    /// Returns detections if bot-like behavior is detected.
    pub fn check_bot(
        &self,
        user_agent: Option<&str>,
        headers: &HashMap<String, Vec<String>>,
        source_ip: Option<&str>,
        tls_fingerprint: Option<&str>,
    ) -> Vec<Detection> {
        if !self.config.bot_detection.enabled {
            return Vec::new();
        }

        let mut bot_detector = match self.bot_detector.write() {
            Ok(detector) => detector,
            Err(_) => return Vec::new(),
        };

        let (classification, detections) = bot_detector.analyze(
            user_agent,
            headers,
            source_ip,
            tls_fingerprint,
        );

        if classification.is_bad_bot() {
            debug!(
                confidence = classification.bad_bot_confidence(),
                user_agent = user_agent,
                source_ip = source_ip,
                "Bad bot detected"
            );
        }

        detections
    }

    /// Check for credential stuffing attacks on login endpoints
    ///
    /// Call this method when a login attempt is made.
    /// Returns true if the request should be blocked.
    pub fn check_credential_attempt(
        &self,
        path: &str,
        ip: &str,
        username: &str,
        success: bool,
    ) -> (bool, Vec<Detection>) {
        if !self.config.credential_protection.enabled {
            return (false, Vec::new());
        }

        let mut protection = match self.credential_protection.write() {
            Ok(p) => p,
            Err(_) => return (false, Vec::new()),
        };

        // Check if this is a login path
        if !protection.is_login_path(path) {
            return (false, Vec::new());
        }

        let (decision, detections) = protection.check_attempt(ip, username, success);

        if decision.is_blocked() {
            debug!(
                ip = ip,
                username_masked = &username[..username.len().min(2)],
                decision = ?decision,
                "Credential protection triggered"
            );
        }

        (decision.is_blocked(), detections)
    }

    /// Check response body for sensitive data leakage
    pub fn check_sensitive_data(&self, response_body: &str) -> Vec<Detection> {
        if !self.config.sensitive_data.enabled {
            return Vec::new();
        }

        let detections = self.sensitive_detector.scan(response_body);

        if !detections.is_empty() {
            debug!(
                detection_count = detections.len(),
                "Sensitive data detected in response"
            );
        }

        detections
    }
}

/// Map attack type to numeric ID for ML rule IDs
fn ml_attack_type_id(attack_type: AttackType) -> u32 {
    match attack_type {
        AttackType::SqlInjection => 1,
        AttackType::Xss => 2,
        AttackType::CommandInjection => 3,
        AttackType::PathTraversal => 4,
        AttackType::Ssrf => 5,
        AttackType::Ssti => 6,
        AttackType::LdapInjection => 7,
        AttackType::XpathInjection => 8,
        AttackType::ProtocolAttack => 9,
        AttackType::ScannerDetection => 10,
        AttackType::RequestSmuggling => 11,
        AttackType::Deserialization => 12,
        AttackType::DataLeakage => 13,
        AttackType::Reconnaissance => 14,
        AttackType::RemoteCodeExecution => 15,
        AttackType::SupplyChain => 16,
    }
}

/// Truncate a value for storage in detection
fn truncate_value(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        format!("{}...", &value[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> WafEngine {
        let config = WafConfig {
            paranoia_level: 2,
            ..Default::default()
        };
        WafEngine::new(config).unwrap()
    }

    #[test]
    fn test_engine_creation() {
        let engine = test_engine();
        assert!(!engine.rules().is_empty());
    }

    #[test]
    fn test_sqli_detection() {
        let engine = test_engine();
        let detections = engine.check("' OR '1'='1", "query");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_xss_detection() {
        let engine = test_engine();
        let detections = engine.check("<script>alert('xss')</script>", "body");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_path_exclusion() {
        let config = WafConfig {
            exclude_paths: vec!["/health".to_string(), "/metrics".to_string()],
            ..Default::default()
        };
        let engine = WafEngine::new(config).unwrap();

        assert!(engine.is_excluded("/health"));
        assert!(engine.is_excluded("/health/ready"));
        assert!(!engine.is_excluded("/api/users"));
    }

    #[test]
    fn test_check_request() {
        let engine = test_engine();
        let mut headers = HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            vec!["Mozilla/5.0".to_string()],
        );

        let detections = engine.check_request("/api/search", Some("q=UNION SELECT"), &headers);
        assert!(!detections.is_empty());
    }
}
