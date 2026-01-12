//! WAF Configuration Types
//!
//! Configuration for the WAF engine including scoring thresholds,
//! rule management, and exclusions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;


/// WAF configuration
#[derive(Debug, Clone)]
pub struct WafConfig {
    /// Paranoia level (1-4)
    pub paranoia_level: u8,
    /// Enable SQL injection detection
    pub sqli_enabled: bool,
    /// Enable XSS detection
    pub xss_enabled: bool,
    /// Enable path traversal detection
    pub path_traversal_enabled: bool,
    /// Enable command injection detection
    pub command_injection_enabled: bool,
    /// Enable protocol attack detection
    pub protocol_enabled: bool,
    /// Block mode (true) or detect-only (false)
    pub block_mode: bool,
    /// Paths to exclude from inspection
    pub exclude_paths: Vec<String>,
    /// Enable request body inspection
    pub body_inspection_enabled: bool,
    /// Maximum body size to inspect
    pub max_body_size: usize,
    /// Enable response body inspection
    pub response_inspection_enabled: bool,
    /// Scoring configuration
    pub scoring: ScoringConfig,
    /// Rule management configuration
    pub rules: RuleManagement,
    /// Streaming body inspection configuration
    pub streaming: StreamingConfig,
    /// ML-based detection configuration
    pub ml: MlConfig,
    /// API security configuration (GraphQL, JSON, JWT)
    pub api_security: ApiSecurityConfig,
    /// Bot detection configuration
    pub bot_detection: BotDetectionConfig,
    /// Credential stuffing protection configuration
    pub credential_protection: CredentialProtectionConfig,
    /// Sensitive data detection configuration
    pub sensitive_data: SensitiveDataDetectionConfig,
    // Phase 4: Enterprise features
    /// Threat intelligence configuration
    pub threat_intel: ThreatIntelConfig,
    /// Virtual patching configuration
    pub virtual_patching: VirtualPatchingConfig,
    /// Supply chain protection configuration
    pub supply_chain: SupplyChainConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
    /// Federated learning configuration
    pub federated: FederatedConfig,
}

/// Configuration for API security inspection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ApiSecurityConfig {
    /// Enable GraphQL inspection
    #[serde(default)]
    pub graphql_enabled: bool,
    /// Enable JSON inspection
    #[serde(default = "default_true")]
    pub json_enabled: bool,
    /// Enable JWT inspection
    #[serde(default = "default_true")]
    pub jwt_enabled: bool,
    /// Block GraphQL introspection queries
    #[serde(default = "default_true")]
    pub block_introspection: bool,
    /// Maximum GraphQL query depth
    #[serde(default = "default_graphql_depth")]
    pub graphql_max_depth: usize,
    /// Block JWT "none" algorithm
    #[serde(default = "default_true")]
    pub jwt_block_none: bool,
}

impl Default for ApiSecurityConfig {
    fn default() -> Self {
        Self {
            graphql_enabled: false,
            json_enabled: true,
            jwt_enabled: true,
            block_introspection: true,
            graphql_max_depth: 10,
            jwt_block_none: true,
        }
    }
}

fn default_graphql_depth() -> usize {
    10
}

/// Configuration for bot detection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BotDetectionConfig {
    /// Enable bot detection
    #[serde(default)]
    pub enabled: bool,
    /// Enable timing-based detection
    #[serde(default = "default_true")]
    pub timing_detection: bool,
    /// Enable header anomaly detection
    #[serde(default = "default_true")]
    pub header_anomaly_detection: bool,
    /// Allow known good bots (Google, Bing, etc.)
    #[serde(default = "default_true")]
    pub allow_good_bots: bool,
    /// Minimum request interval (ms) before flagging
    #[serde(default = "default_min_interval")]
    pub min_request_interval_ms: u64,
}

impl Default for BotDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timing_detection: true,
            header_anomaly_detection: true,
            allow_good_bots: true,
            min_request_interval_ms: 100,
        }
    }
}

fn default_min_interval() -> u64 {
    100
}

/// Configuration for credential stuffing protection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialProtectionConfig {
    /// Enable credential protection
    #[serde(default)]
    pub enabled: bool,
    /// Maximum failed logins per IP per window
    #[serde(default = "default_max_failures_per_ip")]
    pub max_failures_per_ip: usize,
    /// Maximum failed logins per username per window
    #[serde(default = "default_max_failures_per_user")]
    pub max_failures_per_user: usize,
    /// Time window in seconds
    #[serde(default = "default_credential_window")]
    pub window_secs: u64,
    /// Login endpoint paths
    #[serde(default = "default_login_paths")]
    pub login_paths: Vec<String>,
}

impl Default for CredentialProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_failures_per_ip: 10,
            max_failures_per_user: 5,
            window_secs: 300,
            login_paths: default_login_paths(),
        }
    }
}

fn default_max_failures_per_ip() -> usize {
    10
}

fn default_max_failures_per_user() -> usize {
    5
}

fn default_credential_window() -> u64 {
    300
}

fn default_login_paths() -> Vec<String> {
    vec![
        "/login".to_string(),
        "/signin".to_string(),
        "/auth".to_string(),
        "/api/login".to_string(),
        "/api/auth".to_string(),
    ]
}

/// Configuration for sensitive data detection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SensitiveDataDetectionConfig {
    /// Enable sensitive data detection in responses
    #[serde(default)]
    pub enabled: bool,
    /// Detect credit card numbers
    #[serde(default = "default_true")]
    pub credit_card_detection: bool,
    /// Detect Social Security Numbers
    #[serde(default = "default_true")]
    pub ssn_detection: bool,
    /// Detect API keys and tokens
    #[serde(default = "default_true")]
    pub api_key_detection: bool,
    /// Detect private keys
    #[serde(default = "default_true")]
    pub private_key_detection: bool,
}

impl Default for SensitiveDataDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            credit_card_detection: true,
            ssn_detection: true,
            api_key_detection: true,
            private_key_detection: true,
        }
    }
}

// Phase 4: Enterprise configurations

/// Configuration for threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ThreatIntelConfig {
    /// Enable threat intelligence
    #[serde(default)]
    pub enabled: bool,
    /// Enable IP reputation checking
    #[serde(default = "default_true")]
    pub ip_reputation_enabled: bool,
    /// Enable domain reputation checking
    #[serde(default = "default_true")]
    pub domain_reputation_enabled: bool,
    /// Enable IoC checking
    #[serde(default = "default_true")]
    pub ioc_enabled: bool,
    /// Score threshold for blocking (0-100)
    #[serde(default = "default_intel_block_threshold")]
    pub block_threshold: u8,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ip_reputation_enabled: true,
            domain_reputation_enabled: true,
            ioc_enabled: true,
            block_threshold: 80,
        }
    }
}

fn default_intel_block_threshold() -> u8 {
    80
}

/// Configuration for virtual patching
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VirtualPatchingConfig {
    /// Enable virtual patching
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Auto-update patches from feed
    #[serde(default)]
    pub auto_update: bool,
    /// Log patch matches
    #[serde(default = "default_true")]
    pub log_matches: bool,
}

impl Default for VirtualPatchingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_update: false,
            log_matches: true,
        }
    }
}

/// Configuration for supply chain protection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SupplyChainConfig {
    /// Enable supply chain protection
    #[serde(default)]
    pub enabled: bool,
    /// Enable SRI validation
    #[serde(default = "default_true")]
    pub sri_enabled: bool,
    /// Enable suspicious pattern detection
    #[serde(default = "default_true")]
    pub pattern_detection_enabled: bool,
    /// Enable CSP header checking
    #[serde(default = "default_true")]
    pub csp_enabled: bool,
}

impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sri_enabled: true,
            pattern_detection_enabled: true,
            csp_enabled: true,
        }
    }
}

/// Configuration for metrics collection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MetricsConfig {
    /// Enable metrics collection
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Enable per-rule metrics
    #[serde(default = "default_true")]
    pub per_rule_metrics: bool,
    /// Enable latency histograms
    #[serde(default = "default_true")]
    pub latency_histograms: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_rule_metrics: true,
            latency_histograms: true,
        }
    }
}

/// Configuration for streaming body inspection
///
/// Streaming mode inspects request bodies incrementally as chunks arrive,
/// using a sliding window with overlap to detect patterns that span chunks.
/// This provides constant memory usage regardless of body size.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StreamingConfig {
    /// Enable streaming mode (vs full buffering)
    #[serde(default)]
    pub enabled: bool,
    /// Size of overlap buffer between chunks (bytes)
    /// This ensures patterns spanning chunk boundaries are detected.
    /// Default: 256 bytes (enough for most attack patterns)
    #[serde(default = "default_window_overlap")]
    pub window_overlap: usize,
    /// Score threshold for early termination
    /// If accumulated score exceeds this, stop inspecting and block immediately.
    /// Default: 50 (2x block threshold)
    #[serde(default = "default_early_termination")]
    pub early_termination_threshold: u32,
    /// Timeout for abandoned streaming sessions (seconds)
    /// Sessions without activity for this duration are cleaned up.
    /// Default: 300 seconds (5 minutes)
    #[serde(default = "default_cleanup_timeout")]
    pub cleanup_timeout_secs: u64,
    /// Minimum body size to use streaming (bytes)
    /// Bodies smaller than this are inspected in full (more efficient).
    /// Default: 4096 bytes (4KB)
    #[serde(default = "default_min_streaming_size")]
    pub min_streaming_size: usize,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_overlap: 256,
            early_termination_threshold: 50,
            cleanup_timeout_secs: 300,
            min_streaming_size: 4096,
        }
    }
}

fn default_window_overlap() -> usize {
    256
}

fn default_early_termination() -> u32 {
    50
}

fn default_cleanup_timeout() -> u64 {
    300
}

fn default_min_streaming_size() -> usize {
    4096
}

/// Configuration for ML-based attack detection
///
/// ML detection runs alongside rule-based detection to catch attack
/// variations that bypass regex patterns. Scores from ML detection
/// contribute to the overall anomaly score.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MlConfig {
    /// Enable ML-based attack classification
    #[serde(default)]
    pub classifier_enabled: bool,
    /// Minimum confidence threshold for ML detections (0.0 - 1.0)
    #[serde(default = "default_ml_confidence")]
    pub min_confidence: f32,
    /// Enable request fingerprinting for anomaly detection
    #[serde(default)]
    pub fingerprinting_enabled: bool,
    /// Anomaly threshold for fingerprinting (0.0 - 1.0)
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f32,
    /// Enable payload similarity detection
    #[serde(default)]
    pub similarity_enabled: bool,
    /// Similarity threshold for flagging payloads (0.0 - 1.0)
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f32,
    /// Score contribution from ML detections (multiplier)
    #[serde(default = "default_ml_score_weight")]
    pub score_weight: f32,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            classifier_enabled: false,
            min_confidence: 0.4,
            fingerprinting_enabled: false,
            anomaly_threshold: 0.5,
            similarity_enabled: false,
            similarity_threshold: 0.5,
            score_weight: 1.0,
        }
    }
}

fn default_ml_confidence() -> f32 {
    0.4
}

fn default_anomaly_threshold() -> f32 {
    0.5
}

fn default_similarity_threshold() -> f32 {
    0.5
}

fn default_ml_score_weight() -> f32 {
    1.0
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            paranoia_level: 1,
            sqli_enabled: true,
            xss_enabled: true,
            path_traversal_enabled: true,
            command_injection_enabled: true,
            protocol_enabled: true,
            block_mode: true,
            exclude_paths: vec![],
            body_inspection_enabled: true,
            max_body_size: 1048576, // 1MB
            response_inspection_enabled: false,
            scoring: ScoringConfig::default(),
            rules: RuleManagement::default(),
            streaming: StreamingConfig::default(),
            ml: MlConfig::default(),
            api_security: ApiSecurityConfig::default(),
            bot_detection: BotDetectionConfig::default(),
            credential_protection: CredentialProtectionConfig::default(),
            sensitive_data: SensitiveDataDetectionConfig::default(),
            // Phase 4: Enterprise features
            threat_intel: ThreatIntelConfig::default(),
            virtual_patching: VirtualPatchingConfig::default(),
            supply_chain: SupplyChainConfig::default(),
            metrics: MetricsConfig::default(),
            federated: FederatedConfig::default(),
        }
    }
}

/// Federated learning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FederatedConfig {
    /// Enable federated learning
    #[serde(default)]
    pub enabled: bool,
    /// Coordinator server URL
    #[serde(default)]
    pub coordinator_url: Option<String>,
    /// Local training batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Minimum samples before contributing
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,
    /// Update interval in seconds
    #[serde(default = "default_update_interval")]
    pub update_interval_secs: u64,
    /// Privacy budget (epsilon for differential privacy)
    #[serde(default = "default_privacy_epsilon")]
    pub privacy_epsilon: f64,
    /// Enable secure aggregation
    #[serde(default = "default_true")]
    pub secure_aggregation: bool,
}

impl Default for FederatedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            coordinator_url: None,
            batch_size: 32,
            min_samples: 1000,
            update_interval_secs: 3600,
            privacy_epsilon: 1.0,
            secure_aggregation: true,
        }
    }
}

fn default_batch_size() -> usize {
    32
}

fn default_min_samples() -> usize {
    1000
}

fn default_update_interval() -> u64 {
    3600
}

fn default_privacy_epsilon() -> f64 {
    1.0
}

/// Scoring configuration for anomaly-based detection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScoringConfig {
    /// Enable scoring mode (vs binary block/allow)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Score threshold for blocking (default: 25)
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u32,
    /// Score threshold for logging (default: 10)
    #[serde(default = "default_log_threshold")]
    pub log_threshold: u32,
    /// Per-category score multipliers
    #[serde(default)]
    pub category_weights: HashMap<String, f32>,
    /// Location-based score multipliers
    #[serde(default)]
    pub location_weights: LocationWeights,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_threshold: 25,
            log_threshold: 10,
            category_weights: HashMap::new(),
            location_weights: LocationWeights::default(),
        }
    }
}

/// Location-based score multipliers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocationWeights {
    /// Path multiplier
    #[serde(default = "default_path_weight")]
    pub path: f32,
    /// Query string multiplier (highest risk)
    #[serde(default = "default_query_weight")]
    pub query: f32,
    /// Header multiplier
    #[serde(default = "default_header_weight")]
    pub header: f32,
    /// Cookie multiplier
    #[serde(default = "default_cookie_weight")]
    pub cookie: f32,
    /// Body multiplier
    #[serde(default = "default_body_weight")]
    pub body: f32,
}

impl Default for LocationWeights {
    fn default() -> Self {
        Self {
            path: 1.2,
            query: 1.5,
            header: 1.0,
            cookie: 1.3,
            body: 1.2,
        }
    }
}

impl LocationWeights {
    /// Get weight for a location string
    pub fn get(&self, location: &str) -> f32 {
        if location == "path" {
            self.path
        } else if location == "query" {
            self.query
        } else if location.starts_with("header:") {
            self.header
        } else if location.starts_with("cookie:") {
            self.cookie
        } else if location == "body" || location == "response_body" {
            self.body
        } else {
            1.0
        }
    }
}

/// Rule management configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleManagement {
    /// Explicitly enabled rules (if set, only these run)
    #[serde(default)]
    pub enabled: Option<Vec<RuleSelector>>,
    /// Explicitly disabled rules
    #[serde(default)]
    pub disabled: Vec<RuleSelector>,
    /// Per-rule overrides
    #[serde(default)]
    pub overrides: Vec<RuleOverride>,
    /// Exclusions (skip rules for certain conditions)
    #[serde(default)]
    pub exclusions: Vec<RuleExclusion>,
}

/// Rule selector for enabling/disabling rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleSelector {
    /// Single rule by ID: 942100
    Id(u32),
    /// Pattern: "942*", "942100-942199", "@sqli-union"
    Pattern(String),
}

impl RuleSelector {
    /// Check if this selector matches a rule
    pub fn matches(&self, rule_id: u32, tags: &[String]) -> bool {
        match self {
            RuleSelector::Id(id) => *id == rule_id,
            RuleSelector::Pattern(pattern) => {
                // Tag match: @tag-name
                if let Some(tag) = pattern.strip_prefix('@') {
                    return tags.iter().any(|t| t == tag);
                }

                // Range match: 942100-942199
                if let Some((start, end)) = pattern.split_once('-') {
                    if let (Ok(start_id), Ok(end_id)) = (start.parse::<u32>(), end.parse::<u32>()) {
                        return rule_id >= start_id && rule_id <= end_id;
                    }
                }

                // Wildcard match: 942*
                if let Some(prefix) = pattern.strip_suffix('*') {
                    let rule_str = rule_id.to_string();
                    return rule_str.starts_with(prefix);
                }

                // Exact match as string
                pattern == &rule_id.to_string()
            }
        }
    }
}

/// Rule override configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverride {
    /// Rules to override
    pub rules: Vec<RuleSelector>,
    /// Override action
    #[serde(default)]
    pub action: Option<OverrideAction>,
    /// Override base score
    #[serde(default)]
    pub score: Option<u32>,
    /// Conditions for this override
    #[serde(default)]
    pub conditions: Option<ExclusionConditions>,
}

/// Override action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OverrideAction {
    /// Block on match
    Block,
    /// Log only
    Log,
    /// Allow (skip rule)
    Allow,
}

/// Rule exclusion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleExclusion {
    /// Rules to exclude
    pub rules: Vec<RuleSelector>,
    /// Conditions for exclusion
    pub conditions: ExclusionConditions,
}

/// Conditions for rule exclusions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExclusionConditions {
    /// Path prefixes
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    /// Path regex pattern
    #[serde(default)]
    pub path_regex: Option<String>,
    /// Source IP/CIDR ranges
    #[serde(default)]
    pub source_ips: Option<Vec<String>>,
    /// Header matches
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    /// HTTP methods
    #[serde(default)]
    pub methods: Option<Vec<String>>,
}

/// JSON-serializable config for Configure events
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WafConfigJson {
    #[serde(default = "default_paranoia")]
    pub paranoia_level: u8,
    #[serde(default = "default_true")]
    pub sqli: bool,
    #[serde(default = "default_true")]
    pub xss: bool,
    #[serde(default = "default_true")]
    pub path_traversal: bool,
    #[serde(default = "default_true")]
    pub command_injection: bool,
    #[serde(default = "default_true")]
    pub protocol: bool,
    #[serde(default = "default_true")]
    pub block_mode: bool,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default = "default_true")]
    pub body_inspection: bool,
    #[serde(default = "default_max_body")]
    pub max_body_size: usize,
    #[serde(default)]
    pub response_inspection: bool,
    #[serde(default)]
    pub scoring: Option<ScoringConfig>,
    #[serde(default)]
    pub rules: Option<RuleManagement>,
    #[serde(default)]
    pub streaming: Option<StreamingConfig>,
    #[serde(default)]
    pub ml: Option<MlConfig>,
    #[serde(default)]
    pub api_security: Option<ApiSecurityConfig>,
    #[serde(default)]
    pub bot_detection: Option<BotDetectionConfig>,
    #[serde(default)]
    pub credential_protection: Option<CredentialProtectionConfig>,
    #[serde(default)]
    pub sensitive_data: Option<SensitiveDataDetectionConfig>,
    // Phase 4: Enterprise features
    #[serde(default)]
    pub threat_intel: Option<ThreatIntelConfig>,
    #[serde(default)]
    pub virtual_patching: Option<VirtualPatchingConfig>,
    #[serde(default)]
    pub supply_chain: Option<SupplyChainConfig>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub federated: Option<FederatedConfig>,
}

fn default_paranoia() -> u8 {
    1
}

fn default_true() -> bool {
    true
}

fn default_max_body() -> usize {
    1048576
}

fn default_block_threshold() -> u32 {
    25
}

fn default_log_threshold() -> u32 {
    10
}

fn default_path_weight() -> f32 {
    1.2
}

fn default_query_weight() -> f32 {
    1.5
}

fn default_header_weight() -> f32 {
    1.0
}

fn default_cookie_weight() -> f32 {
    1.3
}

fn default_body_weight() -> f32 {
    1.2
}

impl From<WafConfigJson> for WafConfig {
    fn from(json: WafConfigJson) -> Self {
        WafConfig {
            paranoia_level: json.paranoia_level,
            sqli_enabled: json.sqli,
            xss_enabled: json.xss,
            path_traversal_enabled: json.path_traversal,
            command_injection_enabled: json.command_injection,
            protocol_enabled: json.protocol,
            block_mode: json.block_mode,
            exclude_paths: json.exclude_paths,
            body_inspection_enabled: json.body_inspection,
            max_body_size: json.max_body_size,
            response_inspection_enabled: json.response_inspection,
            scoring: json.scoring.unwrap_or_default(),
            rules: json.rules.unwrap_or_default(),
            streaming: json.streaming.unwrap_or_default(),
            ml: json.ml.unwrap_or_default(),
            api_security: json.api_security.unwrap_or_default(),
            bot_detection: json.bot_detection.unwrap_or_default(),
            credential_protection: json.credential_protection.unwrap_or_default(),
            sensitive_data: json.sensitive_data.unwrap_or_default(),
            // Phase 4: Enterprise features
            threat_intel: json.threat_intel.unwrap_or_default(),
            virtual_patching: json.virtual_patching.unwrap_or_default(),
            supply_chain: json.supply_chain.unwrap_or_default(),
            metrics: json.metrics.unwrap_or_default(),
            federated: json.federated.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_selector_id() {
        let selector = RuleSelector::Id(942100);
        assert!(selector.matches(942100, &[]));
        assert!(!selector.matches(942101, &[]));
    }

    #[test]
    fn test_rule_selector_wildcard() {
        let selector = RuleSelector::Pattern("942*".to_string());
        assert!(selector.matches(942100, &[]));
        assert!(selector.matches(942999, &[]));
        assert!(!selector.matches(941100, &[]));
    }

    #[test]
    fn test_rule_selector_range() {
        let selector = RuleSelector::Pattern("942100-942199".to_string());
        assert!(selector.matches(942100, &[]));
        assert!(selector.matches(942150, &[]));
        assert!(selector.matches(942199, &[]));
        assert!(!selector.matches(942200, &[]));
        assert!(!selector.matches(942099, &[]));
    }

    #[test]
    fn test_rule_selector_tag() {
        let selector = RuleSelector::Pattern("@sqli-union".to_string());
        assert!(selector.matches(942100, &["sqli-union".to_string()]));
        assert!(!selector.matches(942100, &["sqli-blind".to_string()]));
    }

    #[test]
    fn test_location_weights() {
        let weights = LocationWeights::default();
        assert_eq!(weights.get("query"), 1.5);
        assert_eq!(weights.get("path"), 1.2);
        assert_eq!(weights.get("header:User-Agent"), 1.0);
        assert_eq!(weights.get("body"), 1.2);
    }

    #[test]
    fn test_scoring_config_default() {
        let config = ScoringConfig::default();
        assert!(config.enabled);
        assert_eq!(config.block_threshold, 25);
        assert_eq!(config.log_threshold, 10);
    }
}
