//! Sensitive Data Detection
//!
//! Detects sensitive data in responses to prevent data leakage:
//! - Credit card numbers (with Luhn validation)
//! - Social Security Numbers (SSN)
//! - API keys and tokens (AWS, Google, GitHub, etc.)
//! - Private keys and certificates
//! - Email addresses (bulk detection)
//!
//! # Rule ID Ranges
//!
//! - 95000-95099: Credit card rules
//! - 95100-95199: SSN/ID rules
//! - 95200-95299: API key rules
//! - 95300-95399: Secret/key rules

use regex::Regex;
use std::sync::LazyLock;

use crate::detection::Detection;
use crate::rules::AttackType;

/// Sensitive data detection configuration
#[derive(Debug, Clone)]
pub struct SensitiveDataConfig {
    /// Enable credit card detection
    pub credit_card_detection: bool,
    /// Enable SSN detection
    pub ssn_detection: bool,
    /// Enable API key detection
    pub api_key_detection: bool,
    /// Enable private key detection
    pub private_key_detection: bool,
    /// Enable email bulk detection
    pub email_bulk_detection: bool,
    /// Minimum emails to trigger bulk detection
    pub email_bulk_threshold: usize,
    /// Mask detected values in logs
    pub mask_values: bool,
}

impl Default for SensitiveDataConfig {
    fn default() -> Self {
        Self {
            credit_card_detection: true,
            ssn_detection: true,
            api_key_detection: true,
            private_key_detection: true,
            email_bulk_detection: true,
            email_bulk_threshold: 10,
            mask_values: true,
        }
    }
}

/// Type of sensitive data detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensitiveDataType {
    CreditCard { card_type: String },
    Ssn,
    ApiKey { provider: String },
    PrivateKey { key_type: String },
    EmailBulk { count: usize },
}

/// Sensitive data detection result
#[derive(Debug, Clone)]
pub struct SensitiveDataMatch {
    /// Type of data found
    pub data_type: SensitiveDataType,
    /// Masked value (if masking enabled)
    pub masked_value: String,
    /// Position in content
    pub position: usize,
}

// Credit card patterns (format varies by card type)
static CREDIT_CARD_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap()
});

// Credit card with separators
static CREDIT_CARD_SEPARATED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5})\b").unwrap()
});

// SSN pattern (XXX-XX-XXXX) - simple pattern, validation done in code
static SSN_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap());

// API Key patterns
static API_KEY_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        // AWS Access Key ID
        (
            Regex::new(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
                .unwrap(),
            "AWS",
        ),
        // AWS Secret Access Key
        (
            Regex::new(r#"(?i)aws.{0,20}['"]\s*[A-Za-z0-9/+=]{40}\s*['"]"#).unwrap(),
            "AWS Secret",
        ),
        // Google API Key
        (Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(), "Google"),
        // GitHub Token
        (
            Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,255}").unwrap(),
            "GitHub",
        ),
        // GitHub Personal Access Token (classic)
        (
            Regex::new(r"github_pat_[A-Za-z0-9_]{22,255}").unwrap(),
            "GitHub PAT",
        ),
        // Slack Token
        (
            Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap(),
            "Slack",
        ),
        // Stripe API Key (live and test)
        (
            Regex::new(r"sk_(live|test)_[0-9a-zA-Z]{24,}").unwrap(),
            "Stripe",
        ),
        (
            Regex::new(r"pk_(live|test)_[0-9a-zA-Z]{24,}").unwrap(),
            "Stripe Public",
        ),
        // Twilio
        (Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(), "Twilio"),
        // SendGrid
        (
            Regex::new(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}").unwrap(),
            "SendGrid",
        ),
        // Mailchimp
        (
            Regex::new(r"[a-f0-9]{32}-us[0-9]{1,2}").unwrap(),
            "Mailchimp",
        ),
        // Square
        (
            Regex::new(r"sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}").unwrap(),
            "Square",
        ),
        // PayPal
        (
            Regex::new(r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}").unwrap(),
            "PayPal",
        ),
        // Heroku
        (
            Regex::new(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            )
            .unwrap(),
            "UUID/Heroku",
        ),
        // Generic API key pattern
        (
            Regex::new(r#"(?i)api[_-]?key['"]?\s*[:=]\s*['"]?[a-zA-Z0-9_-]{20,}['"]?"#).unwrap(),
            "Generic API",
        ),
        // Generic secret pattern
        (
            Regex::new(
                r#"(?i)(?:secret|password|passwd|pwd)[_-]?['"]?\s*[:=]\s*['"]?[^\s'"]{8,}['"]?"#,
            )
            .unwrap(),
            "Generic Secret",
        ),
    ]
});

// Private key patterns
static PRIVATE_KEY_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),
            "RSA",
        ),
        (
            Regex::new(r"-----BEGIN DSA PRIVATE KEY-----").unwrap(),
            "DSA",
        ),
        (Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(), "EC"),
        (
            Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
            "OpenSSH",
        ),
        (
            Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
            "PGP",
        ),
        (Regex::new(r"-----BEGIN PRIVATE KEY-----").unwrap(), "PKCS8"),
        (
            Regex::new(r"-----BEGIN ENCRYPTED PRIVATE KEY-----").unwrap(),
            "Encrypted PKCS8",
        ),
    ]
});

// Email pattern for bulk detection
static EMAIL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap());

/// Sensitive data detector
pub struct SensitiveDataDetector {
    config: SensitiveDataConfig,
}

impl SensitiveDataDetector {
    /// Create a new sensitive data detector
    pub fn new(config: SensitiveDataConfig) -> Self {
        Self { config }
    }

    /// Scan content for sensitive data
    pub fn scan(&self, content: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Credit card detection
        if self.config.credit_card_detection {
            detections.extend(self.scan_credit_cards(content));
        }

        // SSN detection
        if self.config.ssn_detection {
            detections.extend(self.scan_ssn(content));
        }

        // API key detection
        if self.config.api_key_detection {
            detections.extend(self.scan_api_keys(content));
        }

        // Private key detection
        if self.config.private_key_detection {
            detections.extend(self.scan_private_keys(content));
        }

        // Email bulk detection
        if self.config.email_bulk_detection {
            detections.extend(self.scan_email_bulk(content));
        }

        detections
    }

    /// Scan for credit card numbers
    fn scan_credit_cards(&self, content: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check continuous patterns
        for mat in CREDIT_CARD_PATTERN.find_iter(content) {
            let number = mat.as_str();
            if luhn_check(number) {
                let card_type = identify_card_type(number);
                detections.push(Detection {
                    rule_id: 95001,
                    rule_name: format!("Credit Card Detected: {}", card_type),
                    attack_type: AttackType::DataLeakage,
                    matched_value: mask_card_number(number),
                    location: "response_body".to_string(),
                    base_score: 9,
                    tags: vec![
                        "sensitive-data".to_string(),
                        "credit-card".to_string(),
                        "pci".to_string(),
                    ],
                });
            }
        }

        // Check separated patterns
        for mat in CREDIT_CARD_SEPARATED.find_iter(content) {
            let number = mat.as_str();
            let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
            if luhn_check(&digits) {
                let card_type = identify_card_type(&digits);
                detections.push(Detection {
                    rule_id: 95002,
                    rule_name: format!("Credit Card (Formatted) Detected: {}", card_type),
                    attack_type: AttackType::DataLeakage,
                    matched_value: mask_card_number(number),
                    location: "response_body".to_string(),
                    base_score: 9,
                    tags: vec![
                        "sensitive-data".to_string(),
                        "credit-card".to_string(),
                        "pci".to_string(),
                    ],
                });
            }
        }

        detections
    }

    /// Scan for SSN patterns
    fn scan_ssn(&self, content: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for mat in SSN_PATTERN.find_iter(content) {
            let ssn = mat.as_str();
            // Additional validation: not all 0s in any section
            let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() == 9 && is_valid_ssn(&digits) {
                detections.push(Detection {
                    rule_id: 95100,
                    rule_name: "Social Security Number Detected".to_string(),
                    attack_type: AttackType::DataLeakage,
                    matched_value: mask_ssn(ssn),
                    location: "response_body".to_string(),
                    base_score: 9,
                    tags: vec![
                        "sensitive-data".to_string(),
                        "ssn".to_string(),
                        "pii".to_string(),
                    ],
                });
            }
        }

        detections
    }

    /// Scan for API keys
    fn scan_api_keys(&self, content: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for (pattern, provider) in API_KEY_PATTERNS.iter() {
            for mat in pattern.find_iter(content) {
                let key = mat.as_str();
                detections.push(Detection {
                    rule_id: 95200,
                    rule_name: format!("API Key Detected: {}", provider),
                    attack_type: AttackType::DataLeakage,
                    matched_value: mask_api_key(key),
                    location: "response_body".to_string(),
                    base_score: 8,
                    tags: vec![
                        "sensitive-data".to_string(),
                        "api-key".to_string(),
                        provider.to_lowercase(),
                    ],
                });
            }
        }

        detections
    }

    /// Scan for private keys
    fn scan_private_keys(&self, content: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for (pattern, key_type) in PRIVATE_KEY_PATTERNS.iter() {
            if pattern.is_match(content) {
                detections.push(Detection {
                    rule_id: 95300,
                    rule_name: format!("Private Key Detected: {}", key_type),
                    attack_type: AttackType::DataLeakage,
                    matched_value: format!("-----BEGIN {} PRIVATE KEY-----", key_type),
                    location: "response_body".to_string(),
                    base_score: 10,
                    tags: vec![
                        "sensitive-data".to_string(),
                        "private-key".to_string(),
                        "critical".to_string(),
                    ],
                });
            }
        }

        detections
    }

    /// Scan for bulk email exposure
    fn scan_email_bulk(&self, content: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        let email_count = EMAIL_PATTERN.find_iter(content).count();
        if email_count >= self.config.email_bulk_threshold {
            detections.push(Detection {
                rule_id: 95101,
                rule_name: "Bulk Email Exposure".to_string(),
                attack_type: AttackType::DataLeakage,
                matched_value: format!("{} email addresses detected", email_count),
                location: "response_body".to_string(),
                base_score: 7,
                tags: vec![
                    "sensitive-data".to_string(),
                    "email".to_string(),
                    "pii".to_string(),
                ],
            });
        }

        detections
    }

    /// Get detailed matches (for debugging/logging)
    pub fn scan_detailed(&self, content: &str) -> Vec<SensitiveDataMatch> {
        let mut matches = Vec::new();

        // Credit cards
        if self.config.credit_card_detection {
            for mat in CREDIT_CARD_PATTERN.find_iter(content) {
                let number = mat.as_str();
                if luhn_check(number) {
                    matches.push(SensitiveDataMatch {
                        data_type: SensitiveDataType::CreditCard {
                            card_type: identify_card_type(number),
                        },
                        masked_value: mask_card_number(number),
                        position: mat.start(),
                    });
                }
            }
        }

        // SSN
        if self.config.ssn_detection {
            for mat in SSN_PATTERN.find_iter(content) {
                let ssn = mat.as_str();
                let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() == 9 && is_valid_ssn(&digits) {
                    matches.push(SensitiveDataMatch {
                        data_type: SensitiveDataType::Ssn,
                        masked_value: mask_ssn(ssn),
                        position: mat.start(),
                    });
                }
            }
        }

        // API Keys
        if self.config.api_key_detection {
            for (pattern, provider) in API_KEY_PATTERNS.iter() {
                for mat in pattern.find_iter(content) {
                    matches.push(SensitiveDataMatch {
                        data_type: SensitiveDataType::ApiKey {
                            provider: provider.to_string(),
                        },
                        masked_value: mask_api_key(mat.as_str()),
                        position: mat.start(),
                    });
                }
            }
        }

        // Private keys
        if self.config.private_key_detection {
            for (pattern, key_type) in PRIVATE_KEY_PATTERNS.iter() {
                if let Some(mat) = pattern.find(content) {
                    matches.push(SensitiveDataMatch {
                        data_type: SensitiveDataType::PrivateKey {
                            key_type: key_type.to_string(),
                        },
                        masked_value: format!("-----BEGIN {} PRIVATE KEY-----", key_type),
                        position: mat.start(),
                    });
                }
            }
        }

        matches
    }
}

impl Default for SensitiveDataDetector {
    fn default() -> Self {
        Self::new(SensitiveDataConfig::default())
    }
}

/// Luhn algorithm for credit card validation
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum % 10 == 0
}

/// Identify credit card type from number
fn identify_card_type(number: &str) -> String {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.starts_with('4') {
        "Visa".to_string()
    } else if digits.starts_with("51")
        || digits.starts_with("52")
        || digits.starts_with("53")
        || digits.starts_with("54")
        || digits.starts_with("55")
    {
        "Mastercard".to_string()
    } else if digits.starts_with("34") || digits.starts_with("37") {
        "American Express".to_string()
    } else if digits.starts_with("6011") || digits.starts_with("65") {
        "Discover".to_string()
    } else if digits.starts_with("35") {
        "JCB".to_string()
    } else if digits.starts_with("30") || digits.starts_with("36") || digits.starts_with("38") {
        "Diners Club".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// Validate SSN (basic checks)
fn is_valid_ssn(digits: &str) -> bool {
    if digits.len() != 9 {
        return false;
    }

    // Area number (first 3 digits) cannot be 000, 666, or 900-999
    let area: u32 = digits[0..3].parse().unwrap_or(0);
    if area == 0 || area == 666 || (900..=999).contains(&area) {
        return false;
    }

    // Group number (middle 2 digits) cannot be 00
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    if group == 0 {
        return false;
    }

    // Serial number (last 4 digits) cannot be 0000
    let serial: u32 = digits[5..9].parse().unwrap_or(0);
    if serial == 0 {
        return false;
    }

    true
}

/// Mask credit card number for logging
fn mask_card_number(number: &str) -> String {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "****".to_string();
    }
    format!("****-****-****-{}", &digits[digits.len() - 4..])
}

/// Mask SSN for logging
fn mask_ssn(ssn: &str) -> String {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "***-**-****".to_string();
    }
    format!("***-**-{}", &digits[digits.len() - 4..])
}

/// Mask API key for logging
fn mask_api_key(key: &str) -> String {
    if key.len() <= 8 {
        return "********".to_string();
    }
    format!("{}...{}", &key[..4], &key[key.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_check() {
        // Valid test card numbers
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500000000000004")); // Mastercard test
        assert!(luhn_check("340000000000009")); // Amex test

        // Invalid numbers
        assert!(!luhn_check("1234567890123456"));
        assert!(!luhn_check("4111111111111112"));
    }

    #[test]
    fn test_card_type_identification() {
        assert_eq!(identify_card_type("4111111111111111"), "Visa");
        assert_eq!(identify_card_type("5500000000000004"), "Mastercard");
        assert_eq!(identify_card_type("340000000000009"), "American Express");
        assert_eq!(identify_card_type("6011000000000000"), "Discover");
    }

    #[test]
    fn test_credit_card_detection() {
        let detector = SensitiveDataDetector::default();

        let content = "Customer card: 4111111111111111 on file";
        let detections = detector.scan(content);

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.rule_id == 95001));
    }

    #[test]
    fn test_formatted_credit_card() {
        let detector = SensitiveDataDetector::default();

        let content = "Card: 4111-1111-1111-1111";
        let detections = detector.scan(content);

        assert!(!detections.is_empty());
    }

    #[test]
    fn test_ssn_detection() {
        let detector = SensitiveDataDetector::default();

        let content = "SSN: 123-45-6789";
        let detections = detector.scan(content);

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.rule_id == 95100));
    }

    #[test]
    fn test_invalid_ssn() {
        let detector = SensitiveDataDetector::default();

        // Invalid area number (000)
        let content = "SSN: 000-12-3456";
        let detections = detector.scan(content);
        assert!(detections.iter().filter(|d| d.rule_id == 95100).count() == 0);

        // Invalid area number (666)
        let content = "SSN: 666-12-3456";
        let detections = detector.scan(content);
        assert!(detections.iter().filter(|d| d.rule_id == 95100).count() == 0);
    }

    #[test]
    fn test_aws_key_detection() {
        let detector = SensitiveDataDetector::default();

        let content = "aws_key = 'AKIAIOSFODNN7EXAMPLE'";
        let detections = detector.scan(content);

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.rule_id == 95200));
    }

    #[test]
    fn test_github_token_detection() {
        let detector = SensitiveDataDetector::default();

        let content = "token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'";
        let detections = detector.scan(content);

        assert!(!detections.is_empty());
        assert!(detections
            .iter()
            .any(|d| d.tags.contains(&"github".to_string())));
    }

    #[test]
    fn test_private_key_detection() {
        let detector = SensitiveDataDetector::default();

        let content = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3TS...
-----END RSA PRIVATE KEY-----
        "#;
        let detections = detector.scan(content);

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.rule_id == 95300));
        assert!(detections.iter().any(|d| d.base_score == 10)); // Critical
    }

    #[test]
    fn test_email_bulk_detection() {
        let config = SensitiveDataConfig {
            email_bulk_threshold: 3, // Low threshold for testing
            ..Default::default()
        };
        let detector = SensitiveDataDetector::new(config);

        let content =
            "Users: john@example.com, jane@example.com, bob@example.com, alice@example.com";
        let detections = detector.scan(content);

        assert!(detections.iter().any(|d| d.rule_id == 95101));
    }

    #[test]
    fn test_no_false_positives_normal_text() {
        let detector = SensitiveDataDetector::default();

        let content = "Hello world, this is normal text without any sensitive data.";
        let detections = detector.scan(content);

        assert!(detections.is_empty());
    }

    #[test]
    fn test_masking() {
        assert_eq!(mask_card_number("4111111111111111"), "****-****-****-1111");
        assert_eq!(mask_ssn("123-45-6789"), "***-**-6789");
        assert_eq!(mask_api_key("AKIAIOSFODNN7EXAMPLE"), "AKIA...MPLE");
    }

    #[test]
    fn test_detailed_scan() {
        let detector = SensitiveDataDetector::default();

        let content = "Card: 4111111111111111";
        let matches = detector.scan_detailed(content);

        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| matches!(m.data_type, SensitiveDataType::CreditCard { .. })));
    }

    #[test]
    fn test_generic_secret_detection() {
        let detector = SensitiveDataDetector::default();

        let content = r#"password = "mysecretpassword123""#;
        let detections = detector.scan(content);

        assert!(!detections.is_empty());
    }
}
