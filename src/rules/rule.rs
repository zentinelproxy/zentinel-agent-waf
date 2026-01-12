//! Rule types and builder
//!
//! Defines the Rule struct with metadata and a builder pattern for easy rule creation.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Attack type detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackType {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    ProtocolAttack,
    ScannerDetection,
    RequestSmuggling,
    // New attack types
    Ssti,
    LdapInjection,
    XpathInjection,
    Ssrf,
    Deserialization,
    // Phase 3 attack types
    DataLeakage,
    // Phase 4 attack types
    Reconnaissance,
    RemoteCodeExecution,
    SupplyChain,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::SqlInjection => write!(f, "SQL Injection"),
            AttackType::Xss => write!(f, "Cross-Site Scripting"),
            AttackType::PathTraversal => write!(f, "Path Traversal"),
            AttackType::CommandInjection => write!(f, "Command Injection"),
            AttackType::ProtocolAttack => write!(f, "Protocol Attack"),
            AttackType::ScannerDetection => write!(f, "Scanner Detection"),
            AttackType::RequestSmuggling => write!(f, "Request Smuggling"),
            AttackType::Ssti => write!(f, "Server-Side Template Injection"),
            AttackType::LdapInjection => write!(f, "LDAP Injection"),
            AttackType::XpathInjection => write!(f, "XPath Injection"),
            AttackType::Ssrf => write!(f, "Server-Side Request Forgery"),
            AttackType::Deserialization => write!(f, "Insecure Deserialization"),
            AttackType::DataLeakage => write!(f, "Data Leakage"),
            AttackType::Reconnaissance => write!(f, "Reconnaissance"),
            AttackType::RemoteCodeExecution => write!(f, "Remote Code Execution"),
            AttackType::SupplyChain => write!(f, "Supply Chain Attack"),
        }
    }
}

/// Rule severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Get score multiplier for this severity
    pub fn multiplier(&self) -> f32 {
        match self {
            Severity::Critical => 2.0,
            Severity::High => 1.5,
            Severity::Medium => 1.0,
            Severity::Low => 0.7,
            Severity::Info => 0.3,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Rule confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    /// High confidence, low false positive rate
    High,
    /// Medium confidence, some false positives expected
    Medium,
    /// Low confidence, informational, high FP rate
    Low,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::High => write!(f, "HIGH"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::Low => write!(f, "LOW"),
        }
    }
}

/// Target location for rule application
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// URL path
    Path,
    /// Query string
    QueryString,
    /// All headers
    AllHeaders,
    /// Specific header
    Header(String),
    /// Cookie values
    Cookie,
    /// Request body
    Body,
    /// All locations
    All,
}

impl Target {
    /// Check if this target matches a location string
    pub fn matches_location(&self, location: &str) -> bool {
        match self {
            Target::Path => location == "path",
            Target::QueryString => location == "query",
            Target::AllHeaders => location.starts_with("header:"),
            Target::Header(name) => location == format!("header:{}", name),
            Target::Cookie => location.starts_with("cookie:"),
            Target::Body => location == "body" || location == "response_body",
            Target::All => true,
        }
    }
}

/// Detection rule with metadata
#[derive(Debug, Clone)]
pub struct Rule {
    // Identity
    /// Unique rule ID (e.g., 942100)
    pub id: u32,
    /// Human-readable rule name
    pub name: String,
    /// Detailed description
    pub description: String,

    // Classification
    /// Attack type this rule detects
    pub attack_type: AttackType,
    /// Severity level
    pub severity: Severity,
    /// Confidence level (affects false positive rate)
    pub confidence: Confidence,
    /// Paranoia level (1-4)
    pub paranoia_level: u8,

    // Detection
    /// Regex pattern for detection
    pub pattern: Regex,
    /// Raw pattern string (used for automata compilation)
    pub pattern_str: String,
    /// Target locations to apply this rule
    pub targets: Vec<Target>,

    // Scoring
    /// Base anomaly score (1-10)
    pub base_score: u32,

    // Metadata
    /// CVE identifiers
    pub cve_ids: Vec<String>,
    /// CWE identifier
    pub cwe_id: Option<u32>,
    /// OWASP category (e.g., "A03:2021-Injection")
    pub owasp_category: Option<String>,
    /// Reference URLs
    pub references: Vec<String>,
    /// Searchable tags
    pub tags: Vec<String>,
}

impl Rule {
    /// Check if this rule should apply to a given location
    pub fn applies_to(&self, location: &str) -> bool {
        if self.targets.is_empty() {
            return true; // Empty targets = all locations
        }
        self.targets.iter().any(|t| t.matches_location(location))
    }
}

/// Builder for creating rules with a fluent API
pub struct RuleBuilder {
    id: u32,
    name: String,
    description: String,
    attack_type: AttackType,
    severity: Severity,
    confidence: Confidence,
    paranoia_level: u8,
    pattern: String,
    targets: Vec<Target>,
    base_score: u32,
    cve_ids: Vec<String>,
    cwe_id: Option<u32>,
    owasp_category: Option<String>,
    references: Vec<String>,
    tags: Vec<String>,
}

impl RuleBuilder {
    /// Create a new rule builder with required fields
    pub fn new(id: u32, name: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
            description: String::new(),
            attack_type: AttackType::ProtocolAttack,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            paranoia_level: 1,
            pattern: String::new(),
            targets: vec![],
            base_score: 5,
            cve_ids: vec![],
            cwe_id: None,
            owasp_category: None,
            references: vec![],
            tags: vec![],
        }
    }

    /// Set the description
    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set the attack type
    pub fn attack_type(mut self, attack_type: AttackType) -> Self {
        self.attack_type = attack_type;
        self
    }

    /// Set the severity
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the confidence level
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Set the paranoia level
    pub fn paranoia(mut self, level: u8) -> Self {
        self.paranoia_level = level;
        self
    }

    /// Set the regex pattern
    pub fn pattern(mut self, pattern: &str) -> Self {
        self.pattern = pattern.to_string();
        self
    }

    /// Set the target locations
    pub fn targets(mut self, targets: Vec<Target>) -> Self {
        self.targets = targets;
        self
    }

    /// Set the base score
    pub fn base_score(mut self, score: u32) -> Self {
        self.base_score = score;
        self
    }

    /// Add a CVE identifier
    pub fn cve(mut self, cve: &str) -> Self {
        self.cve_ids.push(cve.to_string());
        self
    }

    /// Set the CWE identifier
    pub fn cwe(mut self, cwe: u32) -> Self {
        self.cwe_id = Some(cwe);
        self
    }

    /// Set the OWASP category
    pub fn owasp(mut self, category: &str) -> Self {
        self.owasp_category = Some(category.to_string());
        self
    }

    /// Add a reference URL
    pub fn reference(mut self, url: &str) -> Self {
        self.references.push(url.to_string());
        self
    }

    /// Add a tag
    pub fn tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    /// Add multiple tags
    pub fn tags(mut self, tags: &[&str]) -> Self {
        self.tags.extend(tags.iter().map(|s| s.to_string()));
        self
    }

    /// Build the rule
    pub fn build(self) -> Result<Rule, regex::Error> {
        let pattern = Regex::new(&self.pattern)?;
        Ok(Rule {
            id: self.id,
            name: self.name,
            description: self.description,
            attack_type: self.attack_type,
            severity: self.severity,
            confidence: self.confidence,
            paranoia_level: self.paranoia_level,
            pattern,
            pattern_str: self.pattern,
            targets: self.targets,
            base_score: self.base_score,
            cve_ids: self.cve_ids,
            cwe_id: self.cwe_id,
            owasp_category: self.owasp_category,
            references: self.references,
            tags: self.tags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_builder() {
        let rule = RuleBuilder::new(942100, "SQL Injection: UNION SELECT")
            .description("Detects UNION-based SQL injection")
            .attack_type(AttackType::SqlInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\bUNION\b.*\bSELECT\b")
            .base_score(9)
            .cwe(89)
            .owasp("A03:2021-Injection")
            .tags(&["sqli", "sqli-union"])
            .build()
            .unwrap();

        assert_eq!(rule.id, 942100);
        assert_eq!(rule.attack_type, AttackType::SqlInjection);
        assert_eq!(rule.severity, Severity::Critical);
        assert_eq!(rule.base_score, 9);
        assert!(rule.pattern.is_match("UNION SELECT * FROM users"));
    }

    #[test]
    fn test_target_matching() {
        assert!(Target::Path.matches_location("path"));
        assert!(!Target::Path.matches_location("query"));

        assert!(Target::QueryString.matches_location("query"));
        assert!(Target::AllHeaders.matches_location("header:User-Agent"));
        assert!(Target::Header("User-Agent".to_string()).matches_location("header:User-Agent"));
        assert!(!Target::Header("User-Agent".to_string()).matches_location("header:Host"));

        assert!(Target::All.matches_location("anything"));
    }

    #[test]
    fn test_severity_multiplier() {
        assert_eq!(Severity::Critical.multiplier(), 2.0);
        assert_eq!(Severity::High.multiplier(), 1.5);
        assert_eq!(Severity::Medium.multiplier(), 1.0);
        assert_eq!(Severity::Low.multiplier(), 0.7);
        assert_eq!(Severity::Info.multiplier(), 0.3);
    }
}
