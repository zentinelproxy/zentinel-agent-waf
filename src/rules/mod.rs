//! WAF Rule Registry
//!
//! Contains all detection rules organized by attack category.

pub mod rule;

// Rule category modules
pub mod injection;
pub mod protocol;
pub mod scanner;
pub mod sqli;
pub mod traversal;
pub mod xss;

pub use rule::{AttackType, Confidence, Rule, RuleBuilder, Severity, Target};

use crate::config::WafConfig;
use anyhow::Result;

/// Load all rules based on configuration
pub fn load_rules(config: &WafConfig) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    // SQL Injection rules
    if config.sqli_enabled {
        rules.extend(sqli::rules(config.paranoia_level)?);
    }

    // XSS rules
    if config.xss_enabled {
        rules.extend(xss::rules(config.paranoia_level)?);
    }

    // Path traversal rules
    if config.path_traversal_enabled {
        rules.extend(traversal::rules(config.paranoia_level)?);
    }

    // Command injection and other injection rules
    if config.command_injection_enabled {
        rules.extend(injection::command::rules(config.paranoia_level)?);
    }

    // Protocol attack rules
    if config.protocol_enabled {
        rules.extend(protocol::rules(config.paranoia_level)?);
        rules.extend(scanner::rules(config.paranoia_level)?);
    }

    // New attack categories (always load, they have their own paranoia filters)
    rules.extend(injection::ssti::rules(config.paranoia_level)?);
    rules.extend(injection::ldap::rules(config.paranoia_level)?);
    rules.extend(injection::xpath::rules(config.paranoia_level)?);
    rules.extend(protocol::ssrf::rules(config.paranoia_level)?);
    rules.extend(protocol::deserialization::rules(config.paranoia_level)?);

    Ok(rules)
}

/// Get rule by ID
pub fn get_rule(rules: &[Rule], id: u32) -> Option<&Rule> {
    rules.iter().find(|r| r.id == id)
}

/// Get rules by attack type
pub fn get_rules_by_type(rules: &[Rule], attack_type: AttackType) -> Vec<&Rule> {
    rules
        .iter()
        .filter(|r| r.attack_type == attack_type)
        .collect()
}

/// Get rules by tag
pub fn get_rules_by_tag<'a>(rules: &'a [Rule], tag: &str) -> Vec<&'a Rule> {
    rules
        .iter()
        .filter(|r| r.tags.contains(&tag.to_string()))
        .collect()
}

/// Filter rules by selectors
pub fn filter_rules(
    rules: &[Rule],
    enabled: Option<&[crate::config::RuleSelector]>,
    disabled: &[crate::config::RuleSelector],
) -> Vec<Rule> {
    rules
        .iter()
        .filter(|rule| {
            // Check if rule is in enabled list (if specified)
            let is_enabled = match enabled {
                Some(selectors) => selectors.iter().any(|s| s.matches(rule.id, &rule.tags)),
                None => true, // No enabled list = all enabled
            };

            // Check if rule is in disabled list
            let is_disabled = disabled.iter().any(|s| s.matches(rule.id, &rule.tags));

            is_enabled && !is_disabled
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_rules_default_config() {
        let config = WafConfig::default();
        let rules = load_rules(&config).unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_load_rules_sqli_disabled() {
        let config = WafConfig {
            sqli_enabled: false,
            ..Default::default()
        };
        let rules = load_rules(&config).unwrap();

        // Should have no SQLi rules
        let sqli_rules = get_rules_by_type(&rules, AttackType::SqlInjection);
        assert!(sqli_rules.is_empty());
    }

    #[test]
    fn test_filter_rules_disabled() {
        let config = WafConfig::default();
        let rules = load_rules(&config).unwrap();

        let disabled = vec![crate::config::RuleSelector::Id(942100)];
        let filtered = filter_rules(&rules, None, &disabled);

        assert!(!filtered.iter().any(|r| r.id == 942100));
    }

    #[test]
    fn test_filter_rules_wildcard() {
        let config = WafConfig::default();
        let rules = load_rules(&config).unwrap();

        let disabled = vec![crate::config::RuleSelector::Pattern("942*".to_string())];
        let filtered = filter_rules(&rules, None, &disabled);

        // No 942xxx rules should be present
        assert!(!filtered.iter().any(|r| r.id >= 942000 && r.id < 943000));
    }
}
