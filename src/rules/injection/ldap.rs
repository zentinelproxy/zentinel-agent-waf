//! LDAP Injection Rules

use crate::rules::{AttackType, Confidence, Rule, RuleBuilder, Severity};
use anyhow::Result;

pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let all_rules = vec![
        RuleBuilder::new(933100, "LDAP Injection: Filter injection")
            .description("Detects LDAP filter injection characters")
            .attack_type(AttackType::LdapInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(\(|\)|\\28|\\29|\*|\x00|\\00)")
            .base_score(8)
            .cwe(90)
            .tags(&["ldap", "injection"])
            .build()?,
        RuleBuilder::new(933101, "LDAP Injection: Wildcard bypass")
            .description("Detects LDAP wildcard authentication bypass")
            .attack_type(AttackType::LdapInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"\*\)\(&|\)\(\|\(")
            .base_score(9)
            .cwe(90)
            .tags(&["ldap", "auth-bypass"])
            .build()?,
        RuleBuilder::new(933102, "LDAP Injection: Boolean injection")
            .description("Detects LDAP boolean-based injection")
            .attack_type(AttackType::LdapInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\(\||\(&|\(!")
            .base_score(7)
            .cwe(90)
            .tags(&["ldap", "boolean"])
            .build()?,
        RuleBuilder::new(933103, "LDAP Injection: DN injection")
            .description("Detects LDAP Distinguished Name injection")
            .attack_type(AttackType::LdapInjection)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"(?i)(cn|uid|dc|ou|objectclass)\s*=")
            .base_score(6)
            .cwe(90)
            .tags(&["ldap", "dn"])
            .build()?,
        RuleBuilder::new(933104, "LDAP Injection: Null byte")
            .description("Detects null byte injection in LDAP queries")
            .attack_type(AttackType::LdapInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(%00|\\00|\x00)")
            .base_score(8)
            .cwe(90)
            .tags(&["ldap", "null-byte"])
            .build()?,
    ];

    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}
