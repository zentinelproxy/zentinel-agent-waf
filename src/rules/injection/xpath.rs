//! XPath Injection Rules

use crate::rules::{AttackType, Confidence, Rule, RuleBuilder, Severity};
use anyhow::Result;

pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let all_rules = vec![
        RuleBuilder::new(934100, "XPath Injection: Boolean true")
            .description("Detects XPath boolean true injection")
            .attack_type(AttackType::XpathInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)'\s*or\s*'[^']*'\s*=\s*'")
            .base_score(8)
            .cwe(91)
            .tags(&["xpath", "boolean"])
            .build()?,
        RuleBuilder::new(934101, "XPath Injection: XPath functions")
            .description("Detects XPath function injection")
            .attack_type(AttackType::XpathInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(substring|string-length|normalize-space|translate|concat)\s*\(")
            .base_score(7)
            .cwe(91)
            .tags(&["xpath", "function"])
            .build()?,
        RuleBuilder::new(934102, "XPath Injection: Axis traversal")
            .description("Detects XPath axis injection")
            .attack_type(AttackType::XpathInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(ancestor|child|descendant|following|parent|preceding|self)::")
            .base_score(7)
            .cwe(91)
            .tags(&["xpath", "traversal"])
            .build()?,
        RuleBuilder::new(934103, "XPath Injection: Position predicate")
            .description("Detects XPath position predicate injection")
            .attack_type(AttackType::XpathInjection)
            .severity(Severity::Medium)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"\[position\(\)\s*(=|>|<)\s*\d+\]")
            .base_score(5)
            .cwe(91)
            .tags(&["xpath", "predicate"])
            .build()?,
        RuleBuilder::new(934104, "XPath Injection: Node extraction")
            .description("Detects XPath node extraction")
            .attack_type(AttackType::XpathInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(/\*|\.\.|//\*|/child::\*)")
            .base_score(8)
            .cwe(91)
            .tags(&["xpath", "extraction"])
            .build()?,
        RuleBuilder::new(934105, "XPath Injection: Contains function")
            .description("Detects XPath contains() for blind injection")
            .attack_type(AttackType::XpathInjection)
            .severity(Severity::Medium)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"(?i)contains\s*\([^)]+,[^)]+\)")
            .base_score(5)
            .cwe(91)
            .tags(&["xpath", "blind"])
            .build()?,
    ];

    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}
