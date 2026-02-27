//! Protocol Attack Rules
//!
//! HTTP protocol attacks including:
//! - Request smuggling
//! - SSRF (Server-Side Request Forgery)
//! - Insecure deserialization

pub mod deserialization;
pub mod ssrf;

use crate::rules::{AttackType, Confidence, Rule, RuleBuilder, Severity};
use anyhow::Result;

pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let all_rules = vec![
        // Protocol attacks
        RuleBuilder::new(920100, "Protocol: Control characters in request")
            .description("Detects control characters in HTTP request")
            .attack_type(AttackType::ProtocolAttack)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
            .base_score(8)
            .cwe(20)
            .tags(&["protocol", "malformed"])
            .build()?,

        RuleBuilder::new(920101, "Protocol: Null byte in request")
            .description("Detects null bytes in HTTP request")
            .attack_type(AttackType::ProtocolAttack)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(%00|\x00)")
            .base_score(8)
            .cwe(626)
            .tags(&["protocol", "null-byte"])
            .build()?,

        // Request smuggling
        RuleBuilder::new(920110, "Request Smuggling: GET/HEAD with body")
            .description("Detects GET/HEAD request with Content-Length")
            .attack_type(AttackType::RequestSmuggling)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"(?i)^(GET|HEAD)\s.*content-length:\s*[1-9]")
            .base_score(7)
            .cwe(444)
            .tags(&["protocol", "smuggling"])
            .build()?,

        RuleBuilder::new(920111, "Request Smuggling: Duplicate headers")
            .description("Detects duplicate Content-Length or Transfer-Encoding")
            .attack_type(AttackType::RequestSmuggling)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(content-length|transfer-encoding).*\r?\n.*(content-length|transfer-encoding)")
            .base_score(9)
            .cwe(444)
            .tags(&["protocol", "smuggling"])
            .build()?,

        RuleBuilder::new(920112, "Request Smuggling: CL.TE attack")
            .description("Detects Content-Length with Transfer-Encoding")
            .attack_type(AttackType::RequestSmuggling)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)content-length:.*transfer-encoding:|transfer-encoding:.*content-length:")
            .base_score(10)
            .cwe(444)
            .tags(&["protocol", "smuggling"])
            .build()?,

        RuleBuilder::new(920113, "Request Smuggling: Obfuscated Transfer-Encoding")
            .description("Detects obfuscated Transfer-Encoding header")
            .attack_type(AttackType::RequestSmuggling)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)transfer-encoding\s*:\s*(chunked\s*,|,\s*chunked|\s+chunked)")
            .base_score(10)
            .cwe(444)
            .tags(&["protocol", "smuggling"])
            .build()?,

        // Method override
        RuleBuilder::new(920120, "Protocol: HTTP method override")
            .description("Detects HTTP method override headers")
            .attack_type(AttackType::ProtocolAttack)
            .severity(Severity::Medium)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"(?i)(x-http-method-override|x-http-method|x-method-override)\s*:\s*(DELETE|PUT|PATCH)")
            .base_score(6)
            .cwe(650)
            .tags(&["protocol", "method-override"])
            .build()?,

        // Host header attacks
        RuleBuilder::new(920130, "Protocol: Invalid Host header")
            .description("Detects suspicious Host header values")
            .attack_type(AttackType::ProtocolAttack)
            .severity(Severity::Medium)
            .confidence(Confidence::Low)
            .paranoia(3)
            .pattern(r"(?i)host\s*:\s*(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)")
            .base_score(4)
            .cwe(20)
            .tags(&["protocol", "host-header"])
            .build()?,

        // HTTP response splitting
        RuleBuilder::new(920140, "Protocol: HTTP response splitting")
            .description("Detects CRLF injection for response splitting")
            .attack_type(AttackType::ProtocolAttack)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(%0d%0a|%0D%0A|\r\n)")
            .base_score(8)
            .cwe(113)
            .tags(&["protocol", "crlf", "response-splitting"])
            .build()?,
    ];

    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}
