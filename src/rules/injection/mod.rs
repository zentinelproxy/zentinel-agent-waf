//! Injection Attack Rules
//!
//! Various injection attacks beyond SQL and XSS:
//! - Command injection
//! - LDAP injection
//! - XPath injection
//! - Server-Side Template Injection (SSTI)

pub mod command;
pub mod ldap;
pub mod ssti;
pub mod xpath;

use crate::rules::Rule;
use anyhow::Result;

/// Load all injection rules (except command which is loaded separately)
pub fn all_rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    rules.extend(command::rules(paranoia_level)?);
    rules.extend(ldap::rules(paranoia_level)?);
    rules.extend(xpath::rules(paranoia_level)?);
    rules.extend(ssti::rules(paranoia_level)?);
    Ok(rules)
}
