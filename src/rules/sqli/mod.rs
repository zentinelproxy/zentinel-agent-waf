//! SQL Injection Detection Rules
//!
//! Comprehensive SQLi detection covering:
//! - Union-based injection
//! - Error-based injection
//! - Blind injection (boolean and time-based)
//! - Stacked queries
//! - NoSQL injection

mod blind;
mod error_based;
mod nosql;
mod stacked;
mod union_based;

use super::Rule;
use anyhow::Result;

/// Load all SQL injection rules
pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let mut all_rules = Vec::new();

    all_rules.extend(union_based::rules()?);
    all_rules.extend(error_based::rules()?);
    all_rules.extend(blind::rules()?);
    all_rules.extend(stacked::rules()?);
    all_rules.extend(nosql::rules()?);

    // Filter by paranoia level
    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}

/// Common SQL keywords for detection
pub const SQL_KEYWORDS: &[&str] = &[
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "UNION", "FROM", "WHERE",
    "AND", "OR", "ORDER", "GROUP", "HAVING", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "LIMIT",
    "OFFSET",
];

/// Common SQL functions
pub const SQL_FUNCTIONS: &[&str] = &[
    "CONCAT",
    "SUBSTRING",
    "ASCII",
    "CHAR",
    "LENGTH",
    "COUNT",
    "SUM",
    "AVG",
    "MIN",
    "MAX",
    "SLEEP",
    "BENCHMARK",
    "WAITFOR",
    "DELAY",
    "IF",
    "CASE",
    "WHEN",
    "THEN",
    "ELSE",
    "END",
];
