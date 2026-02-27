//! JSON Security Inspector
//!
//! Detects JSON-specific attacks:
//! - Mass assignment (unexpected fields)
//! - JSON injection
//! - Prototype pollution patterns
//! - NoSQL injection in JSON

use regex::Regex;
use std::sync::LazyLock;

use crate::detection::Detection;
use crate::rules::AttackType;

/// Types of JSON violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonViolation {
    /// NoSQL injection pattern
    NoSqlInjection { pattern: String },
    /// Prototype pollution attempt
    PrototypePollution,
    /// Suspicious key name
    SuspiciousKey { key: String },
    /// Deeply nested JSON (DoS)
    ExcessiveNesting { depth: usize },
}

/// JSON security inspector
pub struct JsonInspector {
    max_depth: usize,
}

// NoSQL injection patterns
static NOSQL_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        // MongoDB operators
        (Regex::new(r#""\$where"\s*:"#).unwrap(), "$where operator"),
        (Regex::new(r#""\$regex"\s*:"#).unwrap(), "$regex operator"),
        (Regex::new(r#""\$gt"\s*:"#).unwrap(), "$gt operator"),
        (Regex::new(r#""\$gte"\s*:"#).unwrap(), "$gte operator"),
        (Regex::new(r#""\$lt"\s*:"#).unwrap(), "$lt operator"),
        (Regex::new(r#""\$lte"\s*:"#).unwrap(), "$lte operator"),
        (Regex::new(r#""\$ne"\s*:"#).unwrap(), "$ne operator"),
        (Regex::new(r#""\$in"\s*:"#).unwrap(), "$in operator"),
        (Regex::new(r#""\$nin"\s*:"#).unwrap(), "$nin operator"),
        (Regex::new(r#""\$or"\s*:"#).unwrap(), "$or operator"),
        (Regex::new(r#""\$and"\s*:"#).unwrap(), "$and operator"),
        (Regex::new(r#""\$not"\s*:"#).unwrap(), "$not operator"),
        (Regex::new(r#""\$exists"\s*:"#).unwrap(), "$exists operator"),
        (Regex::new(r#""\$type"\s*:"#).unwrap(), "$type operator"),
        (Regex::new(r#""\$expr"\s*:"#).unwrap(), "$expr operator"),
        (
            Regex::new(r#""\$jsonSchema"\s*:"#).unwrap(),
            "$jsonSchema operator",
        ),
        // Function injection
        (
            Regex::new(r#""\$function"\s*:"#).unwrap(),
            "$function operator",
        ),
        (
            Regex::new(r#""\$accumulator"\s*:"#).unwrap(),
            "$accumulator operator",
        ),
    ]
});

// Prototype pollution patterns
static PROTOTYPE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#""__proto__"\s*:"#).unwrap(),
        Regex::new(r#""constructor"\s*:\s*\{"#).unwrap(),
        Regex::new(r#""prototype"\s*:"#).unwrap(),
    ]
});

// Suspicious key patterns (potential mass assignment)
static SUSPICIOUS_KEYS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (Regex::new(r#""isAdmin"\s*:"#).unwrap(), "isAdmin"),
        (Regex::new(r#""is_admin"\s*:"#).unwrap(), "is_admin"),
        (Regex::new(r#""admin"\s*:\s*(true|1)"#).unwrap(), "admin"),
        (Regex::new(r#""role"\s*:\s*"admin"#).unwrap(), "role=admin"),
        (Regex::new(r#""permissions"\s*:"#).unwrap(), "permissions"),
        (Regex::new(r#""privileges"\s*:"#).unwrap(), "privileges"),
        (Regex::new(r#""password"\s*:"#).unwrap(), "password"),
        (
            Regex::new(r#""password_hash"\s*:"#).unwrap(),
            "password_hash",
        ),
        (Regex::new(r#""api_key"\s*:"#).unwrap(), "api_key"),
        (Regex::new(r#""secret"\s*:"#).unwrap(), "secret"),
        (Regex::new(r#""internal"\s*:"#).unwrap(), "internal"),
        (Regex::new(r#""_id"\s*:"#).unwrap(), "_id"),
        (Regex::new(r#""id"\s*:"#).unwrap(), "id"),
    ]
});

impl JsonInspector {
    /// Create a new JSON inspector
    pub fn new() -> Self {
        Self { max_depth: 20 }
    }

    /// Create with custom max depth
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// Inspect JSON body for security issues
    pub fn inspect(&self, body: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check for NoSQL injection
        detections.extend(self.check_nosql_injection(body));

        // Check for prototype pollution
        detections.extend(self.check_prototype_pollution(body));

        // Check for suspicious keys (mass assignment)
        detections.extend(self.check_suspicious_keys(body));

        // Check nesting depth
        if let Some(d) = self.check_nesting_depth(body) {
            detections.push(d);
        }

        detections
    }

    /// Check for NoSQL injection patterns
    fn check_nosql_injection(&self, body: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for (pattern, name) in NOSQL_PATTERNS.iter() {
            if let Some(m) = pattern.find(body) {
                detections.push(Detection {
                    rule_id: 98100,
                    rule_name: format!("NoSQL Injection: {}", name),
                    attack_type: AttackType::SqlInjection,
                    matched_value: m.as_str().to_string(),
                    location: "body".to_string(),
                    base_score: 8,
                    tags: vec![
                        "json".to_string(),
                        "nosql".to_string(),
                        "injection".to_string(),
                    ],
                });
            }
        }

        detections
    }

    /// Check for prototype pollution attempts
    fn check_prototype_pollution(&self, body: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for pattern in PROTOTYPE_PATTERNS.iter() {
            if let Some(m) = pattern.find(body) {
                detections.push(Detection {
                    rule_id: 98101,
                    rule_name: "Prototype Pollution Attempt".to_string(),
                    attack_type: AttackType::ProtocolAttack,
                    matched_value: m.as_str().to_string(),
                    location: "body".to_string(),
                    base_score: 9,
                    tags: vec!["json".to_string(), "prototype-pollution".to_string()],
                });
            }
        }

        detections
    }

    /// Check for suspicious keys that might indicate mass assignment
    fn check_suspicious_keys(&self, body: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for (pattern, key_name) in SUSPICIOUS_KEYS.iter() {
            if let Some(m) = pattern.find(body) {
                // Lower score for common keys, higher for clearly dangerous
                let score = match *key_name {
                    "isAdmin" | "is_admin" | "admin" | "role=admin" => 7,
                    "permissions" | "privileges" => 6,
                    "password" | "password_hash" | "api_key" | "secret" => 5,
                    _ => 3,
                };

                detections.push(Detection {
                    rule_id: 98102,
                    rule_name: format!("Suspicious JSON Key: {}", key_name),
                    attack_type: AttackType::ProtocolAttack,
                    matched_value: m.as_str().to_string(),
                    location: "body".to_string(),
                    base_score: score,
                    tags: vec!["json".to_string(), "mass-assignment".to_string()],
                });
            }
        }

        detections
    }

    /// Check for excessive nesting (potential DoS)
    fn check_nesting_depth(&self, body: &str) -> Option<Detection> {
        let depth = calculate_json_depth(body);
        if depth > self.max_depth {
            Some(Detection {
                rule_id: 98103,
                rule_name: "JSON Excessive Nesting".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!("depth={} (max={})", depth, self.max_depth),
                location: "body".to_string(),
                base_score: 6,
                tags: vec!["json".to_string(), "dos".to_string(), "nesting".to_string()],
            })
        } else {
            None
        }
    }
}

impl Default for JsonInspector {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate the nesting depth of JSON
fn calculate_json_depth(body: &str) -> usize {
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for ch in body.chars() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match ch {
            '\\' if in_string => {
                escape_next = true;
            }
            '"' => {
                in_string = !in_string;
            }
            '{' | '[' if !in_string => {
                current_depth += 1;
                max_depth = max_depth.max(current_depth);
            }
            '}' | ']' if !in_string => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    max_depth
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nosql_injection() {
        let inspector = JsonInspector::new();

        let injection = r#"{"username": {"$gt": ""}, "password": {"$gt": ""}}"#;
        let detections = inspector.inspect(injection);
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.rule_id == 98100));

        let where_injection = r#"{"$where": "this.password == 'test'"}"#;
        let detections = inspector.inspect(where_injection);
        assert!(detections
            .iter()
            .any(|d| d.matched_value.contains("$where")));
    }

    #[test]
    fn test_prototype_pollution() {
        let inspector = JsonInspector::new();

        let pollution = r#"{"__proto__": {"isAdmin": true}}"#;
        let detections = inspector.inspect(pollution);
        assert!(detections.iter().any(|d| d.rule_id == 98101));

        let constructor = r#"{"constructor": {"prototype": {"isAdmin": true}}}"#;
        let detections = inspector.inspect(constructor);
        assert!(detections.iter().any(|d| d.rule_id == 98101));
    }

    #[test]
    fn test_suspicious_keys() {
        let inspector = JsonInspector::new();

        let mass_assignment = r#"{"username": "test", "isAdmin": true}"#;
        let detections = inspector.inspect(mass_assignment);
        assert!(detections.iter().any(|d| d.rule_id == 98102));
    }

    #[test]
    fn test_excessive_nesting() {
        let inspector = JsonInspector::with_max_depth(3);

        let deep_json = r#"{"a":{"b":{"c":{"d":{"e":1}}}}}"#;
        let detections = inspector.inspect(deep_json);
        assert!(detections.iter().any(|d| d.rule_id == 98103));

        let shallow_json = r#"{"a":{"b":1}}"#;
        let detections = inspector.inspect(shallow_json);
        assert!(!detections.iter().any(|d| d.rule_id == 98103));
    }

    #[test]
    fn test_normal_json() {
        let inspector = JsonInspector::new();

        let normal = r#"{"name": "John", "email": "john@example.com"}"#;
        let detections = inspector.inspect(normal);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_json_depth_calculation() {
        assert_eq!(calculate_json_depth(r#"{}"#), 1);
        assert_eq!(calculate_json_depth(r#"{"a":{}}"#), 2);
        assert_eq!(calculate_json_depth(r#"{"a":{"b":{}}}"#), 3);
        assert_eq!(calculate_json_depth(r#"[[[1]]]"#), 3);
    }
}
