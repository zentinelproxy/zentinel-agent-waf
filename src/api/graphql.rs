//! GraphQL Security Inspector
//!
//! Detects GraphQL-specific attacks and misconfigurations:
//! - Introspection queries (information disclosure)
//! - Query depth/complexity attacks (DoS)
//! - Batch query abuse
//! - Directive injection
//! - Field suggestion abuse

use regex::Regex;
use std::sync::LazyLock;

use crate::detection::Detection;
use crate::rules::AttackType;

/// GraphQL security configuration
#[derive(Debug, Clone)]
pub struct GraphQLConfig {
    /// Block introspection queries
    pub block_introspection: bool,
    /// Maximum query depth allowed
    pub max_depth: usize,
    /// Maximum number of fields per query
    pub max_fields: usize,
    /// Maximum batch size (number of queries)
    pub max_batch_size: usize,
    /// Block known dangerous operations
    pub block_dangerous_ops: bool,
}

impl Default for GraphQLConfig {
    fn default() -> Self {
        Self {
            block_introspection: true,
            max_depth: 10,
            max_fields: 100,
            max_batch_size: 10,
            block_dangerous_ops: true,
        }
    }
}

/// Types of GraphQL violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphQLViolation {
    /// Introspection query detected
    Introspection,
    /// Query too deep
    DepthExceeded { depth: usize, max: usize },
    /// Too many fields
    FieldsExceeded { count: usize, max: usize },
    /// Batch query abuse
    BatchExceeded { count: usize, max: usize },
    /// Dangerous directive detected
    DangerousDirective { directive: String },
    /// Potential injection in query
    QueryInjection { pattern: String },
}

/// GraphQL security inspector
pub struct GraphQLInspector {
    config: GraphQLConfig,
}

// Compiled regex patterns
static INTROSPECTION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // __schema and __type require { or (, but __typename is a leaf field
    Regex::new(r"(?i)(__schema|__type)\s*[\{\(]|__typename\b").unwrap()
});

static QUERY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(query|mutation|subscription)\s*[\w]*\s*[\(\{]").unwrap());

static DIRECTIVE_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@\w+").unwrap());

static INJECTION_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        // SQL-like patterns in variables
        (
            Regex::new(r#""\s*;\s*(DROP|DELETE|UPDATE|INSERT)"#).unwrap(),
            "sql-in-variable",
        ),
        // Script injection in string values
        (
            Regex::new(r#""[^"]*<script"#).unwrap(),
            "script-in-variable",
        ),
        // Template injection
        (Regex::new(r#"\$\{\{.*\}\}"#).unwrap(), "template-injection"),
        // NoSQL injection patterns
        (Regex::new(r#"\$where\s*:"#).unwrap(), "nosql-where"),
        (Regex::new(r#"\$regex\s*:"#).unwrap(), "nosql-regex"),
    ]
});

// Dangerous directives that could be abused
static DANGEROUS_DIRECTIVES: &[&str] = &[
    "@include",
    "@skip",
    "@deprecated",
    "@specifiedBy",
    "@defer",
    "@stream",
];

impl GraphQLInspector {
    /// Create a new GraphQL inspector
    pub fn new(config: GraphQLConfig) -> Self {
        Self { config }
    }

    /// Inspect a GraphQL query for security issues
    pub fn inspect(&self, body: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check for introspection
        if self.config.block_introspection {
            if let Some(d) = self.check_introspection(body) {
                detections.push(d);
            }
        }

        // Check query depth
        if let Some(d) = self.check_depth(body) {
            detections.push(d);
        }

        // Check field count
        if let Some(d) = self.check_field_count(body) {
            detections.push(d);
        }

        // Check batch size
        if let Some(d) = self.check_batch_size(body) {
            detections.push(d);
        }

        // Check for dangerous directives
        if self.config.block_dangerous_ops {
            detections.extend(self.check_directives(body));
        }

        // Check for injection patterns
        detections.extend(self.check_injection(body));

        detections
    }

    /// Check for introspection queries
    fn check_introspection(&self, body: &str) -> Option<Detection> {
        if INTROSPECTION_PATTERN.is_match(body) {
            Some(Detection {
                rule_id: 98001,
                rule_name: "GraphQL Introspection Blocked".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: INTROSPECTION_PATTERN
                    .find(body)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
                location: "body".to_string(),
                base_score: 5,
                tags: vec!["graphql".to_string(), "introspection".to_string()],
            })
        } else {
            None
        }
    }

    /// Check query depth (nesting level)
    fn check_depth(&self, body: &str) -> Option<Detection> {
        let depth = calculate_depth(body);
        if depth > self.config.max_depth {
            Some(Detection {
                rule_id: 98002,
                rule_name: "GraphQL Query Too Deep".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!("depth={} (max={})", depth, self.config.max_depth),
                location: "body".to_string(),
                base_score: 7,
                tags: vec![
                    "graphql".to_string(),
                    "dos".to_string(),
                    "depth".to_string(),
                ],
            })
        } else {
            None
        }
    }

    /// Check total field count
    fn check_field_count(&self, body: &str) -> Option<Detection> {
        let count = count_fields(body);
        if count > self.config.max_fields {
            Some(Detection {
                rule_id: 98003,
                rule_name: "GraphQL Too Many Fields".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!("fields={} (max={})", count, self.config.max_fields),
                location: "body".to_string(),
                base_score: 6,
                tags: vec![
                    "graphql".to_string(),
                    "dos".to_string(),
                    "fields".to_string(),
                ],
            })
        } else {
            None
        }
    }

    /// Check batch query count
    fn check_batch_size(&self, body: &str) -> Option<Detection> {
        // Check for array of queries
        let trimmed = body.trim();
        if trimmed.starts_with('[') {
            let count = count_queries_in_batch(body);
            if count > self.config.max_batch_size {
                return Some(Detection {
                    rule_id: 98004,
                    rule_name: "GraphQL Batch Query Abuse".to_string(),
                    attack_type: AttackType::ProtocolAttack,
                    matched_value: format!(
                        "batch_size={} (max={})",
                        count, self.config.max_batch_size
                    ),
                    location: "body".to_string(),
                    base_score: 6,
                    tags: vec![
                        "graphql".to_string(),
                        "dos".to_string(),
                        "batch".to_string(),
                    ],
                });
            }
        }

        // Check for multiple operations in single query
        let ops = QUERY_PATTERN.find_iter(body).count();
        if ops > self.config.max_batch_size {
            return Some(Detection {
                rule_id: 98004,
                rule_name: "GraphQL Multiple Operations".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!("operations={} (max={})", ops, self.config.max_batch_size),
                location: "body".to_string(),
                base_score: 5,
                tags: vec!["graphql".to_string(), "batch".to_string()],
            });
        }

        None
    }

    /// Check for dangerous directives
    fn check_directives(&self, body: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for directive_match in DIRECTIVE_PATTERN.find_iter(body) {
            let directive = directive_match.as_str();

            // Check if it's a known dangerous directive used excessively
            for &dangerous in DANGEROUS_DIRECTIVES {
                if directive.eq_ignore_ascii_case(dangerous) {
                    // Count occurrences
                    let count = body.matches(directive).count();
                    if count > 5 {
                        detections.push(Detection {
                            rule_id: 98005,
                            rule_name: "GraphQL Directive Abuse".to_string(),
                            attack_type: AttackType::ProtocolAttack,
                            matched_value: format!("{} (count={})", directive, count),
                            location: "body".to_string(),
                            base_score: 5,
                            tags: vec!["graphql".to_string(), "directive".to_string()],
                        });
                        break;
                    }
                }
            }
        }

        detections
    }

    /// Check for injection patterns in GraphQL
    fn check_injection(&self, body: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for (pattern, name) in INJECTION_PATTERNS.iter() {
            if let Some(m) = pattern.find(body) {
                detections.push(Detection {
                    rule_id: 98010,
                    rule_name: format!("GraphQL Injection: {}", name),
                    attack_type: AttackType::SqlInjection,
                    matched_value: m.as_str().to_string(),
                    location: "body".to_string(),
                    base_score: 8,
                    tags: vec!["graphql".to_string(), "injection".to_string()],
                });
            }
        }

        detections
    }
}

/// Calculate the nesting depth of a GraphQL query
fn calculate_depth(body: &str) -> usize {
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;

    for ch in body.chars() {
        match ch {
            '{' => {
                current_depth += 1;
                max_depth = max_depth.max(current_depth);
            }
            '}' => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    max_depth
}

/// Count the number of fields in a GraphQL query (approximation)
fn count_fields(body: &str) -> usize {
    // Simple heuristic: count identifiers that aren't keywords
    let keywords = [
        "query",
        "mutation",
        "subscription",
        "fragment",
        "on",
        "true",
        "false",
        "null",
    ];

    let mut count = 0;
    let mut in_string = false;
    let mut current_word = String::new();

    for ch in body.chars() {
        if ch == '"' {
            in_string = !in_string;
            continue;
        }

        if in_string {
            continue;
        }

        if ch.is_alphanumeric() || ch == '_' {
            current_word.push(ch);
        } else if !current_word.is_empty() {
            let word_lower = current_word.to_lowercase();
            if !keywords.contains(&word_lower.as_str()) && !current_word.starts_with('$') {
                count += 1;
            }
            current_word.clear();
        }
    }

    count
}

/// Count queries in a batch request
fn count_queries_in_batch(body: &str) -> usize {
    // Simple heuristic: count "query" occurrences in JSON array
    body.matches("\"query\"").count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_introspection_detection() {
        let inspector = GraphQLInspector::new(GraphQLConfig::default());

        let introspection = r#"{ __schema { types { name } } }"#;
        let detections = inspector.inspect(introspection);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].rule_id, 98001);

        let typename = r#"{ user { __typename id } }"#;
        let detections = inspector.inspect(typename);
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_depth_detection() {
        let config = GraphQLConfig {
            max_depth: 3,
            ..Default::default()
        };
        let inspector = GraphQLInspector::new(config);

        // Depth of 5
        let deep_query = r#"{ a { b { c { d { e } } } } }"#;
        let detections = inspector.inspect(deep_query);
        assert!(detections.iter().any(|d| d.rule_id == 98002));

        // Depth of 2
        let shallow_query = r#"{ user { name } }"#;
        let detections = inspector.inspect(shallow_query);
        assert!(!detections.iter().any(|d| d.rule_id == 98002));
    }

    #[test]
    fn test_field_count() {
        let config = GraphQLConfig {
            max_fields: 5,
            block_introspection: false,
            ..Default::default()
        };
        let inspector = GraphQLInspector::new(config);

        // Many fields
        let many_fields = r#"{ user { id name email phone address city country zip } }"#;
        let detections = inspector.inspect(many_fields);
        assert!(detections.iter().any(|d| d.rule_id == 98003));
    }

    #[test]
    fn test_injection_detection() {
        let inspector = GraphQLInspector::new(GraphQLConfig::default());

        let sql_injection = r#"{ user(name: "; DROP TABLE users; --") { id } }"#;
        let detections = inspector.inspect(sql_injection);
        assert!(detections.iter().any(|d| d.rule_id == 98010));
    }

    #[test]
    fn test_normal_query() {
        let config = GraphQLConfig {
            block_introspection: false,
            ..Default::default()
        };
        let inspector = GraphQLInspector::new(config);

        let normal = r#"query GetUser { user(id: "123") { name email } }"#;
        let detections = inspector.inspect(normal);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_depth_calculation() {
        assert_eq!(calculate_depth("{}"), 1);
        assert_eq!(calculate_depth("{ a { b } }"), 2);
        assert_eq!(calculate_depth("{ a { b { c } } }"), 3);
    }
}
