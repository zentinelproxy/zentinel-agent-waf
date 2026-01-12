//! Schema Violation Types
//!
//! Defines violation types detected during schema validation.

use crate::detection::Detection;
use crate::rules::AttackType;

/// Schema violation detected during validation
#[derive(Debug, Clone)]
pub struct SchemaViolation {
    /// Violation type
    pub violation_type: SchemaViolationType,
    /// Location in request (path, query.param, header.name, body.field)
    pub location: String,
    /// Expected value/type from schema
    pub expected: String,
    /// Actual value found in request
    pub actual: String,
    /// Path in schema (e.g., "/users/{id}" or "Query.user.email")
    pub schema_path: String,
    /// Human-readable message
    pub message: String,
}

impl SchemaViolation {
    /// Convert schema violation to WAF detection
    pub fn into_detection(self) -> Detection {
        Detection {
            rule_id: self.violation_type.rule_id(),
            rule_name: self.violation_type.rule_name().to_string(),
            attack_type: self.violation_type.attack_type(),
            matched_value: self.actual.chars().take(100).collect(),
            location: self.location,
            base_score: self.violation_type.base_score(),
            message: Some(self.message),
        }
    }
}

/// Schema violation types with associated rule IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaViolationType {
    // OpenAPI violations (98300-98349)
    /// Path not defined in OpenAPI spec
    UnknownPath,
    /// HTTP method not allowed for this path
    UnknownMethod,
    /// Required parameter missing
    MissingRequiredParameter,
    /// Parameter type doesn't match schema
    InvalidParameterType,
    /// Parameter format doesn't match schema
    InvalidParameterFormat,
    /// Request body doesn't match schema
    InvalidRequestBody,
    /// Content-Type not allowed for this operation
    InvalidContentType,
    /// Response status code not in spec
    UnknownResponseStatus,
    /// Response body doesn't match schema
    InvalidResponseBody,

    // GraphQL violations (98350-98399)
    /// Type not defined in schema
    UnknownType,
    /// Field not defined on type
    UnknownField,
    /// Argument value is invalid
    InvalidArgument,
    /// Required argument is missing
    MissingRequiredArgument,
    /// Argument type doesn't match schema
    InvalidArgumentType,
    /// Field access not authorized (with access rules)
    UnauthorizedFieldAccess,
    /// Using a deprecated field
    DeprecatedFieldUsage,
}

impl SchemaViolationType {
    /// Get rule ID for this violation type
    pub fn rule_id(&self) -> u32 {
        match self {
            // OpenAPI violations: 98300-98349
            SchemaViolationType::UnknownPath => 98300,
            SchemaViolationType::UnknownMethod => 98301,
            SchemaViolationType::MissingRequiredParameter => 98302,
            SchemaViolationType::InvalidParameterType => 98303,
            SchemaViolationType::InvalidParameterFormat => 98304,
            SchemaViolationType::InvalidRequestBody => 98305,
            SchemaViolationType::InvalidContentType => 98306,
            SchemaViolationType::UnknownResponseStatus => 98307,
            SchemaViolationType::InvalidResponseBody => 98308,

            // GraphQL violations: 98350-98399
            SchemaViolationType::UnknownType => 98350,
            SchemaViolationType::UnknownField => 98351,
            SchemaViolationType::InvalidArgument => 98352,
            SchemaViolationType::MissingRequiredArgument => 98353,
            SchemaViolationType::InvalidArgumentType => 98354,
            SchemaViolationType::UnauthorizedFieldAccess => 98355,
            SchemaViolationType::DeprecatedFieldUsage => 98356,
        }
    }

    /// Get rule name for this violation type
    pub fn rule_name(&self) -> &'static str {
        match self {
            SchemaViolationType::UnknownPath => "Schema: Unknown path",
            SchemaViolationType::UnknownMethod => "Schema: Unknown method",
            SchemaViolationType::MissingRequiredParameter => "Schema: Missing required parameter",
            SchemaViolationType::InvalidParameterType => "Schema: Invalid parameter type",
            SchemaViolationType::InvalidParameterFormat => "Schema: Invalid parameter format",
            SchemaViolationType::InvalidRequestBody => "Schema: Invalid request body",
            SchemaViolationType::InvalidContentType => "Schema: Invalid content type",
            SchemaViolationType::UnknownResponseStatus => "Schema: Unknown response status",
            SchemaViolationType::InvalidResponseBody => "Schema: Invalid response body",
            SchemaViolationType::UnknownType => "GraphQL: Unknown type",
            SchemaViolationType::UnknownField => "GraphQL: Unknown field",
            SchemaViolationType::InvalidArgument => "GraphQL: Invalid argument",
            SchemaViolationType::MissingRequiredArgument => "GraphQL: Missing required argument",
            SchemaViolationType::InvalidArgumentType => "GraphQL: Invalid argument type",
            SchemaViolationType::UnauthorizedFieldAccess => "GraphQL: Unauthorized field access",
            SchemaViolationType::DeprecatedFieldUsage => "GraphQL: Deprecated field usage",
        }
    }

    /// Get base anomaly score for this violation type
    pub fn base_score(&self) -> u32 {
        match self {
            // High severity - likely attacks or security issues
            SchemaViolationType::UnknownPath => 6,
            SchemaViolationType::InvalidRequestBody => 7,
            SchemaViolationType::UnauthorizedFieldAccess => 8,

            // Medium severity - potential issues
            SchemaViolationType::UnknownMethod => 5,
            SchemaViolationType::InvalidParameterType => 5,
            SchemaViolationType::UnknownField => 6,
            SchemaViolationType::InvalidArgument => 5,
            SchemaViolationType::UnknownType => 5,

            // Lower severity - informational
            SchemaViolationType::MissingRequiredParameter => 4,
            SchemaViolationType::InvalidParameterFormat => 4,
            SchemaViolationType::InvalidContentType => 3,
            SchemaViolationType::UnknownResponseStatus => 2,
            SchemaViolationType::InvalidResponseBody => 3,
            SchemaViolationType::MissingRequiredArgument => 4,
            SchemaViolationType::InvalidArgumentType => 4,
            SchemaViolationType::DeprecatedFieldUsage => 2,
        }
    }

    /// Get attack type for this violation
    pub fn attack_type(&self) -> AttackType {
        match self {
            SchemaViolationType::UnauthorizedFieldAccess => AttackType::ProtocolAttack,
            SchemaViolationType::InvalidRequestBody => AttackType::ProtocolAttack,
            SchemaViolationType::UnknownPath => AttackType::ProtocolAttack,
            _ => AttackType::ProtocolAttack,
        }
    }

    /// Get string key for enforcement config overrides
    pub fn config_key(&self) -> &'static str {
        match self {
            SchemaViolationType::UnknownPath => "unknown-path",
            SchemaViolationType::UnknownMethod => "unknown-method",
            SchemaViolationType::MissingRequiredParameter => "missing-required-parameter",
            SchemaViolationType::InvalidParameterType => "invalid-parameter-type",
            SchemaViolationType::InvalidParameterFormat => "invalid-parameter-format",
            SchemaViolationType::InvalidRequestBody => "invalid-request-body",
            SchemaViolationType::InvalidContentType => "invalid-content-type",
            SchemaViolationType::UnknownResponseStatus => "unknown-response-status",
            SchemaViolationType::InvalidResponseBody => "invalid-response-body",
            SchemaViolationType::UnknownType => "unknown-type",
            SchemaViolationType::UnknownField => "unknown-field",
            SchemaViolationType::InvalidArgument => "invalid-argument",
            SchemaViolationType::MissingRequiredArgument => "missing-required-argument",
            SchemaViolationType::InvalidArgumentType => "invalid-argument-type",
            SchemaViolationType::UnauthorizedFieldAccess => "unauthorized-field-access",
            SchemaViolationType::DeprecatedFieldUsage => "deprecated-field-usage",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id_ranges() {
        // OpenAPI violations should be in 98300-98349
        assert!(SchemaViolationType::UnknownPath.rule_id() >= 98300);
        assert!(SchemaViolationType::InvalidResponseBody.rule_id() <= 98349);

        // GraphQL violations should be in 98350-98399
        assert!(SchemaViolationType::UnknownType.rule_id() >= 98350);
        assert!(SchemaViolationType::DeprecatedFieldUsage.rule_id() <= 98399);
    }

    #[test]
    fn test_violation_to_detection() {
        let violation = SchemaViolation {
            violation_type: SchemaViolationType::UnknownPath,
            location: "path".to_string(),
            expected: "/users/{id}".to_string(),
            actual: "/unknown/path".to_string(),
            schema_path: "paths".to_string(),
            message: "Path not found in schema".to_string(),
        };

        let detection = violation.into_detection();
        assert_eq!(detection.rule_id, 98300);
        assert_eq!(detection.base_score, 6);
    }
}
