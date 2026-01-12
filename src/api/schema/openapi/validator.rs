//! OpenAPI Request Validator
//!
//! Validates HTTP requests against OpenAPI specifications.

use super::compiled::CompiledOpenApiSchema;
use super::parser;
use crate::api::schema::{RequestContext, SchemaSource, SchemaViolation, SchemaViolationType};
use anyhow::Result;
use std::collections::HashMap;

/// OpenAPI validator
pub struct OpenApiValidator {
    /// Compiled schema
    schema: CompiledOpenApiSchema,
}

impl OpenApiValidator {
    /// Create validator from schema source
    pub fn from_source(source: SchemaSource) -> Result<Self> {
        let schema = parser::parse_from_source(&source)?;
        Ok(Self { schema })
    }

    /// Create validator from compiled schema
    pub fn new(schema: CompiledOpenApiSchema) -> Self {
        Self { schema }
    }

    /// Validate a request against the schema
    pub fn validate_request(&self, ctx: &RequestContext) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        // Check if path exists
        if !self.schema.path_tree.path_exists(ctx.path) {
            violations.push(SchemaViolation {
                violation_type: SchemaViolationType::UnknownPath,
                location: "path".to_string(),
                expected: "defined path".to_string(),
                actual: ctx.path.to_string(),
                schema_path: "paths".to_string(),
                message: format!("Path '{}' is not defined in the OpenAPI schema", ctx.path),
            });
            return violations; // Can't validate further without a valid path
        }

        // Check if method is allowed
        let method = ctx.method.to_uppercase();
        let lookup_result = self.schema.path_tree.lookup(ctx.path, &method);

        if lookup_result.is_none() {
            let allowed = self.schema.path_tree.allowed_methods(ctx.path);
            violations.push(SchemaViolation {
                violation_type: SchemaViolationType::UnknownMethod,
                location: "method".to_string(),
                expected: allowed.join(", "),
                actual: method.clone(),
                schema_path: format!("paths.{}", ctx.path),
                message: format!(
                    "Method '{}' is not allowed for path '{}'. Allowed: {}",
                    method,
                    ctx.path,
                    allowed.join(", ")
                ),
            });
            return violations;
        }

        let (operation, path_params) = lookup_result.unwrap();

        // Validate parameters
        violations.extend(self.validate_parameters(ctx, operation, &path_params));

        // Validate request body if present
        if let Some(body) = ctx.body {
            if !body.is_empty() {
                violations.extend(self.validate_request_body(ctx, operation, body));
            }
        }

        violations
    }

    /// Validate request parameters
    fn validate_parameters(
        &self,
        ctx: &RequestContext,
        operation: &super::compiled::PathOperation,
        path_params: &super::compiled::PathParams,
    ) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        for param in &operation.parameters {
            let value = match param.location.as_str() {
                "query" => ctx
                    .query_params
                    .get(&param.name)
                    .and_then(|v| v.first())
                    .map(|s| s.as_str()),
                "path" => path_params.get(&param.name),
                "header" => ctx
                    .headers
                    .get(&param.name.to_lowercase())
                    .and_then(|v| v.first())
                    .map(|s| s.as_str()),
                _ => None,
            };

            // Check required parameters
            if param.required && value.is_none() {
                violations.push(SchemaViolation {
                    violation_type: SchemaViolationType::MissingRequiredParameter,
                    location: format!("{}.{}", param.location, param.name),
                    expected: "value required".to_string(),
                    actual: "missing".to_string(),
                    schema_path: format!("paths.{}.parameters.{}", ctx.path, param.name),
                    message: format!(
                        "Required {} parameter '{}' is missing",
                        param.location, param.name
                    ),
                });
                continue;
            }

            // Validate parameter type if present
            if let (Some(value), Some(expected_type)) = (value, &param.schema_type) {
                if let Some(violation) = self.validate_param_type(
                    &param.name,
                    &param.location,
                    value,
                    expected_type,
                    ctx.path,
                ) {
                    violations.push(violation);
                }
            }
        }

        violations
    }

    /// Validate parameter type
    fn validate_param_type(
        &self,
        name: &str,
        location: &str,
        value: &str,
        expected_type: &str,
        path: &str,
    ) -> Option<SchemaViolation> {
        let type_valid = match expected_type {
            "integer" => value.parse::<i64>().is_ok(),
            "number" => value.parse::<f64>().is_ok(),
            "boolean" => value == "true" || value == "false",
            "string" => true, // Any value is a valid string
            _ => true,        // Unknown types pass
        };

        if !type_valid {
            Some(SchemaViolation {
                violation_type: SchemaViolationType::InvalidParameterType,
                location: format!("{}.{}", location, name),
                expected: expected_type.to_string(),
                actual: value.to_string(),
                schema_path: format!("paths.{}.parameters.{}", path, name),
                message: format!(
                    "Parameter '{}' expected type '{}', got '{}'",
                    name, expected_type, value
                ),
            })
        } else {
            None
        }
    }

    /// Validate request body against schema
    fn validate_request_body(
        &self,
        ctx: &RequestContext,
        operation: &super::compiled::PathOperation,
        body: &str,
    ) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        // Check content type
        let is_json = ctx
            .content_type
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false);

        if !is_json && operation.request_body_schema.is_some() {
            violations.push(SchemaViolation {
                violation_type: SchemaViolationType::InvalidContentType,
                location: "header.content-type".to_string(),
                expected: "application/json".to_string(),
                actual: ctx.content_type.unwrap_or("none").to_string(),
                schema_path: format!("paths.{}.requestBody", ctx.path),
                message: "Request body requires application/json content type".to_string(),
            });
            return violations;
        }

        // Parse and validate JSON body
        if is_json {
            match serde_json::from_str::<serde_json::Value>(body) {
                Ok(_json_body) => {
                    // TODO: Validate against JSON schema from operation.request_body_schema
                    // This requires jsonschema crate integration
                }
                Err(e) => {
                    violations.push(SchemaViolation {
                        violation_type: SchemaViolationType::InvalidRequestBody,
                        location: "body".to_string(),
                        expected: "valid JSON".to_string(),
                        actual: format!("parse error: {}", e),
                        schema_path: format!("paths.{}.requestBody", ctx.path),
                        message: format!("Invalid JSON in request body: {}", e),
                    });
                }
            }
        }

        violations
    }

    /// Get schema metadata
    pub fn metadata(&self) -> &crate::api::schema::SchemaMetadata {
        &self.schema.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator() -> OpenApiValidator {
        let yaml = r#"
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
paths:
  /users:
    get:
      parameters:
        - name: limit
          in: query
          required: false
          schema:
            type: integer
      responses:
        '200':
          description: OK
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
      responses:
        '201':
          description: Created
  /users/{userId}:
    get:
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: OK
"#;
        let source = SchemaSource::Inline(yaml.to_string());
        OpenApiValidator::from_source(source).unwrap()
    }

    #[test]
    fn test_unknown_path() {
        let validator = create_test_validator();
        let ctx = RequestContext {
            method: "GET",
            path: "/unknown",
            query_params: &HashMap::new(),
            headers: &HashMap::new(),
            content_type: None,
            body: None,
        };

        let violations = validator.validate_request(&ctx);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].violation_type,
            SchemaViolationType::UnknownPath
        );
    }

    #[test]
    fn test_unknown_method() {
        let validator = create_test_validator();
        let ctx = RequestContext {
            method: "DELETE",
            path: "/users",
            query_params: &HashMap::new(),
            headers: &HashMap::new(),
            content_type: None,
            body: None,
        };

        let violations = validator.validate_request(&ctx);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].violation_type,
            SchemaViolationType::UnknownMethod
        );
    }

    #[test]
    fn test_invalid_param_type() {
        let validator = create_test_validator();
        let mut query_params = HashMap::new();
        query_params.insert("limit".to_string(), vec!["not_a_number".to_string()]);

        let ctx = RequestContext {
            method: "GET",
            path: "/users",
            query_params: &query_params,
            headers: &HashMap::new(),
            content_type: None,
            body: None,
        };

        let violations = validator.validate_request(&ctx);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].violation_type,
            SchemaViolationType::InvalidParameterType
        );
    }

    #[test]
    fn test_valid_request() {
        let validator = create_test_validator();
        let mut query_params = HashMap::new();
        query_params.insert("limit".to_string(), vec!["10".to_string()]);

        let ctx = RequestContext {
            method: "GET",
            path: "/users",
            query_params: &query_params,
            headers: &HashMap::new(),
            content_type: None,
            body: None,
        };

        let violations = validator.validate_request(&ctx);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_path_param() {
        let validator = create_test_validator();
        let ctx = RequestContext {
            method: "GET",
            path: "/users/123",
            query_params: &HashMap::new(),
            headers: &HashMap::new(),
            content_type: None,
            body: None,
        };

        let violations = validator.validate_request(&ctx);
        assert!(violations.is_empty());
    }
}
