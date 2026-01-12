//! Schema Validation Module
//!
//! Provides OpenAPI and GraphQL schema validation for API security.
//!
//! # Features
//!
//! - OpenAPI 3.0/3.1 specification validation
//! - GraphQL SDL schema validation
//! - Request/response validation against schemas
//! - Configurable enforcement (warn vs block)
//!
//! # Usage
//!
//! Enable with the `schema-validation` feature flag:
//!
//! ```toml
//! [dependencies]
//! sentinel-agent-waf = { version = "0.1", features = ["schema-validation"] }
//! ```

pub mod loader;
pub mod source;
pub mod violation;

#[cfg(feature = "schema-validation")]
pub mod openapi;

#[cfg(feature = "schema-validation")]
pub mod graphql;

pub use loader::SchemaLoader;
pub use source::{SchemaMetadata, SchemaSource, SchemaType};
pub use violation::{SchemaViolation, SchemaViolationType};

use crate::detection::Detection;
use std::collections::HashMap;

/// Request context for schema validation
#[derive(Debug)]
pub struct RequestContext<'a> {
    /// HTTP method (GET, POST, etc.)
    pub method: &'a str,
    /// Request path (without query string)
    pub path: &'a str,
    /// Query parameters
    pub query_params: &'a HashMap<String, Vec<String>>,
    /// Request headers
    pub headers: &'a HashMap<String, Vec<String>>,
    /// Content-Type header value
    pub content_type: Option<&'a str>,
    /// Request body (if available)
    pub body: Option<&'a str>,
}

/// Response context for schema validation
#[derive(Debug)]
pub struct ResponseContext<'a> {
    /// HTTP status code
    pub status_code: u16,
    /// Response headers
    pub headers: &'a HashMap<String, Vec<String>>,
    /// Content-Type header value
    pub content_type: Option<&'a str>,
    /// Response body (if available)
    pub body: Option<&'a str>,
}

/// Enforcement mode for schema violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Log violation but allow request (default)
    #[default]
    Warn,
    /// Block request on violation
    Block,
    /// Ignore this violation type entirely
    Ignore,
}

/// Schema validator manager - orchestrates OpenAPI and GraphQL validation
#[derive(Default)]
pub struct SchemaValidatorManager {
    /// OpenAPI validator (if configured)
    #[cfg(feature = "schema-validation")]
    openapi: Option<openapi::OpenApiValidator>,

    /// GraphQL validator (if configured)
    #[cfg(feature = "schema-validation")]
    graphql: Option<graphql::GraphQLSchemaValidator>,

    /// Enforcement configuration
    enforcement: EnforcementConfig,
}

/// Enforcement configuration
#[derive(Debug, Clone, Default)]
pub struct EnforcementConfig {
    /// Default enforcement mode for all violations
    pub default_mode: EnforcementMode,
    /// Per-violation-type overrides (key is SchemaViolationType::config_key())
    pub overrides: HashMap<String, EnforcementMode>,
}

impl EnforcementConfig {
    /// Get enforcement mode for a violation type
    pub fn get_mode(&self, violation_type: SchemaViolationType) -> EnforcementMode {
        self.overrides
            .get(violation_type.config_key())
            .copied()
            .unwrap_or(self.default_mode)
    }

    /// Check if a violation should be blocked
    pub fn should_block(&self, violation_type: SchemaViolationType) -> bool {
        self.get_mode(violation_type) == EnforcementMode::Block
    }

    /// Check if a violation should be ignored
    pub fn should_ignore(&self, violation_type: SchemaViolationType) -> bool {
        self.get_mode(violation_type) == EnforcementMode::Ignore
    }
}

impl SchemaValidatorManager {
    /// Create a new schema validator manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Set enforcement configuration
    pub fn with_enforcement(mut self, config: EnforcementConfig) -> Self {
        self.enforcement = config;
        self
    }

    /// Load OpenAPI schema from source
    #[cfg(feature = "schema-validation")]
    pub fn load_openapi(&mut self, source: SchemaSource) -> anyhow::Result<()> {
        let validator = openapi::OpenApiValidator::from_source(source)?;
        self.openapi = Some(validator);
        Ok(())
    }

    /// Load GraphQL schema from source
    #[cfg(feature = "schema-validation")]
    pub fn load_graphql(&mut self, source: SchemaSource) -> anyhow::Result<()> {
        let validator = graphql::GraphQLSchemaValidator::from_source(source)?;
        self.graphql = Some(validator);
        Ok(())
    }

    /// Check if any schema is loaded
    pub fn is_ready(&self) -> bool {
        #[cfg(feature = "schema-validation")]
        {
            self.openapi.is_some() || self.graphql.is_some()
        }
        #[cfg(not(feature = "schema-validation"))]
        {
            false
        }
    }

    /// Validate a request against loaded schemas
    pub fn validate_request(&self, ctx: &RequestContext) -> Vec<Detection> {
        let mut detections = Vec::new();

        #[cfg(feature = "schema-validation")]
        {
            // OpenAPI validation for REST endpoints
            if let Some(ref openapi) = self.openapi {
                for violation in openapi.validate_request(ctx) {
                    if !self.enforcement.should_ignore(violation.violation_type) {
                        detections.push(violation.into_detection());
                    }
                }
            }

            // GraphQL validation for GraphQL endpoints
            if let Some(ref graphql) = self.graphql {
                if is_graphql_request(ctx) {
                    for violation in graphql.validate_request(ctx) {
                        if !self.enforcement.should_ignore(violation.violation_type) {
                            detections.push(violation.into_detection());
                        }
                    }
                }
            }
        }

        detections
    }

    /// Validate a response against loaded schemas
    pub fn validate_response(
        &self,
        _request_ctx: &RequestContext,
        _response_ctx: &ResponseContext,
    ) -> Vec<Detection> {
        let detections = Vec::new();

        #[cfg(feature = "schema-validation")]
        {
            // Response validation is optional and more complex
            // Implement in a future iteration
        }

        detections
    }

    /// Get enforcement mode for a violation type
    pub fn get_enforcement(&self, violation_type: SchemaViolationType) -> EnforcementMode {
        self.enforcement.get_mode(violation_type)
    }
}

/// Check if request is a GraphQL request
fn is_graphql_request(ctx: &RequestContext) -> bool {
    // Check path
    let path_lower = ctx.path.to_lowercase();
    if path_lower.contains("/graphql") || path_lower.ends_with("/gql") {
        return true;
    }

    // Check content type
    if let Some(ct) = ctx.content_type {
        if ct.contains("application/graphql") {
            return true;
        }
    }

    // Check for GraphQL-like body
    if let Some(body) = ctx.body {
        if body.contains("\"query\"") || body.contains("\"mutation\"") {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforcement_config() {
        let mut config = EnforcementConfig::default();
        config
            .overrides
            .insert("unknown-path".to_string(), EnforcementMode::Block);

        assert_eq!(
            config.get_mode(SchemaViolationType::UnknownPath),
            EnforcementMode::Block
        );
        assert_eq!(
            config.get_mode(SchemaViolationType::UnknownField),
            EnforcementMode::Warn
        );
    }

    #[test]
    fn test_is_graphql_request() {
        let headers = HashMap::new();
        let query_params = HashMap::new();

        let ctx = RequestContext {
            method: "POST",
            path: "/graphql",
            query_params: &query_params,
            headers: &headers,
            content_type: None,
            body: None,
        };
        assert!(is_graphql_request(&ctx));

        let ctx2 = RequestContext {
            method: "GET",
            path: "/api/users",
            query_params: &query_params,
            headers: &headers,
            content_type: None,
            body: None,
        };
        assert!(!is_graphql_request(&ctx2));
    }
}
