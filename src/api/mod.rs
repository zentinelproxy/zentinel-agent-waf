//! API Security Module
//!
//! Provides protection for modern API architectures including:
//! - GraphQL introspection blocking and query complexity limits
//! - JSON injection detection
//! - API-specific attack patterns (BOLA, mass assignment)
//! - JWT validation
//! - Schema validation (OpenAPI, GraphQL SDL)
//!
//! # Rule ID Ranges
//!
//! - 98000-98099: GraphQL security rules
//! - 98100-98199: JSON/REST API rules
//! - 98200-98299: JWT/Auth rules
//! - 98300-98349: OpenAPI schema violations
//! - 98350-98399: GraphQL schema violations

pub mod graphql;
pub mod json;
pub mod jwt;

#[cfg(feature = "schema-validation")]
pub mod schema;

pub use graphql::{GraphQLInspector, GraphQLConfig, GraphQLViolation};
pub use json::{JsonInspector, JsonViolation};
pub use jwt::{JwtInspector, JwtConfig, JwtViolation};

use crate::detection::Detection;

/// API security configuration
#[derive(Debug, Clone)]
pub struct ApiSecurityConfig {
    /// Enable GraphQL protection
    pub graphql_enabled: bool,
    /// GraphQL configuration
    pub graphql: GraphQLConfig,
    /// Enable JSON injection detection
    pub json_enabled: bool,
    /// Enable JWT validation
    pub jwt_enabled: bool,
    /// JWT configuration
    pub jwt: JwtConfig,
}

impl Default for ApiSecurityConfig {
    fn default() -> Self {
        Self {
            graphql_enabled: false,
            graphql: GraphQLConfig::default(),
            json_enabled: true,
            jwt_enabled: false,
            jwt: JwtConfig::default(),
        }
    }
}

/// Combined API security inspector
pub struct ApiSecurityInspector {
    graphql: GraphQLInspector,
    json: JsonInspector,
    jwt: JwtInspector,
    config: ApiSecurityConfig,
}

impl ApiSecurityInspector {
    /// Create a new API security inspector
    pub fn new(config: ApiSecurityConfig) -> Self {
        Self {
            graphql: GraphQLInspector::new(config.graphql.clone()),
            json: JsonInspector::new(),
            jwt: JwtInspector::new(config.jwt.clone()),
            config,
        }
    }

    /// Inspect a request for API security issues
    pub fn inspect(
        &self,
        path: &str,
        content_type: Option<&str>,
        body: Option<&str>,
        auth_header: Option<&str>,
    ) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check for GraphQL
        if self.config.graphql_enabled {
            if is_graphql_request(path, content_type) {
                if let Some(body) = body {
                    detections.extend(self.graphql.inspect(body));
                }
            }
        }

        // Check JSON body
        if self.config.json_enabled {
            if let Some(body) = body {
                if is_json_content(content_type) {
                    detections.extend(self.json.inspect(body));
                }
            }
        }

        // Check JWT
        if self.config.jwt_enabled {
            if let Some(auth) = auth_header {
                detections.extend(self.jwt.inspect(auth));
            }
        }

        detections
    }
}

/// Check if request is likely a GraphQL request
fn is_graphql_request(path: &str, content_type: Option<&str>) -> bool {
    // Common GraphQL endpoints
    if path.ends_with("/graphql") || path.ends_with("/gql") {
        return true;
    }

    // GraphQL content type
    if let Some(ct) = content_type {
        if ct.contains("application/graphql") {
            return true;
        }
    }

    false
}

/// Check if content type is JSON
fn is_json_content(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| ct.contains("application/json") || ct.contains("+json"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_detection() {
        assert!(is_graphql_request("/api/graphql", None));
        assert!(is_graphql_request("/gql", None));
        assert!(is_graphql_request("/v1/graphql", None));
        assert!(!is_graphql_request("/api/users", None));
    }

    #[test]
    fn test_json_content_detection() {
        assert!(is_json_content(Some("application/json")));
        assert!(is_json_content(Some("application/json; charset=utf-8")));
        assert!(is_json_content(Some("application/vnd.api+json")));
        assert!(!is_json_content(Some("text/html")));
        assert!(!is_json_content(None));
    }
}
