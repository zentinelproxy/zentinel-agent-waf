//! Compiled OpenAPI Schema
//!
//! Efficient data structures for O(log n) path lookups.

use crate::api::schema::SchemaMetadata;
use std::collections::HashMap;

/// Compiled OpenAPI schema for efficient validation
#[derive(Debug)]
pub struct CompiledOpenApiSchema {
    /// Path tree for O(log n) path matching
    pub path_tree: PathTree,
    /// JSON schemas from components (for body validation)
    pub schemas: HashMap<String, serde_json::Value>,
    /// Schema metadata
    pub metadata: SchemaMetadata,
}

/// Path tree for efficient path template matching
#[derive(Debug, Default)]
pub struct PathTree {
    /// Static path segments
    children: HashMap<String, PathTree>,
    /// Parameter segment (e.g., {petId})
    param_child: Option<Box<(String, PathTree)>>,
    /// Operations at this path level
    operations: HashMap<String, PathOperation>,
}

impl PathTree {
    /// Create new empty path tree
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a path template with its operations
    pub fn insert(&mut self, path_template: &str, operations: HashMap<String, PathOperation>) {
        let segments: Vec<&str> = path_template
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        self.insert_segments(&segments, operations);
    }

    fn insert_segments(&mut self, segments: &[&str], operations: HashMap<String, PathOperation>) {
        if segments.is_empty() {
            self.operations = operations;
            return;
        }

        let segment = segments[0];
        let remaining = &segments[1..];

        if segment.starts_with('{') && segment.ends_with('}') {
            // Parameter segment
            let param_name = segment[1..segment.len() - 1].to_string();
            if self.param_child.is_none() {
                self.param_child = Some(Box::new((param_name, PathTree::new())));
            }
            if let Some(ref mut child) = self.param_child {
                child.1.insert_segments(remaining, operations);
            }
        } else {
            // Static segment
            let child = self
                .children
                .entry(segment.to_string())
                .or_insert_with(PathTree::new);
            child.insert_segments(remaining, operations);
        }
    }

    /// Look up a path and method, returning the operation if found
    pub fn lookup(&self, path: &str, method: &str) -> Option<(&PathOperation, PathParams)> {
        let segments: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut params = PathParams::new();
        self.lookup_segments(&segments, method, &mut params)
            .map(|op| (op, params))
    }

    fn lookup_segments<'a>(
        &'a self,
        segments: &[&str],
        method: &str,
        params: &mut PathParams,
    ) -> Option<&'a PathOperation> {
        if segments.is_empty() {
            return self.operations.get(method);
        }

        let segment = segments[0];
        let remaining = &segments[1..];

        // Try static match first
        if let Some(child) = self.children.get(segment) {
            if let Some(op) = child.lookup_segments(remaining, method, params) {
                return Some(op);
            }
        }

        // Try parameter match
        if let Some(ref child) = self.param_child {
            let old_len = params.values.len();
            params.values.push((child.0.clone(), segment.to_string()));

            if let Some(op) = child.1.lookup_segments(remaining, method, params) {
                return Some(op);
            }

            // Backtrack
            params.values.truncate(old_len);
        }

        None
    }

    /// Check if a path exists (any method)
    pub fn path_exists(&self, path: &str) -> bool {
        let segments: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        self.path_exists_segments(&segments)
    }

    fn path_exists_segments(&self, segments: &[&str]) -> bool {
        if segments.is_empty() {
            return !self.operations.is_empty();
        }

        let segment = segments[0];
        let remaining = &segments[1..];

        // Try static match
        if let Some(child) = self.children.get(segment) {
            if child.path_exists_segments(remaining) {
                return true;
            }
        }

        // Try parameter match
        if let Some(ref child) = self.param_child {
            if child.1.path_exists_segments(remaining) {
                return true;
            }
        }

        false
    }

    /// Get allowed methods for a path
    pub fn allowed_methods(&self, path: &str) -> Vec<String> {
        let segments: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        self.allowed_methods_segments(&segments).unwrap_or_default()
    }

    fn allowed_methods_segments(&self, segments: &[&str]) -> Option<Vec<String>> {
        if segments.is_empty() {
            if self.operations.is_empty() {
                return None;
            }
            return Some(self.operations.keys().cloned().collect());
        }

        let segment = segments[0];
        let remaining = &segments[1..];

        // Try static match first
        if let Some(child) = self.children.get(segment) {
            if let Some(methods) = child.allowed_methods_segments(remaining) {
                return Some(methods);
            }
        }

        // Try parameter match
        if let Some(ref child) = self.param_child {
            if let Some(methods) = child.1.allowed_methods_segments(remaining) {
                return Some(methods);
            }
        }

        None
    }
}

/// Extracted path parameters
#[derive(Debug, Default)]
pub struct PathParams {
    /// Parameter name -> value pairs
    pub values: Vec<(String, String)>,
}

impl PathParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Compiled operation for a path/method combination
#[derive(Debug, Clone)]
pub struct PathOperation {
    /// Operation ID (if specified)
    pub operation_id: Option<String>,
    /// Required and optional parameters
    pub parameters: Vec<CompiledParameter>,
    /// Request body schema reference
    pub request_body_schema: Option<String>,
    /// Valid response status codes
    pub response_codes: Vec<openapiv3::StatusCode>,
}

/// Compiled parameter definition
#[derive(Debug, Clone)]
pub struct CompiledParameter {
    /// Parameter name
    pub name: String,
    /// Location (query, path, header, cookie)
    pub location: String,
    /// Whether the parameter is required
    pub required: bool,
    /// Schema type (string, integer, etc.)
    pub schema_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_tree_static() {
        let mut tree = PathTree::new();
        tree.insert(
            "/users",
            HashMap::from([(
                "GET".to_string(),
                PathOperation {
                    operation_id: Some("listUsers".to_string()),
                    parameters: vec![],
                    request_body_schema: None,
                    response_codes: vec![],
                },
            )]),
        );

        assert!(tree.lookup("/users", "GET").is_some());
        assert!(tree.lookup("/users", "POST").is_none());
        assert!(tree.lookup("/other", "GET").is_none());
    }

    #[test]
    fn test_path_tree_params() {
        let mut tree = PathTree::new();
        tree.insert(
            "/users/{userId}/posts/{postId}",
            HashMap::from([(
                "GET".to_string(),
                PathOperation {
                    operation_id: Some("getPost".to_string()),
                    parameters: vec![],
                    request_body_schema: None,
                    response_codes: vec![],
                },
            )]),
        );

        let (op, params) = tree.lookup("/users/123/posts/456", "GET").unwrap();
        assert_eq!(op.operation_id, Some("getPost".to_string()));
        assert_eq!(params.get("userId"), Some("123"));
        assert_eq!(params.get("postId"), Some("456"));
    }

    #[test]
    fn test_allowed_methods() {
        let mut tree = PathTree::new();
        tree.insert(
            "/pets",
            HashMap::from([
                (
                    "GET".to_string(),
                    PathOperation {
                        operation_id: None,
                        parameters: vec![],
                        request_body_schema: None,
                        response_codes: vec![],
                    },
                ),
                (
                    "POST".to_string(),
                    PathOperation {
                        operation_id: None,
                        parameters: vec![],
                        request_body_schema: None,
                        response_codes: vec![],
                    },
                ),
            ]),
        );

        let methods = tree.allowed_methods("/pets");
        assert!(methods.contains(&"GET".to_string()));
        assert!(methods.contains(&"POST".to_string()));
        assert_eq!(methods.len(), 2);
    }
}
