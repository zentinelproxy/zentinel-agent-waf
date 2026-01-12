//! GraphQL Query Validator
//!
//! Validates GraphQL queries against schemas.

use super::compiled::{CompiledGraphQLSchema, CompiledType};
use super::parser;
use crate::api::schema::{RequestContext, SchemaSource, SchemaViolation, SchemaViolationType};
use anyhow::Result;
use graphql_parser::query::{self as gql, Definition, OperationDefinition, Selection};

/// GraphQL schema validator
pub struct GraphQLSchemaValidator {
    /// Compiled schema
    schema: CompiledGraphQLSchema,
}

impl GraphQLSchemaValidator {
    /// Create validator from schema source
    pub fn from_source(source: SchemaSource) -> Result<Self> {
        let schema = parser::parse_from_source(&source)?;
        Ok(Self { schema })
    }

    /// Create validator from compiled schema
    pub fn new(schema: CompiledGraphQLSchema) -> Self {
        Self { schema }
    }

    /// Validate a request containing a GraphQL query
    pub fn validate_request(&self, ctx: &RequestContext) -> Vec<SchemaViolation> {
        let Some(body) = ctx.body else {
            return Vec::new();
        };

        // Try to extract query from JSON body
        let query = if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            json.get("query")
                .and_then(|q| q.as_str())
                .map(|s| s.to_string())
        } else {
            // Assume body is the query itself
            Some(body.to_string())
        };

        let Some(query) = query else {
            return Vec::new();
        };

        self.validate_query(&query)
    }

    /// Validate a GraphQL query string
    pub fn validate_query(&self, query: &str) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        // Parse the query
        let document = match gql::parse_query::<String>(query) {
            Ok(doc) => doc,
            Err(e) => {
                violations.push(SchemaViolation {
                    violation_type: SchemaViolationType::InvalidArgument,
                    location: "query".to_string(),
                    expected: "valid GraphQL query".to_string(),
                    actual: format!("parse error: {}", e),
                    schema_path: "".to_string(),
                    message: format!("Invalid GraphQL query syntax: {}", e),
                });
                return violations;
            }
        };

        // Validate each operation
        for def in &document.definitions {
            match def {
                Definition::Operation(op) => {
                    violations.extend(self.validate_operation(op));
                }
                Definition::Fragment(frag) => {
                    // Validate fragment type condition
                    let type_name = frag.type_condition.to_string();
                    if !self.schema.type_exists(&type_name) {
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::UnknownType,
                            location: format!("fragment.{}", frag.name),
                            expected: "existing type".to_string(),
                            actual: type_name.clone(),
                            schema_path: format!("fragment {}", frag.name),
                            message: format!(
                                "Fragment '{}' is on unknown type '{}'",
                                frag.name, type_name
                            ),
                        });
                    } else if let Some(type_) = self.schema.get_type(&type_name) {
                        violations.extend(self.validate_selection_set(
                            &frag.selection_set.items,
                            type_,
                            &format!("fragment {}", frag.name),
                        ));
                    }
                }
            }
        }

        violations
    }

    /// Validate an operation
    fn validate_operation(&self, op: &OperationDefinition<'_, String>) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        let (root_type, op_name) = match op {
            OperationDefinition::Query(q) => (
                self.schema.query_root(),
                q.name.as_deref().unwrap_or("query"),
            ),
            OperationDefinition::Mutation(m) => {
                let root = self.schema.mutation_root();
                if root.is_none() {
                    violations.push(SchemaViolation {
                        violation_type: SchemaViolationType::UnknownType,
                        location: "operation".to_string(),
                        expected: "Mutation type defined".to_string(),
                        actual: "no mutation type".to_string(),
                        schema_path: "schema.mutation".to_string(),
                        message: "Mutation operation used but no Mutation type is defined"
                            .to_string(),
                    });
                    return violations;
                }
                (root, m.name.as_deref().unwrap_or("mutation"))
            }
            OperationDefinition::Subscription(s) => {
                let root = self.schema.subscription_root();
                if root.is_none() {
                    violations.push(SchemaViolation {
                        violation_type: SchemaViolationType::UnknownType,
                        location: "operation".to_string(),
                        expected: "Subscription type defined".to_string(),
                        actual: "no subscription type".to_string(),
                        schema_path: "schema.subscription".to_string(),
                        message: "Subscription operation used but no Subscription type is defined"
                            .to_string(),
                    });
                    return violations;
                }
                (root, s.name.as_deref().unwrap_or("subscription"))
            }
            OperationDefinition::SelectionSet(ss) => {
                // Anonymous query
                (self.schema.query_root(), "query")
            }
        };

        let Some(root_type) = root_type else {
            violations.push(SchemaViolation {
                violation_type: SchemaViolationType::UnknownType,
                location: "operation".to_string(),
                expected: "Query type defined".to_string(),
                actual: "no query type".to_string(),
                schema_path: "schema.query".to_string(),
                message: "Query type is not defined in schema".to_string(),
            });
            return violations;
        };

        // Get selection set
        let selection_set = match op {
            OperationDefinition::Query(q) => &q.selection_set.items,
            OperationDefinition::Mutation(m) => &m.selection_set.items,
            OperationDefinition::Subscription(s) => &s.selection_set.items,
            OperationDefinition::SelectionSet(ss) => &ss.items,
        };

        violations.extend(self.validate_selection_set(selection_set, root_type, op_name));

        violations
    }

    /// Validate a selection set against a type
    fn validate_selection_set(
        &self,
        selections: &[Selection<'_, String>],
        parent_type: &CompiledType,
        path: &str,
    ) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        for selection in selections {
            match selection {
                Selection::Field(field) => {
                    let field_name = &field.name;

                    // Skip introspection fields
                    if field_name.starts_with("__") {
                        continue;
                    }

                    // Check if field exists
                    let Some(schema_field) = parent_type.get_field(field_name) else {
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::UnknownField,
                            location: format!("{}.{}", path, field_name),
                            expected: format!("field on {}", parent_type.name),
                            actual: field_name.clone(),
                            schema_path: format!("{}.{}", parent_type.name, field_name),
                            message: format!(
                                "Field '{}' does not exist on type '{}'",
                                field_name, parent_type.name
                            ),
                        });
                        continue;
                    };

                    // Check for deprecated usage
                    if schema_field.is_deprecated {
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::DeprecatedFieldUsage,
                            location: format!("{}.{}", path, field_name),
                            expected: "non-deprecated field".to_string(),
                            actual: field_name.clone(),
                            schema_path: format!("{}.{}", parent_type.name, field_name),
                            message: format!(
                                "Field '{}' on type '{}' is deprecated{}",
                                field_name,
                                parent_type.name,
                                schema_field
                                    .deprecation_reason
                                    .as_ref()
                                    .map(|r| format!(": {}", r))
                                    .unwrap_or_default()
                            ),
                        });
                    }

                    // Validate arguments
                    violations.extend(self.validate_arguments(
                        &field.arguments,
                        schema_field,
                        &format!("{}.{}", path, field_name),
                    ));

                    // Recursively validate nested selections
                    if !field.selection_set.items.is_empty() {
                        if let Some(field_type) = self.schema.get_type(&schema_field.type_ref.name)
                        {
                            violations.extend(self.validate_selection_set(
                                &field.selection_set.items,
                                field_type,
                                &format!("{}.{}", path, field_name),
                            ));
                        }
                    }
                }
                Selection::FragmentSpread(_) => {
                    // Fragment spreads are validated when processing fragments
                }
                Selection::InlineFragment(inline) => {
                    let type_name = inline
                        .type_condition
                        .as_ref()
                        .map(|tc| tc.to_string())
                        .unwrap_or_else(|| parent_type.name.clone());

                    if let Some(type_) = self.schema.get_type(&type_name) {
                        violations.extend(self.validate_selection_set(
                            &inline.selection_set.items,
                            type_,
                            path,
                        ));
                    } else {
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::UnknownType,
                            location: path.to_string(),
                            expected: "existing type".to_string(),
                            actual: type_name.clone(),
                            schema_path: path.to_string(),
                            message: format!("Inline fragment on unknown type '{}'", type_name),
                        });
                    }
                }
            }
        }

        violations
    }

    /// Validate field arguments
    fn validate_arguments(
        &self,
        provided: &[(String, gql::Value<'_, String>)],
        field: &super::compiled::CompiledField,
        path: &str,
    ) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();

        // Check for unknown arguments
        for (name, _value) in provided {
            if field.get_argument(name).is_none() {
                violations.push(SchemaViolation {
                    violation_type: SchemaViolationType::InvalidArgument,
                    location: format!("{}.{}", path, name),
                    expected: format!("valid argument for {}", field.name),
                    actual: name.clone(),
                    schema_path: format!("{}.arguments.{}", path, name),
                    message: format!("Unknown argument '{}' on field '{}'", name, field.name),
                });
            }
        }

        // Check for missing required arguments
        for (name, arg) in &field.arguments {
            if arg.required {
                let is_provided = provided.iter().any(|(n, _)| n == name);
                if !is_provided {
                    violations.push(SchemaViolation {
                        violation_type: SchemaViolationType::MissingRequiredArgument,
                        location: format!("{}.{}", path, name),
                        expected: format!("argument '{}' required", name),
                        actual: "missing".to_string(),
                        schema_path: format!("{}.arguments.{}", path, name),
                        message: format!(
                            "Required argument '{}' is missing on field '{}'",
                            name, field.name
                        ),
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
    use std::collections::HashMap;

    fn create_test_validator() -> GraphQLSchemaValidator {
        let schema = r#"
type Query {
    user(id: ID!): User
    users: [User!]!
}

type User {
    id: ID!
    name: String!
    email: String
    posts: [Post!]
    oldField: String @deprecated(reason: "Use newField instead")
}

type Post {
    id: ID!
    title: String!
}
"#;
        let source = SchemaSource::Inline(schema.to_string());
        GraphQLSchemaValidator::from_source(source).unwrap()
    }

    #[test]
    fn test_valid_query() {
        let validator = create_test_validator();
        let query = r#"{ user(id: "1") { id name } }"#;
        let violations = validator.validate_query(query);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_unknown_field() {
        let validator = create_test_validator();
        let query = r#"{ user(id: "1") { id unknownField } }"#;
        let violations = validator.validate_query(query);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].violation_type,
            SchemaViolationType::UnknownField
        );
    }

    #[test]
    fn test_missing_required_argument() {
        let validator = create_test_validator();
        let query = r#"{ user { id } }"#; // Missing required 'id' argument
        let violations = validator.validate_query(query);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].violation_type,
            SchemaViolationType::MissingRequiredArgument
        );
    }

    #[test]
    fn test_deprecated_field() {
        let validator = create_test_validator();
        let query = r#"{ user(id: "1") { id oldField } }"#;
        let violations = validator.validate_query(query);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].violation_type,
            SchemaViolationType::DeprecatedFieldUsage
        );
    }

    #[test]
    fn test_nested_selection() {
        let validator = create_test_validator();
        let query = r#"{ user(id: "1") { posts { id title } } }"#;
        let violations = validator.validate_query(query);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_unknown_nested_field() {
        let validator = create_test_validator();
        let query = r#"{ user(id: "1") { posts { id unknownField } } }"#;
        let violations = validator.validate_query(query);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].violation_type,
            SchemaViolationType::UnknownField
        );
    }

    #[test]
    fn test_from_request_context() {
        let validator = create_test_validator();
        let body = r#"{"query": "{ users { id name } }"}"#;
        let headers = HashMap::new();
        let query_params = HashMap::new();

        let ctx = RequestContext {
            method: "POST",
            path: "/graphql",
            query_params: &query_params,
            headers: &headers,
            content_type: Some("application/json"),
            body: Some(body),
        };

        let violations = validator.validate_request(&ctx);
        assert!(violations.is_empty());
    }
}
