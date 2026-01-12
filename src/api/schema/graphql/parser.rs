//! GraphQL Schema Parser
//!
//! Parses GraphQL SDL schemas.

use super::compiled::{
    CompiledArgument, CompiledField, CompiledGraphQLSchema, CompiledType, TypeKind, TypeRef,
};
use crate::api::schema::{SchemaMetadata, SchemaSource, SchemaType};
use anyhow::{Context, Result};
use graphql_parser::schema::{self as gql, Definition, TypeDefinition};
use std::collections::HashMap;
use std::fs;

/// Parse GraphQL schema from source
pub fn parse_from_source(source: &SchemaSource) -> Result<CompiledGraphQLSchema> {
    let content = load_content(source)?;
    parse_content(&content, source.clone())
}

/// Load content from source
fn load_content(source: &SchemaSource) -> Result<String> {
    match source {
        SchemaSource::File(path) => {
            fs::read_to_string(path).with_context(|| format!("Failed to read file: {:?}", path))
        }
        SchemaSource::Url(_url) => {
            anyhow::bail!("URL loading not yet implemented - use file source")
        }
        SchemaSource::Inline(content) => Ok(content.clone()),
    }
}

/// Parse GraphQL SDL content
fn parse_content(content: &str, source: SchemaSource) -> Result<CompiledGraphQLSchema> {
    let document = gql::parse_schema::<String>(content)
        .map_err(|e| anyhow::anyhow!("Failed to parse GraphQL schema: {}", e))?;

    compile_schema(document, source)
}

/// Compile GraphQL schema into efficient lookup structure
fn compile_schema(
    document: gql::Document<'_, String>,
    source: SchemaSource,
) -> Result<CompiledGraphQLSchema> {
    let mut types = HashMap::new();
    let mut query_type = "Query".to_string();
    let mut mutation_type = None;
    let mut subscription_type = None;
    let directives = HashMap::new();

    // Add built-in scalar types
    for scalar in ["String", "Int", "Float", "Boolean", "ID"] {
        types.insert(
            scalar.to_string(),
            CompiledType {
                name: scalar.to_string(),
                kind: TypeKind::Scalar,
                fields: HashMap::new(),
                interfaces: Vec::new(),
                possible_types: Vec::new(),
                enum_values: Vec::new(),
                input_fields: HashMap::new(),
                is_deprecated: false,
            },
        );
    }

    // Process definitions
    for def in document.definitions {
        match def {
            Definition::SchemaDefinition(schema_def) => {
                if let Some(q) = schema_def.query {
                    query_type = q.to_string();
                }
                if let Some(m) = schema_def.mutation {
                    mutation_type = Some(m.to_string());
                }
                if let Some(s) = schema_def.subscription {
                    subscription_type = Some(s.to_string());
                }
            }
            Definition::TypeDefinition(type_def) => {
                let compiled = compile_type_definition(&type_def)?;
                types.insert(compiled.name.clone(), compiled);
            }
            Definition::TypeExtension(_) => {
                // Type extensions - handle later
            }
            Definition::DirectiveDefinition(_) => {
                // Directive definitions - handle later
            }
        }
    }

    let metadata = SchemaMetadata::new(SchemaType::GraphQL, source);

    Ok(CompiledGraphQLSchema {
        types,
        query_type,
        mutation_type,
        subscription_type,
        directives,
        metadata,
    })
}

/// Compile a type definition
fn compile_type_definition(type_def: &TypeDefinition<'_, String>) -> Result<CompiledType> {
    match type_def {
        TypeDefinition::Scalar(scalar) => Ok(CompiledType {
            name: scalar.name.to_string(),
            kind: TypeKind::Scalar,
            fields: HashMap::new(),
            interfaces: Vec::new(),
            possible_types: Vec::new(),
            enum_values: Vec::new(),
            input_fields: HashMap::new(),
            is_deprecated: false,
        }),

        TypeDefinition::Object(obj) => {
            let mut fields = HashMap::new();
            for field in &obj.fields {
                let compiled_field = compile_field(field)?;
                fields.insert(compiled_field.name.clone(), compiled_field);
            }

            Ok(CompiledType {
                name: obj.name.to_string(),
                kind: TypeKind::Object,
                fields,
                interfaces: obj
                    .implements_interfaces
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                possible_types: Vec::new(),
                enum_values: Vec::new(),
                input_fields: HashMap::new(),
                is_deprecated: has_deprecated_directive(&obj.directives),
            })
        }

        TypeDefinition::Interface(iface) => {
            let mut fields = HashMap::new();
            for field in &iface.fields {
                let compiled_field = compile_field(field)?;
                fields.insert(compiled_field.name.clone(), compiled_field);
            }

            Ok(CompiledType {
                name: iface.name.to_string(),
                kind: TypeKind::Interface,
                fields,
                interfaces: Vec::new(),
                possible_types: Vec::new(),
                enum_values: Vec::new(),
                input_fields: HashMap::new(),
                is_deprecated: has_deprecated_directive(&iface.directives),
            })
        }

        TypeDefinition::Union(union) => Ok(CompiledType {
            name: union.name.to_string(),
            kind: TypeKind::Union,
            fields: HashMap::new(),
            interfaces: Vec::new(),
            possible_types: union.types.iter().map(|s| s.to_string()).collect(),
            enum_values: Vec::new(),
            input_fields: HashMap::new(),
            is_deprecated: has_deprecated_directive(&union.directives),
        }),

        TypeDefinition::Enum(enum_def) => Ok(CompiledType {
            name: enum_def.name.to_string(),
            kind: TypeKind::Enum,
            fields: HashMap::new(),
            interfaces: Vec::new(),
            possible_types: Vec::new(),
            enum_values: enum_def.values.iter().map(|v| v.name.to_string()).collect(),
            input_fields: HashMap::new(),
            is_deprecated: has_deprecated_directive(&enum_def.directives),
        }),

        TypeDefinition::InputObject(input) => {
            let mut input_fields = HashMap::new();
            for field in &input.fields {
                let type_ref = compile_type_ref(&field.value_type);
                let required = matches!(&field.value_type, gql::Type::NonNullType(_))
                    && field.default_value.is_none();

                input_fields.insert(
                    field.name.to_string(),
                    super::compiled::CompiledInputField {
                        name: field.name.to_string(),
                        type_ref,
                        required,
                        default_value: field.default_value.as_ref().map(|v| format!("{:?}", v)),
                    },
                );
            }

            Ok(CompiledType {
                name: input.name.to_string(),
                kind: TypeKind::InputObject,
                fields: HashMap::new(),
                interfaces: Vec::new(),
                possible_types: Vec::new(),
                enum_values: Vec::new(),
                input_fields,
                is_deprecated: has_deprecated_directive(&input.directives),
            })
        }
    }
}

/// Compile a field definition
fn compile_field(field: &gql::Field<'_, String>) -> Result<CompiledField> {
    let type_ref = compile_type_ref(&field.field_type);

    let mut arguments = HashMap::new();
    for arg in &field.arguments {
        let arg_type = compile_type_ref(&arg.value_type);
        let required =
            matches!(&arg.value_type, gql::Type::NonNullType(_)) && arg.default_value.is_none();

        arguments.insert(
            arg.name.to_string(),
            CompiledArgument {
                name: arg.name.to_string(),
                type_ref: arg_type,
                required,
                default_value: arg.default_value.as_ref().map(|v| format!("{:?}", v)),
            },
        );
    }

    let is_deprecated = has_deprecated_directive(&field.directives);
    let deprecation_reason = get_deprecation_reason(&field.directives);

    Ok(CompiledField {
        name: field.name.to_string(),
        type_ref,
        arguments,
        is_deprecated,
        deprecation_reason,
    })
}

/// Compile a type reference
fn compile_type_ref(type_: &gql::Type<'_, String>) -> TypeRef {
    match type_ {
        gql::Type::NamedType(name) => TypeRef::nullable(name.as_str()),
        gql::Type::NonNullType(inner) => {
            let mut type_ref = compile_type_ref(inner);
            type_ref.non_null = true;
            type_ref
        }
        gql::Type::ListType(inner) => {
            let inner_ref = compile_type_ref(inner);
            TypeRef {
                name: inner_ref.name,
                non_null: false,
                is_list: true,
                list_item_non_null: inner_ref.non_null,
            }
        }
    }
}

/// Check if directives include @deprecated
fn has_deprecated_directive(directives: &[gql::Directive<'_, String>]) -> bool {
    directives.iter().any(|d| d.name == "deprecated")
}

/// Get deprecation reason from @deprecated directive
fn get_deprecation_reason(directives: &[gql::Directive<'_, String>]) -> Option<String> {
    directives
        .iter()
        .find(|d| d.name == "deprecated")
        .and_then(|d| {
            d.arguments
                .iter()
                .find(|(name, _)| *name == "reason")
                .map(|(_, value)| match value {
                    gql::Value::String(s) => s.clone(),
                    _ => format!("{:?}", value),
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_SCHEMA: &str = r#"
type Query {
    user(id: ID!): User
    users(limit: Int = 10): [User!]!
}

type User {
    id: ID!
    name: String!
    email: String
    posts: [Post!]
}

type Post {
    id: ID!
    title: String!
    content: String
    author: User!
}

input CreateUserInput {
    name: String!
    email: String!
}

enum Role {
    ADMIN
    USER
    GUEST
}
"#;

    #[test]
    fn test_parse_simple_schema() {
        let source = SchemaSource::Inline(SIMPLE_SCHEMA.to_string());
        let schema = parse_from_source(&source).expect("Failed to parse schema");

        assert!(schema.type_exists("Query"));
        assert!(schema.type_exists("User"));
        assert!(schema.type_exists("Post"));
        assert!(schema.type_exists("CreateUserInput"));
        assert!(schema.type_exists("Role"));
    }

    #[test]
    fn test_query_fields() {
        let source = SchemaSource::Inline(SIMPLE_SCHEMA.to_string());
        let schema = parse_from_source(&source).unwrap();

        let query = schema.query_root().unwrap();
        assert!(query.field_exists("user"));
        assert!(query.field_exists("users"));

        let user_field = query.get_field("user").unwrap();
        assert!(user_field.get_argument("id").is_some());
    }

    #[test]
    fn test_type_fields() {
        let source = SchemaSource::Inline(SIMPLE_SCHEMA.to_string());
        let schema = parse_from_source(&source).unwrap();

        let user = schema.get_type("User").unwrap();
        assert!(user.field_exists("id"));
        assert!(user.field_exists("name"));
        assert!(user.field_exists("email"));
        assert!(user.field_exists("posts"));
    }

    #[test]
    fn test_enum_values() {
        let source = SchemaSource::Inline(SIMPLE_SCHEMA.to_string());
        let schema = parse_from_source(&source).unwrap();

        let role = schema.get_type("Role").unwrap();
        assert_eq!(role.kind, TypeKind::Enum);
        assert!(role.enum_values.contains(&"ADMIN".to_string()));
        assert!(role.enum_values.contains(&"USER".to_string()));
    }
}
