//! Compiled GraphQL Schema
//!
//! Efficient data structures for O(1) type/field lookups.

use crate::api::schema::SchemaMetadata;
use std::collections::{HashMap, HashSet};

/// Compiled GraphQL schema for efficient validation
#[derive(Debug)]
pub struct CompiledGraphQLSchema {
    /// Types indexed by name
    pub types: HashMap<String, CompiledType>,
    /// Query root type name
    pub query_type: String,
    /// Mutation root type name (if defined)
    pub mutation_type: Option<String>,
    /// Subscription root type name (if defined)
    pub subscription_type: Option<String>,
    /// Directives
    pub directives: HashMap<String, CompiledDirective>,
    /// Schema metadata
    pub metadata: SchemaMetadata,
}

impl CompiledGraphQLSchema {
    /// Get a type by name
    pub fn get_type(&self, name: &str) -> Option<&CompiledType> {
        self.types.get(name)
    }

    /// Check if a type exists
    pub fn type_exists(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    /// Get the query root type
    pub fn query_root(&self) -> Option<&CompiledType> {
        self.types.get(&self.query_type)
    }

    /// Get the mutation root type
    pub fn mutation_root(&self) -> Option<&CompiledType> {
        self.mutation_type
            .as_ref()
            .and_then(|name| self.types.get(name))
    }

    /// Get the subscription root type
    pub fn subscription_root(&self) -> Option<&CompiledType> {
        self.subscription_type
            .as_ref()
            .and_then(|name| self.types.get(name))
    }
}

/// Compiled type definition
#[derive(Debug, Clone)]
pub struct CompiledType {
    /// Type name
    pub name: String,
    /// Type kind
    pub kind: TypeKind,
    /// Fields (for object/interface types)
    pub fields: HashMap<String, CompiledField>,
    /// Implemented interfaces
    pub interfaces: Vec<String>,
    /// Possible types (for interface/union)
    pub possible_types: Vec<String>,
    /// Enum values (for enum types)
    pub enum_values: Vec<String>,
    /// Input fields (for input types)
    pub input_fields: HashMap<String, CompiledInputField>,
    /// Whether this type is deprecated
    pub is_deprecated: bool,
}

impl CompiledType {
    /// Create new object type
    pub fn object(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: TypeKind::Object,
            fields: HashMap::new(),
            interfaces: Vec::new(),
            possible_types: Vec::new(),
            enum_values: Vec::new(),
            input_fields: HashMap::new(),
            is_deprecated: false,
        }
    }

    /// Get a field by name
    pub fn get_field(&self, name: &str) -> Option<&CompiledField> {
        self.fields.get(name)
    }

    /// Check if a field exists
    pub fn field_exists(&self, name: &str) -> bool {
        self.fields.contains_key(name)
    }

    /// Add a field
    pub fn with_field(mut self, field: CompiledField) -> Self {
        self.fields.insert(field.name.clone(), field);
        self
    }
}

/// Type kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    Scalar,
    Object,
    Interface,
    Union,
    Enum,
    InputObject,
}

/// Compiled field definition
#[derive(Debug, Clone)]
pub struct CompiledField {
    /// Field name
    pub name: String,
    /// Return type reference
    pub type_ref: TypeRef,
    /// Field arguments
    pub arguments: HashMap<String, CompiledArgument>,
    /// Whether the field is deprecated
    pub is_deprecated: bool,
    /// Deprecation reason
    pub deprecation_reason: Option<String>,
}

impl CompiledField {
    /// Create new field
    pub fn new(name: impl Into<String>, type_ref: TypeRef) -> Self {
        Self {
            name: name.into(),
            type_ref,
            arguments: HashMap::new(),
            is_deprecated: false,
            deprecation_reason: None,
        }
    }

    /// Add an argument
    pub fn with_argument(mut self, arg: CompiledArgument) -> Self {
        self.arguments.insert(arg.name.clone(), arg);
        self
    }

    /// Get an argument by name
    pub fn get_argument(&self, name: &str) -> Option<&CompiledArgument> {
        self.arguments.get(name)
    }
}

/// Type reference (with nullability and list info)
#[derive(Debug, Clone)]
pub struct TypeRef {
    /// Base type name
    pub name: String,
    /// Whether the type is non-null
    pub non_null: bool,
    /// Whether this is a list type
    pub is_list: bool,
    /// Whether list items are non-null (if is_list)
    pub list_item_non_null: bool,
}

impl TypeRef {
    /// Create a nullable type reference
    pub fn nullable(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            non_null: false,
            is_list: false,
            list_item_non_null: false,
        }
    }

    /// Create a non-null type reference
    pub fn non_null(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            non_null: true,
            is_list: false,
            list_item_non_null: false,
        }
    }

    /// Create a list type reference
    pub fn list(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            non_null: false,
            is_list: true,
            list_item_non_null: false,
        }
    }
}

/// Compiled argument definition
#[derive(Debug, Clone)]
pub struct CompiledArgument {
    /// Argument name
    pub name: String,
    /// Argument type
    pub type_ref: TypeRef,
    /// Whether the argument is required (no default value)
    pub required: bool,
    /// Default value (as string)
    pub default_value: Option<String>,
}

impl CompiledArgument {
    /// Create required argument
    pub fn required(name: impl Into<String>, type_ref: TypeRef) -> Self {
        Self {
            name: name.into(),
            type_ref,
            required: true,
            default_value: None,
        }
    }

    /// Create optional argument
    pub fn optional(name: impl Into<String>, type_ref: TypeRef) -> Self {
        Self {
            name: name.into(),
            type_ref,
            required: false,
            default_value: None,
        }
    }
}

/// Compiled input field (for input types)
#[derive(Debug, Clone)]
pub struct CompiledInputField {
    /// Field name
    pub name: String,
    /// Field type
    pub type_ref: TypeRef,
    /// Whether the field is required
    pub required: bool,
    /// Default value
    pub default_value: Option<String>,
}

/// Compiled directive definition
#[derive(Debug, Clone)]
pub struct CompiledDirective {
    /// Directive name
    pub name: String,
    /// Valid locations
    pub locations: HashSet<String>,
    /// Arguments
    pub arguments: HashMap<String, CompiledArgument>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_field_lookup() {
        let mut user_type = CompiledType::object("User");
        user_type.fields.insert(
            "id".to_string(),
            CompiledField::new("id", TypeRef::non_null("ID")),
        );
        user_type.fields.insert(
            "name".to_string(),
            CompiledField::new("name", TypeRef::nullable("String")),
        );

        assert!(user_type.field_exists("id"));
        assert!(user_type.field_exists("name"));
        assert!(!user_type.field_exists("unknown"));
    }

    #[test]
    fn test_field_arguments() {
        let field = CompiledField::new("user", TypeRef::nullable("User"))
            .with_argument(CompiledArgument::required("id", TypeRef::non_null("ID")));

        assert!(field.get_argument("id").is_some());
        assert!(field.get_argument("unknown").is_none());
    }
}
