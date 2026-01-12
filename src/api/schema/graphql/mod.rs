//! GraphQL Schema Validation
//!
//! Validates GraphQL queries against SDL schemas.

mod compiled;
mod parser;
mod validator;

pub use compiled::CompiledGraphQLSchema;
pub use validator::GraphQLSchemaValidator;

use super::{RequestContext, SchemaSource, SchemaViolation};
use anyhow::Result;
