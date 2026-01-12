//! OpenAPI Schema Validation
//!
//! Validates HTTP requests against OpenAPI 3.0/3.1 specifications.

mod compiled;
mod parser;
mod validator;

pub use compiled::{CompiledOpenApiSchema, PathOperation, PathTree};
pub use validator::OpenApiValidator;

use super::{RequestContext, SchemaSource, SchemaViolation};
use anyhow::Result;
