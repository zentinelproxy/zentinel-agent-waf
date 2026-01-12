//! OpenAPI Specification Parser
//!
//! Parses OpenAPI 3.0/3.1 specifications from YAML or JSON.

use super::compiled::{CompiledOpenApiSchema, CompiledParameter, PathOperation, PathTree};
use crate::api::schema::{SchemaMetadata, SchemaSource, SchemaType};
use anyhow::{Context, Result};
use openapiv3::{OpenAPI, PathItem, ReferenceOr};
use std::collections::HashMap;
use std::fs;

/// Parse OpenAPI spec from source
pub fn parse_from_source(source: &SchemaSource) -> Result<CompiledOpenApiSchema> {
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
            // URL loading requires async - implement with reqwest later
            anyhow::bail!("URL loading not yet implemented - use file source")
        }
        SchemaSource::Inline(content) => Ok(content.clone()),
    }
}

/// Parse OpenAPI content
fn parse_content(content: &str, source: SchemaSource) -> Result<CompiledOpenApiSchema> {
    // Try YAML first, then JSON
    let spec: OpenAPI = if content.trim().starts_with('{') {
        serde_json::from_str(content).context("Failed to parse OpenAPI JSON")?
    } else {
        serde_yaml::from_str(content).context("Failed to parse OpenAPI YAML")?
    };

    compile_spec(spec, source)
}

/// Compile OpenAPI spec into efficient lookup structure
fn compile_spec(spec: OpenAPI, source: SchemaSource) -> Result<CompiledOpenApiSchema> {
    let mut path_tree = PathTree::new();
    let mut schemas = HashMap::new();

    // Extract version and title
    let version = Some(spec.openapi.clone());
    let title = Some(spec.info.title.clone());

    // Process paths
    for (path_template, path_item) in &spec.paths.paths {
        let path_item = resolve_path_item(path_item, &spec)?;
        let operations = extract_operations(&path_item, &spec)?;

        if !operations.is_empty() {
            path_tree.insert(path_template, operations);
        }
    }

    // Process component schemas for JSON validation
    if let Some(components) = &spec.components {
        for (name, schema_ref) in &components.schemas {
            if let ReferenceOr::Item(schema) = schema_ref {
                // Convert to JSON schema for validation
                let json_schema = serde_json::to_value(schema)?;
                schemas.insert(name.clone(), json_schema);
            }
        }
    }

    let metadata = SchemaMetadata::new(SchemaType::OpenApi, source)
        .with_version(version.unwrap_or_default())
        .with_title(title.unwrap_or_default());

    Ok(CompiledOpenApiSchema {
        path_tree,
        schemas,
        metadata,
    })
}

/// Resolve path item reference
fn resolve_path_item<'a>(
    item: &'a ReferenceOr<PathItem>,
    _spec: &'a OpenAPI,
) -> Result<&'a PathItem> {
    match item {
        ReferenceOr::Item(path_item) => Ok(path_item),
        ReferenceOr::Reference { reference } => {
            anyhow::bail!("Path item references not yet supported: {}", reference)
        }
    }
}

/// Extract operations from path item
fn extract_operations(
    path_item: &PathItem,
    spec: &OpenAPI,
) -> Result<HashMap<String, PathOperation>> {
    let mut operations = HashMap::new();

    let method_ops = [
        ("GET", &path_item.get),
        ("POST", &path_item.post),
        ("PUT", &path_item.put),
        ("DELETE", &path_item.delete),
        ("PATCH", &path_item.patch),
        ("HEAD", &path_item.head),
        ("OPTIONS", &path_item.options),
        ("TRACE", &path_item.trace),
    ];

    for (method, op_opt) in method_ops {
        if let Some(operation) = op_opt {
            let path_op = compile_operation(operation, &path_item.parameters, spec)?;
            operations.insert(method.to_string(), path_op);
        }
    }

    Ok(operations)
}

/// Compile a single operation
fn compile_operation(
    operation: &openapiv3::Operation,
    path_params: &[ReferenceOr<openapiv3::Parameter>],
    spec: &OpenAPI,
) -> Result<PathOperation> {
    let mut parameters = Vec::new();

    // Add path-level parameters
    for param_ref in path_params {
        if let Some(param) = resolve_parameter(param_ref, spec)? {
            parameters.push(param);
        }
    }

    // Add operation-level parameters
    for param_ref in &operation.parameters {
        if let Some(param) = resolve_parameter(param_ref, spec)? {
            parameters.push(param);
        }
    }

    // Extract request body schema reference
    let request_body_schema = operation.request_body.as_ref().and_then(|rb| {
        if let ReferenceOr::Item(body) = rb {
            body.content
                .get("application/json")
                .and_then(|media| media.schema.as_ref())
                .and_then(|s| {
                    if let ReferenceOr::Reference { reference } = s {
                        Some(reference.clone())
                    } else {
                        None
                    }
                })
        } else {
            None
        }
    });

    // Extract response status codes
    let mut response_codes = Vec::new();
    for (status, _) in &operation.responses.responses {
        response_codes.push(status.clone());
    }

    Ok(PathOperation {
        operation_id: operation.operation_id.clone(),
        parameters,
        request_body_schema,
        response_codes,
    })
}

/// Resolve parameter reference
fn resolve_parameter(
    param_ref: &ReferenceOr<openapiv3::Parameter>,
    _spec: &OpenAPI,
) -> Result<Option<CompiledParameter>> {
    match param_ref {
        ReferenceOr::Item(param) => {
            let data = match param {
                openapiv3::Parameter::Query { parameter_data, .. } => parameter_data,
                openapiv3::Parameter::Header { parameter_data, .. } => parameter_data,
                openapiv3::Parameter::Path { parameter_data, .. } => parameter_data,
                openapiv3::Parameter::Cookie { parameter_data, .. } => parameter_data,
            };

            let location = match param {
                openapiv3::Parameter::Query { .. } => "query",
                openapiv3::Parameter::Header { .. } => "header",
                openapiv3::Parameter::Path { .. } => "path",
                openapiv3::Parameter::Cookie { .. } => "cookie",
            };

            Ok(Some(CompiledParameter {
                name: data.name.clone(),
                location: location.to_string(),
                required: data.required,
                schema_type: extract_param_type(&data.format),
            }))
        }
        ReferenceOr::Reference { reference } => {
            // TODO: Resolve component parameter references
            tracing::warn!("Parameter reference not resolved: {}", reference);
            Ok(None)
        }
    }
}

/// Extract parameter type from format
fn extract_param_type(format: &openapiv3::ParameterSchemaOrContent) -> Option<String> {
    match format {
        openapiv3::ParameterSchemaOrContent::Schema(schema_ref) => {
            if let ReferenceOr::Item(schema) = schema_ref {
                match &schema.schema_kind {
                    openapiv3::SchemaKind::Type(type_) => match type_ {
                        openapiv3::Type::String(_) => Some("string".to_string()),
                        openapiv3::Type::Number(_) => Some("number".to_string()),
                        openapiv3::Type::Integer(_) => Some("integer".to_string()),
                        openapiv3::Type::Boolean {} => Some("boolean".to_string()),
                        openapiv3::Type::Array(_) => Some("array".to_string()),
                        openapiv3::Type::Object(_) => Some("object".to_string()),
                    },
                    _ => None,
                }
            } else {
                None
            }
        }
        openapiv3::ParameterSchemaOrContent::Content(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PETSTORE_YAML: &str = r#"
openapi: "3.0.0"
info:
  title: Petstore
  version: "1.0.0"
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - name: limit
          in: query
          required: false
          schema:
            type: integer
      responses:
        '200':
          description: A list of pets
    post:
      operationId: createPet
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Pet'
      responses:
        '201':
          description: Pet created
  /pets/{petId}:
    get:
      operationId: getPet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: A pet
components:
  schemas:
    Pet:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
"#;

    #[test]
    fn test_parse_petstore() {
        let source = SchemaSource::Inline(PETSTORE_YAML.to_string());
        let schema = parse_from_source(&source).expect("Failed to parse petstore");

        assert!(schema.path_tree.lookup("/pets", "GET").is_some());
        assert!(schema.path_tree.lookup("/pets", "POST").is_some());
        assert!(schema.path_tree.lookup("/pets/123", "GET").is_some());
        assert!(schema.path_tree.lookup("/unknown", "GET").is_none());
    }
}
