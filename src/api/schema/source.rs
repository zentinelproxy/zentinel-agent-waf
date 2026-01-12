//! Schema Source Types
//!
//! Defines schema source abstractions for file and URL loading.

use std::path::PathBuf;

/// Schema source - where to load the schema from
#[derive(Debug, Clone)]
pub enum SchemaSource {
    /// Load from local file path
    File(PathBuf),
    /// Fetch from URL at startup
    Url(String),
    /// Inline schema content (for testing)
    Inline(String),
}

impl SchemaSource {
    /// Parse a source string (file path or URL)
    pub fn parse(source: &str) -> Self {
        if source.starts_with("http://") || source.starts_with("https://") {
            SchemaSource::Url(source.to_string())
        } else {
            SchemaSource::File(PathBuf::from(source))
        }
    }

    /// Check if this is a URL source
    pub fn is_url(&self) -> bool {
        matches!(self, SchemaSource::Url(_))
    }

    /// Check if this is a file source
    pub fn is_file(&self) -> bool {
        matches!(self, SchemaSource::File(_))
    }

    /// Get the source as a string for logging
    pub fn as_str(&self) -> &str {
        match self {
            SchemaSource::File(path) => path.to_str().unwrap_or("<invalid path>"),
            SchemaSource::Url(url) => url,
            SchemaSource::Inline(_) => "<inline>",
        }
    }
}

/// Schema type for identifying the format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaType {
    /// OpenAPI 3.0 or 3.1 specification
    OpenApi,
    /// GraphQL SDL schema
    GraphQL,
}

impl SchemaType {
    /// Detect schema type from file extension
    pub fn from_extension(path: &str) -> Option<Self> {
        let lower = path.to_lowercase();
        if lower.ends_with(".yaml")
            || lower.ends_with(".yml")
            || lower.ends_with(".json")
            || lower.contains("openapi")
            || lower.contains("swagger")
        {
            Some(SchemaType::OpenApi)
        } else if lower.ends_with(".graphql") || lower.ends_with(".gql") {
            Some(SchemaType::GraphQL)
        } else {
            None
        }
    }

    /// Detect schema type from content
    pub fn from_content(content: &str) -> Option<Self> {
        let trimmed = content.trim();

        // GraphQL schemas typically start with type/schema/directive keywords
        if trimmed.starts_with("type ")
            || trimmed.starts_with("schema ")
            || trimmed.starts_with("directive ")
            || trimmed.starts_with("scalar ")
            || trimmed.starts_with("interface ")
            || trimmed.starts_with("union ")
            || trimmed.starts_with("enum ")
            || trimmed.starts_with("input ")
            || trimmed.contains("type Query")
        {
            return Some(SchemaType::GraphQL);
        }

        // OpenAPI specs have openapi or swagger version field
        if trimmed.contains("\"openapi\"")
            || trimmed.contains("'openapi'")
            || trimmed.contains("openapi:")
            || trimmed.contains("\"swagger\"")
            || trimmed.contains("swagger:")
        {
            return Some(SchemaType::OpenApi);
        }

        None
    }
}

/// Schema metadata
#[derive(Debug, Clone)]
pub struct SchemaMetadata {
    /// Schema type
    pub schema_type: SchemaType,
    /// Source location
    pub source: SchemaSource,
    /// Version string (if available)
    pub version: Option<String>,
    /// Title (if available)
    pub title: Option<String>,
    /// When the schema was loaded
    pub loaded_at: std::time::Instant,
}

impl SchemaMetadata {
    /// Create new metadata
    pub fn new(schema_type: SchemaType, source: SchemaSource) -> Self {
        Self {
            schema_type,
            source,
            version: None,
            title: None,
            loaded_at: std::time::Instant::now(),
        }
    }

    /// Set version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set title
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_source_parse() {
        let file = SchemaSource::parse("/etc/openapi.yaml");
        assert!(file.is_file());

        let url = SchemaSource::parse("https://api.example.com/schema.yaml");
        assert!(url.is_url());
    }

    #[test]
    fn test_schema_type_from_extension() {
        assert_eq!(
            SchemaType::from_extension("api.yaml"),
            Some(SchemaType::OpenApi)
        );
        assert_eq!(
            SchemaType::from_extension("schema.graphql"),
            Some(SchemaType::GraphQL)
        );
        assert_eq!(
            SchemaType::from_extension("openapi.json"),
            Some(SchemaType::OpenApi)
        );
    }

    #[test]
    fn test_schema_type_from_content() {
        let openapi = r#"{"openapi": "3.0.0"}"#;
        assert_eq!(SchemaType::from_content(openapi), Some(SchemaType::OpenApi));

        let graphql = "type Query { user: User }";
        assert_eq!(SchemaType::from_content(graphql), Some(SchemaType::GraphQL));
    }
}
