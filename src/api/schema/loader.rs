//! Schema Loader
//!
//! Handles loading schemas from files and URLs.

use super::source::SchemaSource;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Schema loader for file and URL sources
pub struct SchemaLoader {
    /// HTTP client for URL fetching (when reqwest feature is enabled)
    #[cfg(feature = "schema-validation")]
    client: Option<reqwest::blocking::Client>,
}

impl Default for SchemaLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaLoader {
    /// Create a new schema loader
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "schema-validation")]
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .ok(),
        }
    }

    /// Load schema content from source
    pub fn load(&self, source: &SchemaSource) -> Result<String> {
        match source {
            SchemaSource::File(path) => self.load_file(path),
            SchemaSource::Url(url) => self.load_url(url),
            SchemaSource::Inline(content) => Ok(content.clone()),
        }
    }

    /// Load schema from file
    fn load_file(&self, path: &Path) -> Result<String> {
        fs::read_to_string(path)
            .with_context(|| format!("Failed to read schema file: {}", path.display()))
    }

    /// Load schema from URL
    #[cfg(feature = "schema-validation")]
    fn load_url(&self, url: &str) -> Result<String> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HTTP client not available for URL fetching"))?;

        let response = client
            .get(url)
            .header("Accept", "application/json, application/yaml, text/plain")
            .send()
            .with_context(|| format!("Failed to fetch schema from URL: {}", url))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Failed to fetch schema from {}: HTTP {}",
                url,
                response.status()
            );
        }

        response
            .text()
            .with_context(|| format!("Failed to read schema response from: {}", url))
    }

    #[cfg(not(feature = "schema-validation"))]
    fn load_url(&self, url: &str) -> Result<String> {
        anyhow::bail!(
            "URL loading requires the 'schema-validation' feature. Cannot load: {}",
            url
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "openapi: 3.0.0").unwrap();

        let loader = SchemaLoader::new();
        let source = SchemaSource::File(file.path().to_path_buf());
        let content = loader.load(&source).unwrap();

        assert!(content.contains("openapi"));
    }

    #[test]
    fn test_load_inline() {
        let loader = SchemaLoader::new();
        let source = SchemaSource::Inline("type Query { test: String }".to_string());
        let content = loader.load(&source).unwrap();

        assert!(content.contains("Query"));
    }

    #[test]
    fn test_load_missing_file() {
        let loader = SchemaLoader::new();
        let source = SchemaSource::File("/nonexistent/path/schema.yaml".into());
        let result = loader.load(&source);

        assert!(result.is_err());
    }
}
