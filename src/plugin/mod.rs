//! WAF Plugin Architecture
//!
//! Provides extensibility for the WAF engine through a plugin system.
//! Plugins can add custom rules, detection logic, or scoring adjustments.
//!
//! # Plugin Types
//!
//! - **RulePlugin**: Provides additional detection rules
//! - **DetectionPlugin**: Custom detection logic that runs alongside rules
//! - **ScoringPlugin**: Adjusts scores based on request context
//!
//! # Execution Phases
//!
//! Plugins execute in specific phases:
//! 1. **PreDetection**: Before rule matching (e.g., preprocessing)
//! 2. **Detection**: Custom detection logic
//! 3. **PostDetection**: After rule matching (e.g., filtering)
//! 4. **Scoring**: Score adjustment
//!
//! # Rule ID Ranges
//!
//! - 99100-99499: Rule plugins
//! - 99500-99799: Detection plugins
//! - 99800-99999: Scoring plugins

pub mod registry;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::detection::{AnomalyScore, Detection};
use crate::rules::Rule;

/// Plugin execution phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginPhase {
    /// Before rule matching
    PreDetection,
    /// Custom detection logic (runs alongside rules)
    Detection,
    /// After rule matching
    PostDetection,
    /// Score adjustment phase
    Scoring,
}

/// Plugin information and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Unique plugin identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Phases this plugin executes in
    pub phases: Vec<PluginPhase>,
    /// Whether this plugin is enabled
    pub enabled: bool,
}

impl PluginInfo {
    /// Create new plugin info
    pub fn new(id: &str, name: &str, version: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            description: String::new(),
            phases: Vec::new(),
            enabled: true,
        }
    }

    /// Set description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    /// Set phases
    pub fn with_phases(mut self, phases: Vec<PluginPhase>) -> Self {
        self.phases = phases;
        self
    }
}

/// Context passed to plugins during execution
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Request path
    pub path: String,
    /// Query string (if present)
    pub query: Option<String>,
    /// HTTP method
    pub method: String,
    /// Source IP address (if available)
    pub source_ip: Option<String>,
    /// Request headers (name -> values)
    pub headers: std::collections::HashMap<String, Vec<String>>,
    /// Current detections (available in PostDetection and Scoring phases)
    pub detections: Vec<Detection>,
    /// Current score (available in Scoring phase)
    pub score: AnomalyScore,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            path: String::new(),
            query: None,
            method: "GET".to_string(),
            source_ip: None,
            headers: std::collections::HashMap::new(),
            detections: Vec::new(),
            score: AnomalyScore::default(),
        }
    }
}

/// Output from plugin execution
#[derive(Debug, Clone, Default)]
pub struct PluginOutput {
    /// New detections to add
    pub detections: Vec<Detection>,
    /// Score adjustment (positive or negative)
    pub score_adjustment: i32,
    /// Tags to add to the request
    pub tags: Vec<String>,
    /// Whether to skip further processing
    pub skip_remaining: bool,
    /// Custom metadata for logging
    pub metadata: std::collections::HashMap<String, String>,
}

impl PluginOutput {
    /// Create empty output
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create output with detections
    pub fn with_detections(detections: Vec<Detection>) -> Self {
        Self {
            detections,
            ..Default::default()
        }
    }

    /// Create output with score adjustment
    pub fn with_score_adjustment(adjustment: i32) -> Self {
        Self {
            score_adjustment: adjustment,
            ..Default::default()
        }
    }

    /// Add a tag
    pub fn add_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    /// Set skip remaining flag
    pub fn skip_remaining(mut self) -> Self {
        self.skip_remaining = true;
        self
    }

    /// Add metadata
    pub fn add_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Trait for plugins that provide additional detection rules
pub trait RulePlugin: Send + Sync {
    /// Get plugin information
    fn info(&self) -> PluginInfo;

    /// Initialize the plugin with configuration
    fn initialize(&mut self, config: serde_json::Value) -> Result<()>;

    /// Get rules provided by this plugin
    fn rules(&self) -> Vec<Rule>;

    /// Called when plugin is being unloaded (optional)
    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Trait for plugins that provide custom detection logic
pub trait DetectionPlugin: Send + Sync {
    /// Get plugin information
    fn info(&self) -> PluginInfo;

    /// Initialize the plugin with configuration
    fn initialize(&mut self, config: serde_json::Value) -> Result<()>;

    /// Execute detection logic
    fn detect(&self, value: &str, location: &str, context: &RequestContext) -> PluginOutput;

    /// Called when plugin is being unloaded (optional)
    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Trait for plugins that adjust scoring
pub trait ScoringPlugin: Send + Sync {
    /// Get plugin information
    fn info(&self) -> PluginInfo;

    /// Initialize the plugin with configuration
    fn initialize(&mut self, config: serde_json::Value) -> Result<()>;

    /// Adjust score based on context and current detections
    fn adjust_score(
        &self,
        context: &RequestContext,
        detections: &[Detection],
        current_score: &AnomalyScore,
    ) -> PluginOutput;

    /// Called when plugin is being unloaded (optional)
    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

// Implement Serialize/Deserialize for PluginPhase
impl Serialize for PluginPhase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            PluginPhase::PreDetection => "pre-detection",
            PluginPhase::Detection => "detection",
            PluginPhase::PostDetection => "post-detection",
            PluginPhase::Scoring => "scoring",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for PluginPhase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "pre-detection" => Ok(PluginPhase::PreDetection),
            "detection" => Ok(PluginPhase::Detection),
            "post-detection" => Ok(PluginPhase::PostDetection),
            "scoring" => Ok(PluginPhase::Scoring),
            _ => Err(serde::de::Error::custom(format!(
                "unknown plugin phase: {}",
                s
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_info() {
        let info = PluginInfo::new("test-plugin", "Test Plugin", "1.0.0")
            .with_description("A test plugin")
            .with_phases(vec![PluginPhase::Detection]);

        assert_eq!(info.id, "test-plugin");
        assert_eq!(info.name, "Test Plugin");
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.description, "A test plugin");
        assert_eq!(info.phases.len(), 1);
        assert!(info.enabled);
    }

    #[test]
    fn test_plugin_output() {
        let output = PluginOutput::empty()
            .add_tag("custom")
            .add_metadata("key", "value")
            .skip_remaining();

        assert!(output.skip_remaining);
        assert_eq!(output.tags, vec!["custom"]);
        assert_eq!(output.metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_request_context_default() {
        let ctx = RequestContext::default();
        assert_eq!(ctx.method, "GET");
        assert!(ctx.detections.is_empty());
    }

    #[test]
    fn test_plugin_phase_serde() {
        let phase = PluginPhase::Detection;
        let json = serde_json::to_string(&phase).unwrap();
        assert_eq!(json, "\"detection\"");

        let deserialized: PluginPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, phase);
    }
}
