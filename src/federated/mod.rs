//! Federated Learning Module
//!
//! Privacy-preserving distributed learning across WAF deployments.
#![allow(clippy::await_holding_lock)]
//! Only model gradients are shared, never raw request data.

mod coordinator;
mod gradients;
mod privacy;

pub use coordinator::{CoordinatorConfig, FederatedCoordinator};
pub use gradients::{GradientUpdate, ModelGradients};
pub use privacy::{DifferentialPrivacy, PrivacyBudget};

use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Federated learning configuration
#[derive(Debug, Clone)]
pub struct FederatedConfig {
    /// Enable federated learning
    pub enabled: bool,
    /// Coordinator server URL
    pub coordinator_url: Option<String>,
    /// Local training batch size
    pub batch_size: usize,
    /// Minimum samples before contributing
    pub min_samples: usize,
    /// Update interval
    pub update_interval: Duration,
    /// Privacy budget (epsilon for differential privacy)
    pub privacy_epsilon: f64,
    /// Enable secure aggregation
    pub secure_aggregation: bool,
    /// Node identifier
    pub node_id: String,
}

impl Default for FederatedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            coordinator_url: None,
            batch_size: 32,
            min_samples: 1000,
            update_interval: Duration::from_secs(3600), // 1 hour
            privacy_epsilon: 1.0,
            secure_aggregation: true,
            node_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

/// Training sample for federated learning
#[derive(Debug, Clone)]
pub struct TrainingSample {
    /// Feature vector
    pub features: Vec<f32>,
    /// Label (attack type or benign)
    pub label: u8,
    /// Confidence in label (for semi-supervised learning)
    pub confidence: f32,
    /// Timestamp
    pub timestamp: Instant,
}

/// Federated learning engine
pub struct FederatedLearning {
    config: FederatedConfig,
    /// Local model being trained
    local_model: Arc<RwLock<LocalModel>>,
    /// Accumulated gradients
    gradients: Arc<RwLock<ModelGradients>>,
    /// Training samples buffer
    samples: Arc<RwLock<Vec<TrainingSample>>>,
    /// Coordinator connection
    coordinator: Option<FederatedCoordinator>,
    /// Privacy mechanism
    privacy: DifferentialPrivacy,
    /// Last sync time
    last_sync: Arc<RwLock<Instant>>,
    /// Statistics
    stats: Arc<RwLock<FederatedStats>>,
}

/// Local model for training
#[derive(Debug, Clone)]
pub struct LocalModel {
    /// Model weights (simplified representation)
    pub weights: Vec<f32>,
    /// Model version
    pub version: u64,
    /// Architecture identifier
    pub architecture: String,
}

impl Default for LocalModel {
    fn default() -> Self {
        // Initialize with small random weights
        let mut weights = Vec::with_capacity(10000);
        for i in 0..10000 {
            // Pseudo-random initialization
            weights.push((i as f32 * 0.0001).sin() * 0.1);
        }

        Self {
            weights,
            version: 0,
            architecture: "zentinel-waf-v1".to_string(),
        }
    }
}

/// Federated learning statistics
#[derive(Debug, Default)]
pub struct FederatedStats {
    /// Total samples collected
    pub samples_collected: u64,
    /// Total updates contributed
    pub updates_contributed: u64,
    /// Total models received
    pub models_received: u64,
    /// Last contribution time
    pub last_contribution: Option<Instant>,
    /// Last model update time
    pub last_model_update: Option<Instant>,
    /// Training rounds participated
    pub rounds_participated: u64,
}

impl FederatedLearning {
    /// Create new federated learning instance
    pub fn new(config: FederatedConfig) -> Self {
        let privacy = DifferentialPrivacy::new(config.privacy_epsilon);
        let coordinator = config
            .coordinator_url
            .as_ref()
            .map(|url| FederatedCoordinator::new(url.clone(), config.node_id.clone()));

        Self {
            config,
            local_model: Arc::new(RwLock::new(LocalModel::default())),
            gradients: Arc::new(RwLock::new(ModelGradients::new())),
            samples: Arc::new(RwLock::new(Vec::new())),
            coordinator,
            privacy,
            last_sync: Arc::new(RwLock::new(Instant::now())),
            stats: Arc::new(RwLock::new(FederatedStats::default())),
        }
    }

    /// Add a training sample from WAF inspection
    pub fn add_sample(&self, features: Vec<f32>, label: u8, confidence: f32) {
        if !self.config.enabled {
            return;
        }

        let sample = TrainingSample {
            features,
            label,
            confidence,
            timestamp: Instant::now(),
        };

        let mut samples = self.samples.write();
        samples.push(sample);

        let mut stats = self.stats.write();
        stats.samples_collected += 1;

        // Trigger local training if batch is full
        if samples.len() >= self.config.batch_size {
            drop(samples);
            drop(stats);
            self.train_local_batch();
        }
    }

    /// Train on local batch and accumulate gradients
    fn train_local_batch(&self) {
        let mut samples = self.samples.write();
        if samples.len() < self.config.batch_size {
            return;
        }

        // Take a batch
        let batch: Vec<_> = samples.drain(..self.config.batch_size).collect();
        drop(samples);

        // Compute gradients (simplified gradient computation)
        let gradients = self.compute_gradients(&batch);

        // Apply differential privacy
        let private_gradients = self.privacy.add_noise(&gradients);

        // Accumulate
        let mut accumulated = self.gradients.write();
        accumulated.accumulate(&private_gradients);

        debug!(batch_size = batch.len(), "Completed local training batch");
    }

    /// Compute gradients for a batch (simplified)
    fn compute_gradients(&self, batch: &[TrainingSample]) -> Vec<f32> {
        let model = self.local_model.read();
        let mut gradients = vec![0.0f32; model.weights.len()];

        for sample in batch {
            // Forward pass (simplified)
            let prediction = self.forward(&model, &sample.features);

            // Compute loss gradient (cross-entropy)
            let error = prediction - (sample.label as f32 / 255.0);

            // Backward pass (simplified gradient accumulation)
            for (i, &feature) in sample.features.iter().enumerate() {
                if i < gradients.len() {
                    gradients[i] += error * feature * sample.confidence;
                }
            }
        }

        // Average gradients
        let batch_size = batch.len() as f32;
        for g in &mut gradients {
            *g /= batch_size;
        }

        gradients
    }

    /// Simple forward pass
    fn forward(&self, model: &LocalModel, features: &[f32]) -> f32 {
        let mut sum = 0.0f32;
        for (i, &f) in features.iter().enumerate() {
            if i < model.weights.len() {
                sum += f * model.weights[i];
            }
        }
        // Sigmoid activation
        1.0 / (1.0 + (-sum).exp())
    }

    /// Contribute gradients to coordinator
    pub async fn contribute(&self) -> Result<(), FederatedError> {
        if !self.config.enabled {
            return Ok(());
        }

        let coordinator = self
            .coordinator
            .as_ref()
            .ok_or(FederatedError::NoCoordinator)?;

        // Check if we have enough samples
        let stats = self.stats.read();
        if stats.samples_collected < self.config.min_samples as u64 {
            return Err(FederatedError::InsufficientSamples {
                have: stats.samples_collected,
                need: self.config.min_samples as u64,
            });
        }
        drop(stats);

        // Get accumulated gradients
        let gradients = {
            let mut g = self.gradients.write();
            std::mem::take(&mut *g)
        };

        if gradients.is_empty() {
            return Err(FederatedError::NoGradients);
        }

        // Submit to coordinator
        let update = GradientUpdate {
            node_id: self.config.node_id.clone(),
            gradients: gradients.values().to_vec(),
            sample_count: gradients.sample_count(),
            model_version: self.local_model.read().version,
        };

        coordinator.submit_gradients(update).await?;

        let mut stats = self.stats.write();
        stats.updates_contributed += 1;
        stats.last_contribution = Some(Instant::now());
        stats.rounds_participated += 1;

        info!(
            updates = stats.updates_contributed,
            "Contributed gradients to federated coordinator"
        );

        Ok(())
    }

    /// Fetch and apply updated model from coordinator
    pub async fn sync_model(&self) -> Result<(), FederatedError> {
        if !self.config.enabled {
            return Ok(());
        }

        let coordinator = self
            .coordinator
            .as_ref()
            .ok_or(FederatedError::NoCoordinator)?;

        // Check if enough time has passed
        let last_sync = *self.last_sync.read();
        if last_sync.elapsed() < self.config.update_interval {
            return Ok(());
        }

        // Fetch latest model
        let current_version = self.local_model.read().version;
        let global_model = coordinator.fetch_model(current_version).await?;

        if let Some(model) = global_model {
            // Apply federated averaging
            let mut local = self.local_model.write();
            self.federated_average(&mut local, &model);
            local.version = model.version;

            let mut stats = self.stats.write();
            stats.models_received += 1;
            stats.last_model_update = Some(Instant::now());

            info!(version = model.version, "Applied federated model update");
        }

        *self.last_sync.write() = Instant::now();
        Ok(())
    }

    /// Apply federated averaging
    fn federated_average(&self, local: &mut LocalModel, global: &GlobalModel) {
        // Weighted average based on sample counts
        let local_weight = 0.3; // Keep 30% local knowledge
        let global_weight = 0.7; // Apply 70% global update

        for (i, local_w) in local.weights.iter_mut().enumerate() {
            if i < global.weights.len() {
                *local_w = (*local_w * local_weight) + (global.weights[i] * global_weight);
            }
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> FederatedStats {
        self.stats.read().clone()
    }

    /// Check if ready to contribute
    pub fn ready_to_contribute(&self) -> bool {
        let stats = self.stats.read();
        stats.samples_collected >= self.config.min_samples as u64
            && !self.gradients.read().is_empty()
    }

    /// Extract features from a request for training
    pub fn extract_features(
        &self,
        path: &str,
        query: Option<&str>,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Vec<f32> {
        let mut features = Vec::with_capacity(256);

        // Path features
        features.push(path.len() as f32 / 1000.0);
        features.push(path.matches('/').count() as f32 / 10.0);
        features.push(if path.contains("..") { 1.0 } else { 0.0 });
        features.push(if path.contains("'") { 1.0 } else { 0.0 });
        features.push(if path.contains("<") { 1.0 } else { 0.0 });

        // Query features
        if let Some(q) = query {
            features.push(q.len() as f32 / 1000.0);
            features.push(q.matches('=').count() as f32 / 10.0);
            features.push(q.matches('&').count() as f32 / 10.0);
            features.push(self.entropy(q.as_bytes()));
        } else {
            features.extend_from_slice(&[0.0; 4]);
        }

        // Header features
        features.push(headers.len() as f32 / 20.0);
        for (name, value) in headers.iter().take(10) {
            features.push(name.len() as f32 / 100.0);
            features.push(value.len() as f32 / 1000.0);
        }
        // Pad if fewer than 10 headers
        while features.len() < 30 {
            features.push(0.0);
        }

        // Body features
        if let Some(b) = body {
            features.push(b.len() as f32 / 10000.0);
            features.push(self.entropy(b));
            features.push(self.printable_ratio(b));
        } else {
            features.extend_from_slice(&[0.0; 3]);
        }

        // Character distribution features (n-gram inspired)
        let all_text = format!(
            "{} {} {}",
            path,
            query.unwrap_or(""),
            body.map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or_default()
        );

        // Add character frequency buckets
        let mut char_buckets = [0u32; 16];
        for c in all_text.chars() {
            let bucket = (c as usize) % 16;
            char_buckets[bucket] += 1;
        }
        let total = all_text.len().max(1) as f32;
        for count in char_buckets {
            features.push(count as f32 / total);
        }

        // Pad to fixed size
        features.resize(256, 0.0);
        features
    }

    /// Calculate entropy of bytes
    fn entropy(&self, data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy = 0.0f32;
        for &count in &counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy / 8.0 // Normalize to 0-1
    }

    /// Calculate ratio of printable characters
    fn printable_ratio(&self, data: &[u8]) -> f32 {
        if data.is_empty() {
            return 1.0;
        }

        let printable = data.iter().filter(|&&b| (0x20..0x7F).contains(&b)).count();
        printable as f32 / data.len() as f32
    }
}

/// Global model from coordinator
#[derive(Debug, Clone)]
pub struct GlobalModel {
    pub weights: Vec<f32>,
    pub version: u64,
    pub participants: u32,
    pub architecture: String,
}

/// Federated learning errors
#[derive(Debug, thiserror::Error)]
pub enum FederatedError {
    #[error("No coordinator configured")]
    NoCoordinator,

    #[error("Insufficient samples: have {have}, need {need}")]
    InsufficientSamples { have: u64, need: u64 },

    #[error("No gradients to contribute")]
    NoGradients,

    #[error("Coordinator error: {0}")]
    CoordinatorError(String),

    #[error("Model version mismatch: local {local}, global {global}")]
    VersionMismatch { local: u64, global: u64 },

    #[error("Network error: {0}")]
    NetworkError(String),
}

impl Clone for FederatedStats {
    fn clone(&self) -> Self {
        Self {
            samples_collected: self.samples_collected,
            updates_contributed: self.updates_contributed,
            models_received: self.models_received,
            last_contribution: self.last_contribution,
            last_model_update: self.last_model_update,
            rounds_participated: self.rounds_participated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_extraction() {
        let fl = FederatedLearning::new(FederatedConfig::default());

        let features = fl.extract_features(
            "/api/users",
            Some("id=1&name=test"),
            &[("Content-Type".to_string(), "application/json".to_string())],
            Some(b"{\"key\": \"value\"}"),
        );

        assert_eq!(features.len(), 256);
        assert!(features[0] > 0.0); // Path length
    }

    #[test]
    fn test_entropy_calculation() {
        let fl = FederatedLearning::new(FederatedConfig::default());

        // Low entropy (repeated)
        let low = fl.entropy(b"aaaaaaaaaa");
        // High entropy (random-ish)
        let high = fl.entropy(b"aB3$xY9@mN");

        assert!(low < high);
    }

    #[test]
    fn test_sample_collection() {
        let config = FederatedConfig {
            enabled: true,
            batch_size: 10,
            ..Default::default()
        };
        let fl = FederatedLearning::new(config);

        // Add samples
        for i in 0..5 {
            fl.add_sample(vec![i as f32; 256], 0, 1.0);
        }

        let stats = fl.stats();
        assert_eq!(stats.samples_collected, 5);
    }

    #[test]
    fn test_local_model_forward() {
        let fl = FederatedLearning::new(FederatedConfig::default());
        let model = LocalModel::default();

        let features = vec![0.5f32; 100];
        let output = fl.forward(&model, &features);

        // Output should be between 0 and 1 (sigmoid)
        assert!(output >= 0.0 && output <= 1.0);
    }

    #[test]
    fn test_printable_ratio() {
        let fl = FederatedLearning::new(FederatedConfig::default());

        let printable = fl.printable_ratio(b"Hello World!");
        let binary = fl.printable_ratio(&[0x00, 0x01, 0x02, 0xFF]);

        assert!(printable > 0.9);
        assert!(binary < 0.1);
    }
}
