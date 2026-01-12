//! Gradient accumulation and management
//!
//! Handles gradient computation, accumulation, and compression for efficient transfer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Accumulated model gradients
#[derive(Debug, Clone)]
pub struct ModelGradients {
    /// Gradient values by layer
    layers: HashMap<String, LayerGradients>,
    /// Total samples contributing to these gradients
    sample_count: u64,
    /// Whether gradients have been clipped
    clipped: bool,
}

/// Gradients for a single layer
#[derive(Debug, Clone)]
pub struct LayerGradients {
    /// Gradient values
    pub values: Vec<f32>,
    /// Number of samples
    pub samples: u64,
}

impl ModelGradients {
    /// Create empty gradient accumulator
    pub fn new() -> Self {
        Self {
            layers: HashMap::new(),
            sample_count: 0,
            clipped: false,
        }
    }

    /// Accumulate gradients from a batch
    pub fn accumulate(&mut self, gradients: &[f32]) {
        // Store as single "main" layer for simplified model
        let layer = self.layers.entry("main".to_string())
            .or_insert_with(|| LayerGradients {
                values: vec![0.0; gradients.len()],
                samples: 0,
            });

        // Accumulate with running average
        for (i, &g) in gradients.iter().enumerate() {
            if i < layer.values.len() {
                layer.values[i] += g;
            }
        }
        layer.samples += 1;
        self.sample_count += 1;
    }

    /// Accumulate gradients for a specific layer
    pub fn accumulate_layer(&mut self, layer_name: &str, gradients: &[f32]) {
        let layer = self.layers.entry(layer_name.to_string())
            .or_insert_with(|| LayerGradients {
                values: vec![0.0; gradients.len()],
                samples: 0,
            });

        for (i, &g) in gradients.iter().enumerate() {
            if i < layer.values.len() {
                layer.values[i] += g;
            }
        }
        layer.samples += 1;
    }

    /// Check if gradients are empty
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty() || self.sample_count == 0
    }

    /// Get total sample count
    pub fn sample_count(&self) -> u64 {
        self.sample_count
    }

    /// Get flattened gradient values
    pub fn values(&self) -> Vec<f32> {
        let mut values = Vec::new();
        for layer in self.layers.values() {
            // Average gradients by sample count
            let avg: Vec<f32> = layer.values.iter()
                .map(|&v| if layer.samples > 0 { v / layer.samples as f32 } else { v })
                .collect();
            values.extend(avg);
        }
        values
    }

    /// Clip gradients to prevent explosion
    pub fn clip(&mut self, max_norm: f32) {
        for layer in self.layers.values_mut() {
            let norm: f32 = layer.values.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > max_norm {
                let scale = max_norm / norm;
                for v in &mut layer.values {
                    *v *= scale;
                }
            }
        }
        self.clipped = true;
    }

    /// Compress gradients for transmission (top-k sparsification)
    pub fn compress(&self, top_k: usize) -> CompressedGradients {
        let values = self.values();
        let mut indexed: Vec<(usize, f32)> = values.iter()
            .enumerate()
            .map(|(i, &v)| (i, v.abs()))
            .collect();

        // Sort by absolute magnitude
        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Take top-k
        let mut indices = Vec::with_capacity(top_k);
        let mut compressed_values = Vec::with_capacity(top_k);

        for (idx, _) in indexed.into_iter().take(top_k) {
            indices.push(idx as u32);
            compressed_values.push(values[idx]);
        }

        CompressedGradients {
            indices,
            values: compressed_values,
            original_size: values.len(),
            sample_count: self.sample_count,
        }
    }

    /// Get layer names
    pub fn layer_names(&self) -> Vec<&str> {
        self.layers.keys().map(|s| s.as_str()).collect()
    }

    /// Get gradients for a specific layer
    pub fn get_layer(&self, name: &str) -> Option<&LayerGradients> {
        self.layers.get(name)
    }
}

impl Default for ModelGradients {
    fn default() -> Self {
        Self::new()
    }
}

/// Compressed gradient representation for efficient transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedGradients {
    /// Indices of non-zero gradients
    pub indices: Vec<u32>,
    /// Gradient values
    pub values: Vec<f32>,
    /// Original tensor size
    pub original_size: usize,
    /// Number of samples
    pub sample_count: u64,
}

impl CompressedGradients {
    /// Decompress to full gradient vector
    pub fn decompress(&self) -> Vec<f32> {
        let mut full = vec![0.0; self.original_size];
        for (&idx, &val) in self.indices.iter().zip(self.values.iter()) {
            if (idx as usize) < full.len() {
                full[idx as usize] = val;
            }
        }
        full
    }

    /// Get compression ratio
    pub fn compression_ratio(&self) -> f32 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.indices.len() as f32 / self.original_size as f32
    }
}

/// Gradient update to send to coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradientUpdate {
    /// Node identifier
    pub node_id: String,
    /// Gradient values (or compressed)
    pub gradients: Vec<f32>,
    /// Number of samples used
    pub sample_count: u64,
    /// Model version this update is based on
    pub model_version: u64,
}

/// Gradient aggregation methods
#[derive(Debug, Clone, Copy)]
pub enum AggregationMethod {
    /// Simple average
    Average,
    /// Weighted by sample count
    WeightedAverage,
    /// Median (robust to outliers)
    Median,
    /// Trimmed mean (remove outliers)
    TrimmedMean { trim_ratio: f32 },
}

/// Aggregate gradients from multiple nodes
pub fn aggregate_gradients(
    updates: &[GradientUpdate],
    method: AggregationMethod,
) -> Vec<f32> {
    if updates.is_empty() {
        return Vec::new();
    }

    let grad_len = updates[0].gradients.len();

    match method {
        AggregationMethod::Average => {
            let mut result = vec![0.0; grad_len];
            for update in updates {
                for (i, &g) in update.gradients.iter().enumerate() {
                    if i < result.len() {
                        result[i] += g;
                    }
                }
            }
            let n = updates.len() as f32;
            for v in &mut result {
                *v /= n;
            }
            result
        }

        AggregationMethod::WeightedAverage => {
            let mut result = vec![0.0; grad_len];
            let total_samples: u64 = updates.iter().map(|u| u.sample_count).sum();

            for update in updates {
                let weight = update.sample_count as f32 / total_samples as f32;
                for (i, &g) in update.gradients.iter().enumerate() {
                    if i < result.len() {
                        result[i] += g * weight;
                    }
                }
            }
            result
        }

        AggregationMethod::Median => {
            let mut result = vec![0.0; grad_len];
            for i in 0..grad_len {
                let mut values: Vec<f32> = updates.iter()
                    .filter_map(|u| u.gradients.get(i).copied())
                    .collect();
                values.sort_by(|a, b| a.partial_cmp(b).unwrap());
                result[i] = if values.len() % 2 == 0 {
                    (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
                } else {
                    values[values.len() / 2]
                };
            }
            result
        }

        AggregationMethod::TrimmedMean { trim_ratio } => {
            let mut result = vec![0.0; grad_len];
            let trim_count = (updates.len() as f32 * trim_ratio) as usize;

            for i in 0..grad_len {
                let mut values: Vec<f32> = updates.iter()
                    .filter_map(|u| u.gradients.get(i).copied())
                    .collect();
                values.sort_by(|a, b| a.partial_cmp(b).unwrap());

                // Trim outliers
                let trimmed = &values[trim_count..values.len().saturating_sub(trim_count)];
                result[i] = if trimmed.is_empty() {
                    0.0
                } else {
                    trimmed.iter().sum::<f32>() / trimmed.len() as f32
                };
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gradient_accumulation() {
        let mut grads = ModelGradients::new();

        grads.accumulate(&[1.0, 2.0, 3.0]);
        grads.accumulate(&[2.0, 4.0, 6.0]);

        assert_eq!(grads.sample_count(), 2);
        assert!(!grads.is_empty());

        let values = grads.values();
        // Average: [1.5, 3.0, 4.5]
        assert_eq!(values.len(), 3);
        assert!((values[0] - 1.5).abs() < 0.01);
    }

    #[test]
    fn test_gradient_clipping() {
        let mut grads = ModelGradients::new();
        grads.accumulate(&[10.0, 10.0, 10.0]);

        grads.clip(1.0);

        let values = grads.values();
        let norm: f32 = values.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(norm <= 1.01); // Allow small floating point error
    }

    #[test]
    fn test_compression() {
        let mut grads = ModelGradients::new();
        grads.accumulate(&[0.1, 5.0, 0.2, 10.0, 0.3]);

        let compressed = grads.compress(2); // Top 2

        assert_eq!(compressed.indices.len(), 2);
        assert!(compressed.indices.contains(&3)); // 10.0
        assert!(compressed.indices.contains(&1)); // 5.0
    }

    #[test]
    fn test_decompression() {
        let compressed = CompressedGradients {
            indices: vec![1, 3],
            values: vec![5.0, 10.0],
            original_size: 5,
            sample_count: 1,
        };

        let full = compressed.decompress();
        assert_eq!(full, vec![0.0, 5.0, 0.0, 10.0, 0.0]);
    }

    #[test]
    fn test_aggregation_average() {
        let updates = vec![
            GradientUpdate {
                node_id: "a".to_string(),
                gradients: vec![1.0, 2.0],
                sample_count: 10,
                model_version: 1,
            },
            GradientUpdate {
                node_id: "b".to_string(),
                gradients: vec![3.0, 4.0],
                sample_count: 10,
                model_version: 1,
            },
        ];

        let result = aggregate_gradients(&updates, AggregationMethod::Average);
        assert_eq!(result, vec![2.0, 3.0]);
    }

    #[test]
    fn test_aggregation_weighted() {
        let updates = vec![
            GradientUpdate {
                node_id: "a".to_string(),
                gradients: vec![1.0],
                sample_count: 1,
                model_version: 1,
            },
            GradientUpdate {
                node_id: "b".to_string(),
                gradients: vec![3.0],
                sample_count: 3,
                model_version: 1,
            },
        ];

        let result = aggregate_gradients(&updates, AggregationMethod::WeightedAverage);
        // (1.0 * 1/4) + (3.0 * 3/4) = 0.25 + 2.25 = 2.5
        assert!((result[0] - 2.5).abs() < 0.01);
    }

    #[test]
    fn test_aggregation_median() {
        let updates = vec![
            GradientUpdate { node_id: "a".to_string(), gradients: vec![1.0], sample_count: 1, model_version: 1 },
            GradientUpdate { node_id: "b".to_string(), gradients: vec![2.0], sample_count: 1, model_version: 1 },
            GradientUpdate { node_id: "c".to_string(), gradients: vec![100.0], sample_count: 1, model_version: 1 }, // outlier
        ];

        let result = aggregate_gradients(&updates, AggregationMethod::Median);
        assert_eq!(result[0], 2.0); // Median ignores outlier
    }
}
