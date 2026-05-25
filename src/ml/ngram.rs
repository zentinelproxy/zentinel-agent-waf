//! Character N-Gram Tokenizer
//!
//! Extracts character-level n-grams from input strings for ML-based analysis.
//! N-grams are effective for detecting attack patterns because they:
//! - Are language-agnostic
//! - Capture local structure
//! - Are robust to obfuscation

use rustc_hash::FxHashMap;
use std::hash::{Hash, Hasher};

/// Configuration for n-gram extraction
#[derive(Debug, Clone)]
pub struct NGramConfig {
    /// Minimum n-gram size (default: 2)
    pub min_n: usize,
    /// Maximum n-gram size (default: 4)
    pub max_n: usize,
    /// Whether to lowercase input (default: true)
    pub lowercase: bool,
    /// Maximum unique n-grams to keep (default: 10000)
    pub max_features: usize,
}

impl Default for NGramConfig {
    fn default() -> Self {
        Self {
            min_n: 2,
            max_n: 4,
            lowercase: true,
            max_features: 10000,
        }
    }
}

/// Character n-gram tokenizer
#[derive(Debug)]
pub struct CharNGramTokenizer {
    config: NGramConfig,
}

impl CharNGramTokenizer {
    /// Create a new tokenizer with default config
    pub fn new() -> Self {
        Self {
            config: NGramConfig::default(),
        }
    }

    /// Create a tokenizer with custom config
    pub fn with_config(config: NGramConfig) -> Self {
        Self { config }
    }

    /// Extract n-grams from input and return frequency map
    pub fn extract(&self, input: &str) -> NGramFeatures {
        let text = if self.config.lowercase {
            input.to_lowercase()
        } else {
            input.to_string()
        };

        let chars: Vec<char> = text.chars().collect();
        let mut features = FxHashMap::default();
        let mut total_count = 0usize;

        // Extract n-grams of each size
        for n in self.config.min_n..=self.config.max_n {
            if chars.len() < n {
                continue;
            }

            for window in chars.windows(n) {
                let ngram: String = window.iter().collect();
                let hash = fast_hash(&ngram);
                *features.entry(hash).or_insert(0u32) += 1;
                total_count += 1;

                // Limit features to prevent memory explosion
                if features.len() >= self.config.max_features {
                    break;
                }
            }
        }

        NGramFeatures {
            features,
            total_count,
        }
    }

    /// Extract n-grams and return as sorted vector (for comparison)
    pub fn extract_sorted(&self, input: &str) -> Vec<(u64, u32)> {
        let features = self.extract(input);
        let mut vec: Vec<_> = features.features.into_iter().collect();
        vec.sort_by_key(|b| std::cmp::Reverse(b.1)); // Sort by frequency descending
        vec
    }
}

impl Default for CharNGramTokenizer {
    fn default() -> Self {
        Self::new()
    }
}

/// N-gram feature set with frequencies
#[derive(Debug, Clone)]
pub struct NGramFeatures {
    /// Hash -> count mapping
    pub features: FxHashMap<u64, u32>,
    /// Total n-gram count
    pub total_count: usize,
}

impl NGramFeatures {
    /// Create empty features
    pub fn empty() -> Self {
        Self {
            features: FxHashMap::default(),
            total_count: 0,
        }
    }

    /// Get the frequency of a specific n-gram hash
    pub fn get(&self, hash: u64) -> u32 {
        self.features.get(&hash).copied().unwrap_or(0)
    }

    /// Get normalized frequency (0.0 - 1.0)
    pub fn normalized(&self, hash: u64) -> f32 {
        if self.total_count == 0 {
            return 0.0;
        }
        self.get(hash) as f32 / self.total_count as f32
    }

    /// Calculate Jaccard similarity with another feature set
    pub fn jaccard_similarity(&self, other: &NGramFeatures) -> f32 {
        if self.features.is_empty() && other.features.is_empty() {
            return 1.0;
        }
        if self.features.is_empty() || other.features.is_empty() {
            return 0.0;
        }

        let mut intersection = 0u32;
        let mut union = 0u32;

        for (hash, count) in &self.features {
            let other_count = other.get(*hash);
            intersection += (*count).min(other_count);
            union += (*count).max(other_count);
        }

        // Add features only in 'other'
        for (hash, count) in &other.features {
            if !self.features.contains_key(hash) {
                union += *count;
            }
        }

        if union == 0 {
            0.0
        } else {
            intersection as f32 / union as f32
        }
    }

    /// Calculate cosine similarity with another feature set
    pub fn cosine_similarity(&self, other: &NGramFeatures) -> f32 {
        if self.features.is_empty() || other.features.is_empty() {
            return 0.0;
        }

        let mut dot_product = 0.0f32;
        let mut norm_a = 0.0f32;
        let mut norm_b = 0.0f32;

        for (hash, count) in &self.features {
            let a = *count as f32;
            norm_a += a * a;

            if let Some(other_count) = other.features.get(hash) {
                dot_product += a * (*other_count as f32);
            }
        }

        for count in other.features.values() {
            let b = *count as f32;
            norm_b += b * b;
        }

        let denominator = norm_a.sqrt() * norm_b.sqrt();
        if denominator == 0.0 {
            0.0
        } else {
            dot_product / denominator
        }
    }
}

/// Fast hash function for n-grams
fn fast_hash(s: &str) -> u64 {
    let mut hasher = rustc_hash::FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ngram_extraction() {
        let tokenizer = CharNGramTokenizer::new();
        let features = tokenizer.extract("SELECT");

        // Should have n-grams of sizes 2, 3, 4
        // "select" lowercased: se, el, le, ec, ct, sel, ele, lec, ect, sele, elec, lect
        assert!(!features.features.is_empty());
        assert!(features.total_count > 0);
    }

    #[test]
    fn test_case_insensitivity() {
        let tokenizer = CharNGramTokenizer::new();
        let upper = tokenizer.extract("SELECT");
        let lower = tokenizer.extract("select");
        let mixed = tokenizer.extract("SeLeCt");

        // All should produce the same features
        assert_eq!(upper.features, lower.features);
        assert_eq!(upper.features, mixed.features);
    }

    #[test]
    fn test_jaccard_similarity() {
        let tokenizer = CharNGramTokenizer::new();

        let a = tokenizer.extract("SELECT FROM");
        let b = tokenizer.extract("SELECT FROM");
        assert!((a.jaccard_similarity(&b) - 1.0).abs() < 0.001);

        let c = tokenizer.extract("hello world");
        let similarity = a.jaccard_similarity(&c);
        assert!(similarity < 0.5); // Should be dissimilar
    }

    #[test]
    fn test_cosine_similarity() {
        let tokenizer = CharNGramTokenizer::new();

        let a = tokenizer.extract("UNION SELECT");
        let b = tokenizer.extract("union select password");

        // Should have high similarity due to shared n-grams
        let similarity = a.cosine_similarity(&b);
        assert!(similarity > 0.3);
    }

    #[test]
    fn test_obfuscation_detection() {
        let tokenizer = CharNGramTokenizer::new();

        // Original
        let original = tokenizer.extract("SELECT * FROM users");
        // Obfuscated with comments
        let obfuscated = tokenizer.extract("SELECT/**/*/**/FROM/**/users");

        // Should still have significant overlap due to shared n-grams
        let similarity = original.jaccard_similarity(&obfuscated);
        assert!(similarity > 0.2);
    }
}
