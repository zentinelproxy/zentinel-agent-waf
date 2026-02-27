//! Streaming Body Inspection
//!
//! Provides incremental body inspection using a sliding window approach.
//! This ensures constant memory usage regardless of body size while still
//! detecting patterns that may span chunk boundaries.
//!
//! # Architecture
//!
//! Instead of buffering the entire body (up to 1MB), streaming inspection:
//! 1. Maintains a small overlap buffer (default 256 bytes) from previous chunks
//! 2. Inspects each chunk with the overlap prepended
//! 3. Accumulates detections and scores across chunks
//! 4. Supports early termination when score threshold is exceeded
//!
//! # Memory Usage
//!
//! - Traditional buffering: O(body_size) - up to 1MB per request
//! - Streaming: O(overlap_size) - typically 256 bytes per request

use std::collections::VecDeque;
use std::time::Instant;

use crate::config::StreamingConfig;
use crate::detection::{AnomalyScore, Detection};

/// State for streaming body inspection
#[derive(Debug)]
pub struct StreamingInspector {
    /// Overlap buffer containing last N bytes from previous chunk
    overlap_buffer: VecDeque<u8>,
    /// Maximum overlap size (from config)
    max_overlap: usize,
    /// Accumulated anomaly score across all chunks
    accumulated_score: AnomalyScore,
    /// All detections found across chunks
    detections: Vec<Detection>,
    /// Total bytes processed so far
    bytes_processed: usize,
    /// When this inspector was created
    created_at: Instant,
    /// Whether inspection was terminated early due to high score
    terminated_early: bool,
    /// Early termination threshold
    early_termination_threshold: u32,
}

impl StreamingInspector {
    /// Create a new streaming inspector with the given configuration
    pub fn new(config: &StreamingConfig) -> Self {
        Self {
            overlap_buffer: VecDeque::with_capacity(config.window_overlap),
            max_overlap: config.window_overlap,
            accumulated_score: AnomalyScore::default(),
            detections: Vec::new(),
            bytes_processed: 0,
            created_at: Instant::now(),
            terminated_early: false,
            early_termination_threshold: config.early_termination_threshold,
        }
    }

    /// Process a chunk of body data
    ///
    /// Returns the text to inspect (overlap + chunk) and updates internal state.
    /// If early termination threshold was exceeded, returns None.
    pub fn prepare_chunk(&mut self, chunk: &[u8]) -> Option<String> {
        if self.terminated_early {
            return None;
        }

        // Build inspection text: overlap buffer + new chunk
        let mut inspection_bytes = Vec::with_capacity(self.overlap_buffer.len() + chunk.len());
        inspection_bytes.extend(self.overlap_buffer.iter());
        inspection_bytes.extend_from_slice(chunk);

        // Convert to string for inspection (lossy - invalid UTF-8 becomes replacement char)
        let inspection_text = String::from_utf8_lossy(&inspection_bytes).into_owned();

        // Update overlap buffer with last N bytes of chunk
        self.update_overlap(chunk);

        // Track bytes processed
        self.bytes_processed += chunk.len();

        Some(inspection_text)
    }

    /// Update the overlap buffer with the last N bytes of the chunk
    fn update_overlap(&mut self, chunk: &[u8]) {
        self.overlap_buffer.clear();

        // Only keep the last max_overlap bytes
        let start = chunk.len().saturating_sub(self.max_overlap);
        for &byte in &chunk[start..] {
            self.overlap_buffer.push_back(byte);
        }
    }

    /// Add detections from inspecting a chunk
    ///
    /// Returns true if inspection should continue, false if early termination triggered.
    /// Uses default weights (1.0) for body content - caller can use more specific weights
    /// by calling add_detections_with_weights instead.
    pub fn add_detections(&mut self, new_detections: Vec<Detection>) -> bool {
        self.add_detections_with_weights(new_detections, 1.0, 1.0)
    }

    /// Add detections from inspecting a chunk with specific weights
    ///
    /// Returns true if inspection should continue, false if early termination triggered.
    pub fn add_detections_with_weights(
        &mut self,
        new_detections: Vec<Detection>,
        location_weight: f32,
        severity_weight: f32,
    ) -> bool {
        // Deduplicate detections by rule_id (same rule might match in overlap region)
        for detection in new_detections {
            if !self
                .detections
                .iter()
                .any(|d| d.rule_id == detection.rule_id)
            {
                self.accumulated_score
                    .add(&detection, location_weight, severity_weight);
                self.detections.push(detection);
            }
        }

        // Check for early termination
        if self.accumulated_score.total >= self.early_termination_threshold {
            self.terminated_early = true;
            return false;
        }

        true
    }

    /// Get whether this inspector has been terminated early
    pub fn is_terminated(&self) -> bool {
        self.terminated_early
    }

    /// Get all detections found so far
    pub fn detections(&self) -> &[Detection] {
        &self.detections
    }

    /// Get the accumulated anomaly score
    pub fn score(&self) -> &AnomalyScore {
        &self.accumulated_score
    }

    /// Consume the inspector and return final results
    pub fn finalize(self) -> StreamingResult {
        StreamingResult {
            detections: self.detections,
            score: self.accumulated_score,
            bytes_processed: self.bytes_processed,
            terminated_early: self.terminated_early,
            duration: self.created_at.elapsed(),
        }
    }

    /// Get how long this inspector has been active
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Get total bytes processed
    pub fn bytes_processed(&self) -> usize {
        self.bytes_processed
    }
}

/// Result of streaming inspection
#[derive(Debug)]
pub struct StreamingResult {
    /// All detections found
    pub detections: Vec<Detection>,
    /// Accumulated anomaly score
    pub score: AnomalyScore,
    /// Total bytes inspected
    pub bytes_processed: usize,
    /// Whether inspection was terminated early
    pub terminated_early: bool,
    /// Time spent inspecting
    pub duration: std::time::Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::AttackType;

    fn test_config() -> StreamingConfig {
        StreamingConfig {
            enabled: true,
            window_overlap: 16,
            early_termination_threshold: 50,
            cleanup_timeout_secs: 300,
            min_streaming_size: 100,
        }
    }

    fn make_detection(rule_id: u32, score: u32) -> Detection {
        Detection {
            rule_id,
            rule_name: format!("Test Rule {}", rule_id),
            attack_type: AttackType::SqlInjection,
            matched_value: "test".to_string(),
            location: "body".to_string(),
            base_score: score,
            tags: vec![],
        }
    }

    #[test]
    fn test_streaming_basic() {
        let config = test_config();
        let mut inspector = StreamingInspector::new(&config);

        // First chunk
        let chunk1 = b"Hello World";
        let text1 = inspector.prepare_chunk(chunk1).unwrap();
        assert_eq!(text1, "Hello World");

        // Second chunk should include overlap
        let chunk2 = b" from Rust";
        let text2 = inspector.prepare_chunk(chunk2).unwrap();
        // Overlap should be "Hello World" (last 16 bytes, but chunk is only 11)
        assert!(text2.starts_with("Hello World"));
        assert!(text2.ends_with(" from Rust"));
    }

    #[test]
    fn test_overlap_buffer() {
        let config = StreamingConfig {
            window_overlap: 8,
            ..test_config()
        };
        let mut inspector = StreamingInspector::new(&config);

        // Process a long chunk (16 bytes: "0123456789ABCDEF")
        let chunk1 = b"0123456789ABCDEF";
        inspector.prepare_chunk(chunk1).unwrap();

        // Next chunk should have last 8 bytes as overlap ("89ABCDEF")
        let chunk2 = b"XYZ";
        let text2 = inspector.prepare_chunk(chunk2).unwrap();
        assert_eq!(text2, "89ABCDEFXYZ");
    }

    #[test]
    fn test_detection_accumulation() {
        let config = test_config();
        let mut inspector = StreamingInspector::new(&config);

        inspector.prepare_chunk(b"test").unwrap();

        // Add some detections
        let detections1 = vec![make_detection(1001, 10)];
        assert!(inspector.add_detections(detections1));
        assert_eq!(inspector.detections().len(), 1);
        assert_eq!(inspector.score().total, 10);

        // Add more detections
        let detections2 = vec![make_detection(1002, 15)];
        assert!(inspector.add_detections(detections2));
        assert_eq!(inspector.detections().len(), 2);
        assert_eq!(inspector.score().total, 25);
    }

    #[test]
    fn test_detection_deduplication() {
        let config = test_config();
        let mut inspector = StreamingInspector::new(&config);

        inspector.prepare_chunk(b"test").unwrap();

        // Add detection
        let detections1 = vec![make_detection(1001, 10)];
        inspector.add_detections(detections1);

        // Try to add same detection again (e.g., from overlap region)
        let detections2 = vec![make_detection(1001, 10)];
        inspector.add_detections(detections2);

        // Should still only have one detection
        assert_eq!(inspector.detections().len(), 1);
        assert_eq!(inspector.score().total, 10);
    }

    #[test]
    fn test_early_termination() {
        let config = StreamingConfig {
            early_termination_threshold: 30,
            ..test_config()
        };
        let mut inspector = StreamingInspector::new(&config);

        inspector.prepare_chunk(b"test").unwrap();

        // Add detections that exceed threshold
        let detections = vec![make_detection(1001, 15), make_detection(1002, 20)];
        let should_continue = inspector.add_detections(detections);

        assert!(!should_continue);
        assert!(inspector.is_terminated());

        // Further chunks should return None
        assert!(inspector.prepare_chunk(b"more data").is_none());
    }

    #[test]
    fn test_finalize() {
        let config = test_config();
        let mut inspector = StreamingInspector::new(&config);

        inspector.prepare_chunk(b"chunk1").unwrap();
        inspector.prepare_chunk(b"chunk2").unwrap();
        inspector.add_detections(vec![make_detection(1001, 10)]);

        let result = inspector.finalize();

        assert_eq!(result.detections.len(), 1);
        assert_eq!(result.score.total, 10);
        assert_eq!(result.bytes_processed, 12);
        assert!(!result.terminated_early);
    }
}
