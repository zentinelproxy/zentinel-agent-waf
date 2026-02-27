//! Request Fingerprinting
//!
//! Detects anomalous requests based on structural features.
//! This module learns what "normal" requests look like for each endpoint
//! and flags requests that deviate significantly from the baseline.
//!
//! # Features Analyzed
//!
//! - Header count and presence patterns
//! - Header ordering (browsers have consistent patterns)
//! - Parameter count and entropy
//! - Path structure (depth, segments)
//! - Content-Type patterns
//! - Query string characteristics

use rustc_hash::FxHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// Structural fingerprint of a request
#[derive(Debug, Clone)]
pub struct RequestFingerprint {
    /// Number of headers
    pub header_count: u8,
    /// Hash of header names in order (browser fingerprint)
    pub header_order_hash: u64,
    /// Set of present header name hashes
    pub header_presence: Vec<u64>,
    /// HTTP method
    pub method: HttpMethod,
    /// Content-Type category
    pub content_type: ContentType,
    /// Path depth (number of segments)
    pub path_depth: u8,
    /// Query parameter count
    pub param_count: u8,
    /// Shannon entropy of query string
    pub query_entropy: f32,
    /// Total query string length
    pub query_length: u16,
    /// Whether body is present
    pub has_body: bool,
    /// Body length category
    pub body_size_category: BodySizeCategory,
}

impl RequestFingerprint {
    /// Create a fingerprint from request data
    pub fn from_request(
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HashMap<String, Vec<String>>,
        body_size: Option<usize>,
    ) -> Self {
        // Parse method
        let method = HttpMethod::from_str(method);

        // Analyze headers
        let header_count = headers.len().min(255) as u8;
        let mut header_names: Vec<_> = headers.keys().collect();
        header_names.sort(); // Normalize order for presence hash

        let header_order_hash = {
            let mut hasher = FxHasher::default();
            for name in &header_names {
                name.to_lowercase().hash(&mut hasher);
            }
            hasher.finish()
        };

        let header_presence: Vec<u64> = header_names
            .iter()
            .map(|name| {
                let mut hasher = FxHasher::default();
                name.to_lowercase().hash(&mut hasher);
                hasher.finish()
            })
            .collect();

        // Analyze content type
        let content_type = headers
            .get("content-type")
            .or_else(|| headers.get("Content-Type"))
            .and_then(|v| v.first())
            .map(|ct| ContentType::from_str(ct))
            .unwrap_or(ContentType::None);

        // Analyze path
        let path_depth = path.split('/').filter(|s| !s.is_empty()).count().min(255) as u8;

        // Analyze query string
        let (param_count, query_entropy, query_length) = if let Some(q) = query {
            let count = q.matches('&').count() + if q.is_empty() { 0 } else { 1 };
            let entropy = shannon_entropy(q);
            (count.min(255) as u8, entropy, q.len().min(65535) as u16)
        } else {
            (0, 0.0, 0)
        };

        // Analyze body
        let has_body = body_size.map(|s| s > 0).unwrap_or(false);
        let body_size_category = body_size
            .map(BodySizeCategory::from_size)
            .unwrap_or(BodySizeCategory::None);

        Self {
            header_count,
            header_order_hash,
            header_presence,
            method,
            content_type,
            path_depth,
            param_count,
            query_entropy,
            query_length,
            has_body,
            body_size_category,
        }
    }
}

/// HTTP method categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Other,
}

impl HttpMethod {
    fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            _ => Self::Other,
        }
    }
}

/// Content-Type categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    None,
    FormUrlEncoded,
    MultipartForm,
    Json,
    Xml,
    Html,
    Text,
    Binary,
    Other,
}

impl ContentType {
    fn from_str(s: &str) -> Self {
        let lower = s.to_lowercase();
        if lower.contains("application/x-www-form-urlencoded") {
            Self::FormUrlEncoded
        } else if lower.contains("multipart/form-data") {
            Self::MultipartForm
        } else if lower.contains("application/json") || lower.contains("+json") {
            Self::Json
        } else if lower.contains("application/xml")
            || lower.contains("+xml")
            || lower.contains("text/xml")
        {
            Self::Xml
        } else if lower.contains("text/html") {
            Self::Html
        } else if lower.contains("text/") {
            Self::Text
        } else if lower.contains("application/octet-stream") {
            Self::Binary
        } else {
            Self::Other
        }
    }
}

/// Body size categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodySizeCategory {
    None,
    Tiny,   // < 256 bytes
    Small,  // < 4KB
    Medium, // < 64KB
    Large,  // < 1MB
    Huge,   // >= 1MB
}

impl BodySizeCategory {
    fn from_size(size: usize) -> Self {
        match size {
            0 => Self::None,
            1..=255 => Self::Tiny,
            256..=4095 => Self::Small,
            4096..=65535 => Self::Medium,
            65536..=1048575 => Self::Large,
            _ => Self::Huge,
        }
    }
}

/// Learned baseline for an endpoint
#[derive(Debug, Clone)]
pub struct EndpointBaseline {
    /// Expected header count range
    pub header_count_range: (u8, u8),
    /// Common header order hashes
    pub common_header_orders: Vec<u64>,
    /// Expected headers (hash -> frequency 0.0-1.0)
    pub expected_headers: HashMap<u64, f32>,
    /// Expected methods
    pub expected_methods: Vec<HttpMethod>,
    /// Expected content types
    pub expected_content_types: Vec<ContentType>,
    /// Expected param count range
    pub param_count_range: (u8, u8),
    /// Expected query entropy range
    pub query_entropy_range: (f32, f32),
    /// Number of samples used to build this baseline
    pub sample_count: usize,
}

impl Default for EndpointBaseline {
    fn default() -> Self {
        Self {
            header_count_range: (0, 50),
            common_header_orders: Vec::new(),
            expected_headers: HashMap::new(),
            expected_methods: vec![HttpMethod::Get, HttpMethod::Post],
            expected_content_types: vec![
                ContentType::None,
                ContentType::FormUrlEncoded,
                ContentType::Json,
            ],
            param_count_range: (0, 20),
            query_entropy_range: (0.0, 5.0),
            sample_count: 0,
        }
    }
}

impl EndpointBaseline {
    /// Update baseline with a new fingerprint
    pub fn learn(&mut self, fingerprint: &RequestFingerprint) {
        self.sample_count += 1;

        // Update header count range
        self.header_count_range.0 = self.header_count_range.0.min(fingerprint.header_count);
        self.header_count_range.1 = self.header_count_range.1.max(fingerprint.header_count);

        // Track header order
        if !self
            .common_header_orders
            .contains(&fingerprint.header_order_hash)
            && self.common_header_orders.len() < 100
        {
            self.common_header_orders
                .push(fingerprint.header_order_hash);
        }

        // Track expected headers
        for &header_hash in &fingerprint.header_presence {
            let freq = self.expected_headers.entry(header_hash).or_insert(0.0);
            // Exponential moving average
            *freq = *freq * 0.9 + 0.1;
        }

        // Track methods
        if !self.expected_methods.contains(&fingerprint.method) {
            self.expected_methods.push(fingerprint.method);
        }

        // Track content types
        if !self
            .expected_content_types
            .contains(&fingerprint.content_type)
        {
            self.expected_content_types.push(fingerprint.content_type);
        }

        // Update param count range
        self.param_count_range.0 = self.param_count_range.0.min(fingerprint.param_count);
        self.param_count_range.1 = self.param_count_range.1.max(fingerprint.param_count);

        // Update entropy range
        self.query_entropy_range.0 = self.query_entropy_range.0.min(fingerprint.query_entropy);
        self.query_entropy_range.1 = self.query_entropy_range.1.max(fingerprint.query_entropy);
    }
}

/// Baseline model for all endpoints
#[derive(Debug)]
pub struct FingerprintBaseline {
    /// Per-endpoint baselines
    endpoints: HashMap<String, EndpointBaseline>,
    /// Global baseline (for unknown endpoints)
    global: EndpointBaseline,
    /// Minimum samples before using endpoint-specific baseline
    min_samples: usize,
}

impl FingerprintBaseline {
    /// Create a new baseline model
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
            global: EndpointBaseline::default(),
            min_samples: 10,
        }
    }

    /// Learn from a request fingerprint
    pub fn learn(&mut self, endpoint: &str, fingerprint: &RequestFingerprint) {
        // Update endpoint-specific baseline
        let baseline = self.endpoints.entry(endpoint.to_string()).or_default();
        baseline.learn(fingerprint);

        // Update global baseline
        self.global.learn(fingerprint);
    }

    /// Calculate anomaly score for a fingerprint
    pub fn anomaly_score(&self, endpoint: &str, fingerprint: &RequestFingerprint) -> AnomalyResult {
        let baseline = self
            .endpoints
            .get(endpoint)
            .filter(|b| b.sample_count >= self.min_samples)
            .unwrap_or(&self.global);

        let mut total_score = 0.0f32;
        let mut anomalies = Vec::new();

        // Check header count
        if fingerprint.header_count < baseline.header_count_range.0
            || fingerprint.header_count > baseline.header_count_range.1
        {
            total_score += 0.1;
            anomalies.push(AnomalyFactor::UnusualHeaderCount);
        }

        // Check header order (bot detection)
        if !baseline.common_header_orders.is_empty()
            && !baseline
                .common_header_orders
                .contains(&fingerprint.header_order_hash)
        {
            total_score += 0.15;
            anomalies.push(AnomalyFactor::UnusualHeaderOrder);
        }

        // Check method
        if !baseline.expected_methods.contains(&fingerprint.method) {
            total_score += 0.2;
            anomalies.push(AnomalyFactor::UnexpectedMethod);
        }

        // Check content type
        if fingerprint.content_type != ContentType::None
            && !baseline
                .expected_content_types
                .contains(&fingerprint.content_type)
        {
            total_score += 0.15;
            anomalies.push(AnomalyFactor::UnexpectedContentType);
        }

        // Check param count
        if fingerprint.param_count < baseline.param_count_range.0
            || fingerprint.param_count > baseline.param_count_range.1 + 5
        {
            total_score += 0.1;
            anomalies.push(AnomalyFactor::UnusualParamCount);
        }

        // Check query entropy (high entropy = suspicious)
        if fingerprint.query_entropy > baseline.query_entropy_range.1 + 1.0 {
            total_score += 0.2;
            anomalies.push(AnomalyFactor::HighQueryEntropy);
        }

        // Check for missing expected headers
        let missing_expected = baseline
            .expected_headers
            .iter()
            .filter(|(hash, freq)| **freq > 0.8 && !fingerprint.header_presence.contains(hash))
            .count();
        if missing_expected > 2 {
            total_score += 0.1;
            anomalies.push(AnomalyFactor::MissingExpectedHeaders);
        }

        AnomalyResult {
            score: total_score.min(1.0),
            factors: anomalies,
            baseline_samples: baseline.sample_count,
        }
    }

    /// Get the number of learned endpoints
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Get sample count for an endpoint
    pub fn samples_for_endpoint(&self, endpoint: &str) -> usize {
        self.endpoints
            .get(endpoint)
            .map(|b| b.sample_count)
            .unwrap_or(0)
    }
}

impl Default for FingerprintBaseline {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of anomaly detection
#[derive(Debug, Clone)]
pub struct AnomalyResult {
    /// Overall anomaly score (0.0 - 1.0)
    pub score: f32,
    /// Factors contributing to the anomaly score
    pub factors: Vec<AnomalyFactor>,
    /// Number of baseline samples used for comparison
    pub baseline_samples: usize,
}

impl AnomalyResult {
    /// Check if this request should be flagged
    pub fn is_anomalous(&self, threshold: f32) -> bool {
        self.score >= threshold
    }
}

/// Factors that contribute to anomaly score
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyFactor {
    /// Unusual number of headers
    UnusualHeaderCount,
    /// Header order differs from learned patterns
    UnusualHeaderOrder,
    /// Unexpected HTTP method for this endpoint
    UnexpectedMethod,
    /// Unexpected content type
    UnexpectedContentType,
    /// Unusual number of query parameters
    UnusualParamCount,
    /// Query string has unusually high entropy
    HighQueryEntropy,
    /// Missing headers that are usually present
    MissingExpectedHeaders,
}

/// Calculate Shannon entropy of a string
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts = HashMap::new();
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0usize) += 1;
    }

    let len = s.len() as f32;
    let mut entropy = 0.0f32;

    for &count in char_counts.values() {
        let p = count as f32 / len;
        entropy -= p * p.log2();
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(names: &[&str]) -> HashMap<String, Vec<String>> {
        names
            .iter()
            .map(|n| (n.to_string(), vec!["value".to_string()]))
            .collect()
    }

    #[test]
    fn test_fingerprint_creation() {
        let headers = make_headers(&["Host", "User-Agent", "Accept"]);
        let fp =
            RequestFingerprint::from_request("GET", "/api/users", Some("id=1"), &headers, None);

        assert_eq!(fp.method, HttpMethod::Get);
        assert_eq!(fp.header_count, 3);
        assert_eq!(fp.path_depth, 2);
        assert_eq!(fp.param_count, 1);
        assert!(!fp.has_body);
    }

    #[test]
    fn test_content_type_detection() {
        let headers = make_headers(&["Content-Type"]);
        let mut headers = headers;
        headers.insert(
            "Content-Type".to_string(),
            vec!["application/json".to_string()],
        );

        let fp = RequestFingerprint::from_request("POST", "/api", None, &headers, Some(100));
        assert_eq!(fp.content_type, ContentType::Json);
    }

    #[test]
    fn test_baseline_learning() {
        let mut baseline = FingerprintBaseline::new();
        baseline.min_samples = 2;

        // Learn normal requests
        let headers = make_headers(&["Host", "User-Agent", "Accept"]);
        for _ in 0..5 {
            let fp = RequestFingerprint::from_request(
                "GET",
                "/api/users",
                Some("page=1"),
                &headers,
                None,
            );
            baseline.learn("/api/users", &fp);
        }

        // Test normal request
        let normal_fp =
            RequestFingerprint::from_request("GET", "/api/users", Some("page=2"), &headers, None);
        let result = baseline.anomaly_score("/api/users", &normal_fp);
        assert!(result.score < 0.3);

        // Test anomalous request (different method)
        let anomalous_fp = RequestFingerprint::from_request(
            "DELETE",
            "/api/users",
            Some("page=1"),
            &headers,
            None,
        );
        let result = baseline.anomaly_score("/api/users", &anomalous_fp);
        assert!(result.factors.contains(&AnomalyFactor::UnexpectedMethod));
    }

    #[test]
    fn test_entropy_calculation() {
        // Low entropy (repeated characters)
        assert!(shannon_entropy("aaaaaaaaaa") < 1.0);

        // High entropy (random-looking)
        assert!(shannon_entropy("a1b2c3d4e5f6g7h8i9j0") > 3.0);
    }

    #[test]
    fn test_body_size_categories() {
        assert_eq!(BodySizeCategory::from_size(0), BodySizeCategory::None);
        assert_eq!(BodySizeCategory::from_size(100), BodySizeCategory::Tiny);
        assert_eq!(BodySizeCategory::from_size(1000), BodySizeCategory::Small);
        assert_eq!(BodySizeCategory::from_size(10000), BodySizeCategory::Medium);
        assert_eq!(BodySizeCategory::from_size(100000), BodySizeCategory::Large);
        assert_eq!(
            BodySizeCategory::from_size(10000000),
            BodySizeCategory::Huge
        );
    }
}
