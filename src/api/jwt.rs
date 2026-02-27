//! JWT Security Inspector
//!
//! Detects JWT-specific attacks:
//! - Algorithm confusion (none, HS256 when expecting RS256)
//! - Expired tokens
//! - Suspicious claims
//! - Token injection patterns

use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;

use crate::detection::Detection;
use crate::rules::AttackType;

/// JWT security configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Block tokens with "none" algorithm
    pub block_none_algorithm: bool,
    /// Block tokens with symmetric algorithms (HS256, etc.) when RS256 expected
    pub block_symmetric_algorithms: bool,
    /// Check for expired tokens
    pub check_expiration: bool,
    /// Allowed algorithms (if set, only these are accepted)
    pub allowed_algorithms: Vec<String>,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            block_none_algorithm: true,
            block_symmetric_algorithms: false,
            check_expiration: true,
            allowed_algorithms: vec![],
        }
    }
}

/// Types of JWT violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtViolation {
    /// Algorithm "none" used
    NoneAlgorithm,
    /// Weak/disallowed algorithm
    WeakAlgorithm { algorithm: String },
    /// Token expired
    Expired,
    /// Invalid token format
    InvalidFormat,
    /// Suspicious claim value
    SuspiciousClaim { claim: String, value: String },
}

/// JWT security inspector
pub struct JwtInspector {
    config: JwtConfig,
}

static JWT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // JWT format: base64.base64.base64
    Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").unwrap()
});

impl JwtInspector {
    /// Create a new JWT inspector
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    /// Inspect Authorization header for JWT issues
    pub fn inspect(&self, auth_header: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Extract JWT from header
        let token = if let Some(bearer) = auth_header.strip_prefix("Bearer ") {
            bearer.trim()
        } else if JWT_PATTERN.is_match(auth_header) {
            auth_header.trim()
        } else {
            return detections;
        };

        // Parse JWT parts
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return detections;
        }

        // Decode header
        if let Some(header) = decode_jwt_part(parts[0]) {
            detections.extend(self.check_header(&header, token));
        }

        // Decode payload
        if let Some(payload) = decode_jwt_part(parts[1]) {
            detections.extend(self.check_payload(&payload, token));
        }

        detections
    }

    /// Check JWT header for security issues
    fn check_header(&self, header: &str, token: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check for "none" algorithm
        if self.config.block_none_algorithm
            && (header.contains(r#""alg":"none""#)
                || header.contains(r#""alg": "none""#)
                || header.contains(r#""alg":"None""#)
                || header.contains(r#""alg":"NONE""#))
        {
            detections.push(Detection {
                rule_id: 98200,
                rule_name: "JWT None Algorithm Attack".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: truncate(token, 50),
                location: "header:Authorization".to_string(),
                base_score: 9,
                tags: vec![
                    "jwt".to_string(),
                    "algorithm".to_string(),
                    "none".to_string(),
                ],
            });
        }

        // Check for weak algorithms
        let weak_algs = ["HS256", "HS384", "HS512"];
        if self.config.block_symmetric_algorithms {
            for alg in weak_algs {
                if header.contains(&format!(r#""alg":"{}""#, alg))
                    || header.contains(&format!(r#""alg": "{}""#, alg))
                {
                    detections.push(Detection {
                        rule_id: 98201,
                        rule_name: format!("JWT Weak Algorithm: {}", alg),
                        attack_type: AttackType::ProtocolAttack,
                        matched_value: truncate(token, 50),
                        location: "header:Authorization".to_string(),
                        base_score: 6,
                        tags: vec![
                            "jwt".to_string(),
                            "algorithm".to_string(),
                            "weak".to_string(),
                        ],
                    });
                    break;
                }
            }
        }

        // Check allowed algorithms
        if !self.config.allowed_algorithms.is_empty() {
            let mut found_allowed = false;
            for alg in &self.config.allowed_algorithms {
                if header.contains(&format!(r#""alg":"{}""#, alg))
                    || header.contains(&format!(r#""alg": "{}""#, alg))
                {
                    found_allowed = true;
                    break;
                }
            }
            if !found_allowed {
                detections.push(Detection {
                    rule_id: 98202,
                    rule_name: "JWT Disallowed Algorithm".to_string(),
                    attack_type: AttackType::ProtocolAttack,
                    matched_value: truncate(token, 50),
                    location: "header:Authorization".to_string(),
                    base_score: 7,
                    tags: vec!["jwt".to_string(), "algorithm".to_string()],
                });
            }
        }

        detections
    }

    /// Check JWT payload for security issues
    fn check_payload(&self, payload: &str, token: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check for suspicious claims
        let suspicious_patterns = [
            (r#""admin":true"#, "admin claim"),
            (r#""admin": true"#, "admin claim"),
            (r#""role":"admin""#, "admin role"),
            (r#""role": "admin""#, "admin role"),
            (r#""is_admin":true"#, "is_admin claim"),
            (r#""isAdmin":true"#, "isAdmin claim"),
        ];

        for (pattern, name) in suspicious_patterns {
            if payload.contains(pattern) {
                detections.push(Detection {
                    rule_id: 98203,
                    rule_name: format!("JWT Suspicious Claim: {}", name),
                    attack_type: AttackType::ProtocolAttack,
                    matched_value: truncate(token, 50),
                    location: "header:Authorization".to_string(),
                    base_score: 5,
                    tags: vec!["jwt".to_string(), "claim".to_string()],
                });
            }
        }

        // Check for exp claim (expiration)
        if self.config.check_expiration {
            // Look for exp claim and check if it's in the past
            if let Some(exp) = extract_exp_claim(payload) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                if exp < now {
                    detections.push(Detection {
                        rule_id: 98204,
                        rule_name: "JWT Expired Token".to_string(),
                        attack_type: AttackType::ProtocolAttack,
                        matched_value: truncate(token, 50),
                        location: "header:Authorization".to_string(),
                        base_score: 4,
                        tags: vec!["jwt".to_string(), "expired".to_string()],
                    });
                }
            }
        }

        // Check for injection in claims
        let injection_patterns = ["<script", "javascript:", "' OR ", "\" OR ", "; DROP "];

        for pattern in injection_patterns {
            if payload.to_lowercase().contains(&pattern.to_lowercase()) {
                detections.push(Detection {
                    rule_id: 98205,
                    rule_name: "JWT Claim Injection".to_string(),
                    attack_type: AttackType::SqlInjection,
                    matched_value: truncate(token, 50),
                    location: "header:Authorization".to_string(),
                    base_score: 8,
                    tags: vec!["jwt".to_string(), "injection".to_string()],
                });
                break;
            }
        }

        detections
    }
}

/// Decode a JWT part (base64url to string)
fn decode_jwt_part(part: &str) -> Option<String> {
    // JWT uses base64url encoding
    let padded = match part.len() % 4 {
        2 => format!("{}==", part),
        3 => format!("{}=", part),
        _ => part.to_string(),
    };

    // Replace URL-safe characters
    let standard = padded.replace('-', "+").replace('_', "/");

    base64::engine::general_purpose::STANDARD
        .decode(&standard)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Extract exp claim from payload
fn extract_exp_claim(payload: &str) -> Option<u64> {
    // Simple extraction without full JSON parsing
    let exp_patterns = [r#""exp":"#, r#""exp": "#];

    for pattern in exp_patterns {
        if let Some(start) = payload.find(pattern) {
            let after_key = &payload[start + pattern.len()..];
            let end = after_key
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after_key.len());
            if let Ok(exp) = after_key[..end].parse::<u64>() {
                return Some(exp);
            }
        }
    }

    None
}

/// Truncate a string for display
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_algorithm_detection() {
        let inspector = JwtInspector::new(JwtConfig::default());

        // JWT with alg: none
        // Header: {"alg":"none","typ":"JWT"}
        // Payload: {"sub":"1234567890","name":"John Doe"}
        let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.";

        let detections = inspector.inspect(&format!("Bearer {}", none_jwt));
        assert!(detections.iter().any(|d| d.rule_id == 98200));
    }

    #[test]
    fn test_weak_algorithm_detection() {
        let config = JwtConfig {
            block_symmetric_algorithms: true,
            ..Default::default()
        };
        let inspector = JwtInspector::new(config);

        // JWT with alg: HS256
        // Header: {"alg":"HS256","typ":"JWT"}
        let hs256_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

        let detections = inspector.inspect(&format!("Bearer {}", hs256_jwt));
        assert!(detections.iter().any(|d| d.rule_id == 98201));
    }

    #[test]
    fn test_normal_jwt() {
        let inspector = JwtInspector::new(JwtConfig::default());

        // Normal RS256 JWT
        // Header: {"alg":"RS256","typ":"JWT"}
        let rs256_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature";

        let detections = inspector.inspect(&format!("Bearer {}", rs256_jwt));
        // Should not detect none algorithm or weak algorithm
        assert!(!detections
            .iter()
            .any(|d| d.rule_id == 98200 || d.rule_id == 98201));
    }

    #[test]
    fn test_jwt_part_decoding() {
        // {"alg":"none"}
        let decoded = decode_jwt_part("eyJhbGciOiJub25lIn0");
        assert!(decoded.is_some());
        assert!(decoded.unwrap().contains("none"));
    }

    #[test]
    fn test_exp_extraction() {
        let payload = r#"{"sub":"123","exp":1700000000}"#;
        let exp = extract_exp_claim(payload);
        assert_eq!(exp, Some(1700000000));
    }
}
