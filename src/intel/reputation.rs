//! Reputation Types
//!
//! Data structures for IP and domain reputation tracking.

use serde::{Deserialize, Serialize};

/// IP address reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    /// Reputation score (0-100, higher = worse)
    pub score: u8,
    /// Category of threat
    pub category: String,
    /// Last time this IP was seen being malicious
    pub last_seen: Option<u64>, // Unix timestamp
    /// Number of reports
    pub reports: u32,
}

impl IpReputation {
    /// Create a new IP reputation entry
    pub fn new(score: u8, category: impl Into<String>) -> Self {
        Self {
            score,
            category: category.into(),
            last_seen: None,
            reports: 1,
        }
    }

    /// Create from scanner activity
    pub fn scanner() -> Self {
        Self::new(70, "scanner")
    }

    /// Create from spam activity
    pub fn spam() -> Self {
        Self::new(60, "spam")
    }

    /// Create from botnet activity
    pub fn botnet() -> Self {
        Self::new(90, "botnet")
    }

    /// Create from brute force activity
    pub fn brute_force() -> Self {
        Self::new(80, "brute_force")
    }

    /// Is this a high-risk IP?
    pub fn is_high_risk(&self) -> bool {
        self.score >= 80
    }

    /// Is this a medium-risk IP?
    pub fn is_medium_risk(&self) -> bool {
        self.score >= 50 && self.score < 80
    }

    /// Is this a low-risk IP?
    pub fn is_low_risk(&self) -> bool {
        self.score < 50
    }
}

/// Domain reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputation {
    /// Reputation score (0-100, higher = worse)
    pub score: u8,
    /// Category of threat
    pub category: String,
    /// First time this domain was seen
    pub first_seen: Option<u64>, // Unix timestamp
    /// Number of reports
    pub reports: u32,
}

impl DomainReputation {
    /// Create a new domain reputation entry
    pub fn new(score: u8, category: impl Into<String>) -> Self {
        Self {
            score,
            category: category.into(),
            first_seen: None,
            reports: 1,
        }
    }

    /// Create from phishing activity
    pub fn phishing() -> Self {
        Self::new(95, "phishing")
    }

    /// Create from malware hosting
    pub fn malware() -> Self {
        Self::new(90, "malware")
    }

    /// Create from C2 activity
    pub fn c2() -> Self {
        Self::new(100, "c2")
    }

    /// Create from spam activity
    pub fn spam() -> Self {
        Self::new(70, "spam")
    }

    /// Is this a high-risk domain?
    pub fn is_high_risk(&self) -> bool {
        self.score >= 80
    }
}

/// Reputation score calculation
#[derive(Debug, Clone, Copy, Default)]
pub struct ReputationScore {
    /// Overall score (0-100)
    pub overall: u8,
    /// IP-based component
    pub ip_score: u8,
    /// Domain-based component
    pub domain_score: u8,
    /// Behavioral component
    pub behavioral_score: u8,
}

impl ReputationScore {
    /// Calculate overall score from components
    pub fn calculate(ip_score: u8, domain_score: u8, behavioral_score: u8) -> Self {
        // Weighted average: IP 40%, Domain 30%, Behavioral 30%
        let overall = ((ip_score as u16 * 40
            + domain_score as u16 * 30
            + behavioral_score as u16 * 30)
            / 100) as u8;

        Self {
            overall,
            ip_score,
            domain_score,
            behavioral_score,
        }
    }

    /// Create from a single IP score
    pub fn from_ip(score: u8) -> Self {
        Self::calculate(score, 0, 0)
    }

    /// Create from a single domain score
    pub fn from_domain(score: u8) -> Self {
        Self::calculate(0, score, 0)
    }

    /// Is this overall a high-risk score?
    pub fn is_high_risk(&self) -> bool {
        self.overall >= 70
    }

    /// Is this overall a medium-risk score?
    pub fn is_medium_risk(&self) -> bool {
        self.overall >= 40 && self.overall < 70
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_reputation() {
        let rep = IpReputation::botnet();
        assert!(rep.is_high_risk());
        assert_eq!(rep.category, "botnet");
        assert_eq!(rep.score, 90);
    }

    #[test]
    fn test_ip_risk_levels() {
        assert!(IpReputation::new(90, "test").is_high_risk());
        assert!(IpReputation::new(60, "test").is_medium_risk());
        assert!(IpReputation::new(30, "test").is_low_risk());
    }

    #[test]
    fn test_domain_reputation() {
        let rep = DomainReputation::phishing();
        assert!(rep.is_high_risk());
        assert_eq!(rep.category, "phishing");
    }

    #[test]
    fn test_reputation_score() {
        let score = ReputationScore::calculate(80, 60, 40);
        // 80*40 + 60*30 + 40*30 = 3200 + 1800 + 1200 = 6200 / 100 = 62
        assert_eq!(score.overall, 62);
        assert!(score.is_medium_risk());
    }

    #[test]
    fn test_reputation_score_from_ip() {
        let score = ReputationScore::from_ip(100);
        // 100*40 + 0*30 + 0*30 = 4000 / 100 = 40
        assert_eq!(score.overall, 40);
    }
}
