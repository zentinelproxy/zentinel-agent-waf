//! Threat Intelligence Module
//!
//! Provides real-time threat intelligence integration for enhanced detection:
//! - IP reputation feeds (malicious IPs, Tor exits, proxies)
//! - Domain reputation (malware C2, phishing)
//! - Indicator of Compromise (IoC) feeds
//! - Local caching with configurable refresh intervals
//!
//! # Rule ID Ranges
//!
//! - 94000-94099: IP reputation rules
//! - 94100-94199: Domain reputation rules
//! - 94200-94299: IoC-based rules

pub mod feeds;
pub mod reputation;

pub use feeds::{ThreatFeed, FeedConfig, FeedType};
pub use reputation::{IpReputation, DomainReputation, ReputationScore};

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::detection::Detection;
use crate::rules::AttackType;

/// Threat intelligence configuration
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    /// Enable threat intelligence
    pub enabled: bool,
    /// IP reputation enabled
    pub ip_reputation_enabled: bool,
    /// Domain reputation enabled
    pub domain_reputation_enabled: bool,
    /// IoC checking enabled
    pub ioc_enabled: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// Feed refresh interval in seconds
    pub refresh_interval_secs: u64,
    /// Score threshold for blocking (0-100)
    pub block_threshold: u8,
    /// Score threshold for logging (0-100)
    pub log_threshold: u8,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ip_reputation_enabled: true,
            domain_reputation_enabled: true,
            ioc_enabled: true,
            cache_ttl_secs: 3600,      // 1 hour
            refresh_interval_secs: 86400, // 24 hours
            block_threshold: 80,
            log_threshold: 50,
        }
    }
}

/// Threat intelligence engine
pub struct ThreatIntelEngine {
    config: ThreatIntelConfig,
    /// IP reputation data
    ip_reputation: Arc<RwLock<IpReputationDb>>,
    /// Domain reputation data
    domain_reputation: Arc<RwLock<DomainReputationDb>>,
    /// IoC database
    ioc_db: Arc<RwLock<IocDatabase>>,
    /// Last refresh time
    last_refresh: Arc<RwLock<Option<Instant>>>,
}

/// IP reputation database
struct IpReputationDb {
    /// Known malicious IPs with scores
    malicious_ips: HashMap<IpAddr, IpReputation>,
    /// Tor exit nodes
    tor_exits: HashSet<IpAddr>,
    /// Known proxy IPs
    proxies: HashSet<IpAddr>,
    /// VPN endpoints
    vpn_endpoints: HashSet<IpAddr>,
    /// Cloud provider ranges (for detection, not blocking)
    cloud_ips: HashSet<IpAddr>,
    /// ASN reputation scores
    asn_scores: HashMap<u32, u8>,
}

impl Default for IpReputationDb {
    fn default() -> Self {
        Self {
            malicious_ips: HashMap::new(),
            tor_exits: HashSet::new(),
            proxies: HashSet::new(),
            vpn_endpoints: HashSet::new(),
            cloud_ips: HashSet::new(),
            asn_scores: HashMap::new(),
        }
    }
}

/// Domain reputation database
struct DomainReputationDb {
    /// Known malicious domains
    malicious_domains: HashMap<String, DomainReputation>,
    /// Phishing domains
    phishing_domains: HashSet<String>,
    /// Malware C2 domains
    c2_domains: HashSet<String>,
    /// Newly registered domains (suspicious)
    new_domains: HashSet<String>,
}

impl Default for DomainReputationDb {
    fn default() -> Self {
        Self {
            malicious_domains: HashMap::new(),
            phishing_domains: HashSet::new(),
            c2_domains: HashSet::new(),
            new_domains: HashSet::new(),
        }
    }
}

/// Indicator of Compromise database
struct IocDatabase {
    /// File hashes (SHA256)
    file_hashes: HashSet<String>,
    /// Malicious URLs
    malicious_urls: HashSet<String>,
    /// Malicious email addresses
    malicious_emails: HashSet<String>,
    /// Attack signatures
    signatures: Vec<IocSignature>,
}

impl Default for IocDatabase {
    fn default() -> Self {
        Self {
            file_hashes: HashSet::new(),
            malicious_urls: HashSet::new(),
            malicious_emails: HashSet::new(),
            signatures: Vec::new(),
        }
    }
}

/// IoC signature for pattern matching
#[derive(Debug, Clone)]
pub struct IocSignature {
    /// Signature ID
    pub id: String,
    /// Description
    pub description: String,
    /// Pattern to match
    pub pattern: String,
    /// Threat type
    pub threat_type: ThreatType,
    /// Confidence score (0-100)
    pub confidence: u8,
}

/// Type of threat
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatType {
    Malware,
    Phishing,
    BotnetC2,
    Ransomware,
    Cryptominer,
    Scanner,
    Spam,
    Exploit,
    Other,
}

impl ThreatIntelEngine {
    /// Create a new threat intelligence engine
    pub fn new(config: ThreatIntelConfig) -> Self {
        let engine = Self {
            config,
            ip_reputation: Arc::new(RwLock::new(IpReputationDb::default())),
            domain_reputation: Arc::new(RwLock::new(DomainReputationDb::default())),
            ioc_db: Arc::new(RwLock::new(IocDatabase::default())),
            last_refresh: Arc::new(RwLock::new(None)),
        };

        // Load built-in threat data
        engine.load_builtin_data();

        engine
    }

    /// Load built-in threat intelligence data
    fn load_builtin_data(&self) {
        // Load some well-known malicious indicators
        // In production, these would come from external feeds

        let mut ip_db = self.ip_reputation.write();

        // Example: Known scanner IPs (these are fake examples)
        // Real deployment would fetch from threat feeds
        ip_db.asn_scores.insert(4134, 60);  // Example high-risk ASN
        ip_db.asn_scores.insert(4837, 55);  // Example moderate-risk ASN

        drop(ip_db);

        let mut domain_db = self.domain_reputation.write();

        // Example malicious TLDs with higher baseline risk
        // (not blocking, just higher scrutiny)

        drop(domain_db);

        info!("Loaded built-in threat intelligence data");
    }

    /// Check an IP address for threats
    pub fn check_ip(&self, ip: IpAddr) -> Vec<Detection> {
        if !self.config.enabled || !self.config.ip_reputation_enabled {
            return Vec::new();
        }

        let mut detections = Vec::new();
        let ip_db = self.ip_reputation.read();

        // Check malicious IP list
        if let Some(rep) = ip_db.malicious_ips.get(&ip) {
            if rep.score >= self.config.log_threshold {
                detections.push(Detection {
                    rule_id: 94000,
                    rule_name: format!("Malicious IP: {}", rep.category),
                    attack_type: AttackType::Reconnaissance,
                    matched_value: ip.to_string(),
                    location: "source_ip".to_string(),
                    base_score: (rep.score / 10) as u32,
                    tags: vec!["intel".to_string(), "ip-reputation".to_string()],
                });
            }
        }

        // Check Tor exit nodes
        if ip_db.tor_exits.contains(&ip) {
            detections.push(Detection {
                rule_id: 94001,
                rule_name: "Tor Exit Node".to_string(),
                attack_type: AttackType::Reconnaissance,
                matched_value: ip.to_string(),
                location: "source_ip".to_string(),
                base_score: 4, // Medium - not always malicious
                tags: vec!["intel".to_string(), "tor".to_string(), "anonymizer".to_string()],
            });
        }

        // Check known proxies
        if ip_db.proxies.contains(&ip) {
            detections.push(Detection {
                rule_id: 94002,
                rule_name: "Known Proxy IP".to_string(),
                attack_type: AttackType::Reconnaissance,
                matched_value: ip.to_string(),
                location: "source_ip".to_string(),
                base_score: 3,
                tags: vec!["intel".to_string(), "proxy".to_string()],
            });
        }

        // Check VPN endpoints
        if ip_db.vpn_endpoints.contains(&ip) {
            detections.push(Detection {
                rule_id: 94003,
                rule_name: "VPN Endpoint".to_string(),
                attack_type: AttackType::Reconnaissance,
                matched_value: ip.to_string(),
                location: "source_ip".to_string(),
                base_score: 2, // Low - common for privacy
                tags: vec!["intel".to_string(), "vpn".to_string()],
            });
        }

        detections
    }

    /// Check a domain for threats
    pub fn check_domain(&self, domain: &str) -> Vec<Detection> {
        if !self.config.enabled || !self.config.domain_reputation_enabled {
            return Vec::new();
        }

        let mut detections = Vec::new();
        let domain_db = self.domain_reputation.read();
        let domain_lower = domain.to_lowercase();

        // Check malicious domains
        if let Some(rep) = domain_db.malicious_domains.get(&domain_lower) {
            if rep.score >= self.config.log_threshold {
                detections.push(Detection {
                    rule_id: 94100,
                    rule_name: format!("Malicious Domain: {}", rep.category),
                    attack_type: AttackType::Reconnaissance,
                    matched_value: domain.to_string(),
                    location: "domain".to_string(),
                    base_score: (rep.score / 10) as u32,
                    tags: vec!["intel".to_string(), "domain-reputation".to_string()],
                });
            }
        }

        // Check phishing domains
        if domain_db.phishing_domains.contains(&domain_lower) {
            detections.push(Detection {
                rule_id: 94101,
                rule_name: "Known Phishing Domain".to_string(),
                attack_type: AttackType::Reconnaissance,
                matched_value: domain.to_string(),
                location: "domain".to_string(),
                base_score: 9,
                tags: vec!["intel".to_string(), "phishing".to_string()],
            });
        }

        // Check C2 domains
        if domain_db.c2_domains.contains(&domain_lower) {
            detections.push(Detection {
                rule_id: 94102,
                rule_name: "Known C2 Domain".to_string(),
                attack_type: AttackType::Reconnaissance,
                matched_value: domain.to_string(),
                location: "domain".to_string(),
                base_score: 10,
                tags: vec!["intel".to_string(), "c2".to_string(), "malware".to_string()],
            });
        }

        // Check newly registered domains
        if domain_db.new_domains.contains(&domain_lower) {
            detections.push(Detection {
                rule_id: 94103,
                rule_name: "Newly Registered Domain".to_string(),
                attack_type: AttackType::Reconnaissance,
                matched_value: domain.to_string(),
                location: "domain".to_string(),
                base_score: 3, // Low - just suspicious
                tags: vec!["intel".to_string(), "new-domain".to_string()],
            });
        }

        detections
    }

    /// Check a URL for IoC matches
    pub fn check_url(&self, url: &str) -> Vec<Detection> {
        if !self.config.enabled || !self.config.ioc_enabled {
            return Vec::new();
        }

        let mut detections = Vec::new();
        let ioc_db = self.ioc_db.read();

        // Check malicious URLs
        if ioc_db.malicious_urls.contains(url) {
            detections.push(Detection {
                rule_id: 94200,
                rule_name: "Known Malicious URL".to_string(),
                attack_type: AttackType::Reconnaissance,
                matched_value: url.to_string(),
                location: "url".to_string(),
                base_score: 9,
                tags: vec!["intel".to_string(), "ioc".to_string(), "malicious-url".to_string()],
            });
        }

        detections
    }

    /// Check a file hash for IoC matches
    pub fn check_hash(&self, hash: &str) -> Vec<Detection> {
        if !self.config.enabled || !self.config.ioc_enabled {
            return Vec::new();
        }

        let mut detections = Vec::new();
        let ioc_db = self.ioc_db.read();

        if ioc_db.file_hashes.contains(hash) {
            detections.push(Detection {
                rule_id: 94201,
                rule_name: "Known Malicious File Hash".to_string(),
                attack_type: AttackType::Reconnaissance,
                matched_value: hash.to_string(),
                location: "file_hash".to_string(),
                base_score: 10,
                tags: vec!["intel".to_string(), "ioc".to_string(), "malware".to_string()],
            });
        }

        detections
    }

    /// Add an IP to the malicious list
    pub fn add_malicious_ip(&self, ip: IpAddr, reputation: IpReputation) {
        let mut ip_db = self.ip_reputation.write();
        ip_db.malicious_ips.insert(ip, reputation);
        debug!(ip = %ip, "Added malicious IP to threat intel");
    }

    /// Add a domain to the malicious list
    pub fn add_malicious_domain(&self, domain: String, reputation: DomainReputation) {
        let mut domain_db = self.domain_reputation.write();
        domain_db.malicious_domains.insert(domain.to_lowercase(), reputation);
        debug!(domain = domain, "Added malicious domain to threat intel");
    }

    /// Add Tor exit nodes
    pub fn add_tor_exits(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut ip_db = self.ip_reputation.write();
        ip_db.tor_exits.extend(ips);
    }

    /// Add proxy IPs
    pub fn add_proxies(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut ip_db = self.ip_reputation.write();
        ip_db.proxies.extend(ips);
    }

    /// Add IoC file hashes
    pub fn add_file_hashes(&self, hashes: impl IntoIterator<Item = String>) {
        let mut ioc_db = self.ioc_db.write();
        ioc_db.file_hashes.extend(hashes);
    }

    /// Add malicious URLs
    pub fn add_malicious_urls(&self, urls: impl IntoIterator<Item = String>) {
        let mut ioc_db = self.ioc_db.write();
        ioc_db.malicious_urls.extend(urls);
    }

    /// Get statistics about loaded threat data
    pub fn stats(&self) -> ThreatIntelStats {
        let ip_db = self.ip_reputation.read();
        let domain_db = self.domain_reputation.read();
        let ioc_db = self.ioc_db.read();

        ThreatIntelStats {
            malicious_ips: ip_db.malicious_ips.len(),
            tor_exits: ip_db.tor_exits.len(),
            proxies: ip_db.proxies.len(),
            vpn_endpoints: ip_db.vpn_endpoints.len(),
            malicious_domains: domain_db.malicious_domains.len(),
            phishing_domains: domain_db.phishing_domains.len(),
            c2_domains: domain_db.c2_domains.len(),
            file_hashes: ioc_db.file_hashes.len(),
            malicious_urls: ioc_db.malicious_urls.len(),
        }
    }

    /// Check if refresh is needed
    pub fn needs_refresh(&self) -> bool {
        let last = self.last_refresh.read();
        match *last {
            Some(instant) => {
                instant.elapsed() > Duration::from_secs(self.config.refresh_interval_secs)
            }
            None => true,
        }
    }

    /// Mark data as refreshed
    pub fn mark_refreshed(&self) {
        let mut last = self.last_refresh.write();
        *last = Some(Instant::now());
    }
}

impl Default for ThreatIntelEngine {
    fn default() -> Self {
        Self::new(ThreatIntelConfig::default())
    }
}

/// Statistics about loaded threat intelligence
#[derive(Debug, Clone)]
pub struct ThreatIntelStats {
    pub malicious_ips: usize,
    pub tor_exits: usize,
    pub proxies: usize,
    pub vpn_endpoints: usize,
    pub malicious_domains: usize,
    pub phishing_domains: usize,
    pub c2_domains: usize,
    pub file_hashes: usize,
    pub malicious_urls: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_engine_creation() {
        let engine = ThreatIntelEngine::default();
        let stats = engine.stats();
        assert_eq!(stats.malicious_ips, 0);
    }

    #[test]
    fn test_add_malicious_ip() {
        let engine = ThreatIntelEngine::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        engine.add_malicious_ip(
            ip,
            IpReputation {
                score: 90,
                category: "scanner".to_string(),
                last_seen: None,
                reports: 5,
            },
        );

        let detections = engine.check_ip(ip);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].rule_id, 94000);
    }

    #[test]
    fn test_tor_exit_detection() {
        let engine = ThreatIntelEngine::default();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        engine.add_tor_exits(vec![ip]);

        let detections = engine.check_ip(ip);
        assert!(detections.iter().any(|d| d.rule_id == 94001));
    }

    #[test]
    fn test_malicious_domain() {
        let engine = ThreatIntelEngine::default();

        engine.add_malicious_domain(
            "evil.example.com".to_string(),
            DomainReputation {
                score: 95,
                category: "malware".to_string(),
                first_seen: None,
                reports: 10,
            },
        );

        let detections = engine.check_domain("evil.example.com");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].rule_id, 94100);
    }

    #[test]
    fn test_clean_ip() {
        let engine = ThreatIntelEngine::default();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let detections = engine.check_ip(ip);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_clean_domain() {
        let engine = ThreatIntelEngine::default();

        let detections = engine.check_domain("google.com");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_malicious_url() {
        let engine = ThreatIntelEngine::default();

        engine.add_malicious_urls(vec!["http://evil.com/malware.exe".to_string()]);

        let detections = engine.check_url("http://evil.com/malware.exe");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].rule_id, 94200);
    }

    #[test]
    fn test_file_hash() {
        let engine = ThreatIntelEngine::default();

        engine.add_file_hashes(vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ]);

        let detections =
            engine.check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].rule_id, 94201);
    }

    #[test]
    fn test_stats() {
        let engine = ThreatIntelEngine::default();

        engine.add_tor_exits(vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        ]);

        let stats = engine.stats();
        assert_eq!(stats.tor_exits, 2);
    }

    #[test]
    fn test_disabled_checks() {
        let config = ThreatIntelConfig {
            enabled: false,
            ..Default::default()
        };
        let engine = ThreatIntelEngine::new(config);

        engine.add_tor_exits(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);

        let detections = engine.check_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(detections.is_empty());
    }
}
