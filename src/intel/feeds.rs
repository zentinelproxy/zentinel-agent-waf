//! Threat Feed Management
//!
//! Handles fetching and parsing threat intelligence feeds from various sources.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Threat feed configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    /// Feed name
    pub name: String,
    /// Feed URL
    pub url: String,
    /// Feed type
    pub feed_type: FeedType,
    /// Refresh interval in seconds
    pub refresh_interval_secs: u64,
    /// Enable this feed
    pub enabled: bool,
    /// API key (if required)
    pub api_key: Option<String>,
    /// Custom headers
    pub headers: Vec<(String, String)>,
}

impl FeedConfig {
    /// Create a new feed configuration
    pub fn new(name: impl Into<String>, url: impl Into<String>, feed_type: FeedType) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            feed_type,
            refresh_interval_secs: 86400, // 24 hours default
            enabled: true,
            api_key: None,
            headers: Vec::new(),
        }
    }

    /// Set refresh interval
    pub fn with_refresh_interval(mut self, secs: u64) -> Self {
        self.refresh_interval_secs = secs;
        self
    }

    /// Set API key
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Add custom header
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Get refresh interval as Duration
    pub fn refresh_interval(&self) -> Duration {
        Duration::from_secs(self.refresh_interval_secs)
    }
}

/// Type of threat feed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedType {
    /// IP address list (one per line)
    IpList,
    /// Domain list (one per line)
    DomainList,
    /// URL list (one per line)
    UrlList,
    /// Hash list (one per line)
    HashList,
    /// CSV format
    Csv,
    /// JSON format
    Json,
    /// STIX format
    Stix,
    /// TAXII feed
    Taxii,
}

/// Represents a threat feed source
#[derive(Debug, Clone)]
pub struct ThreatFeed {
    /// Feed configuration
    pub config: FeedConfig,
    /// Last successful fetch
    pub last_fetch: Option<std::time::Instant>,
    /// Number of entries loaded
    pub entry_count: usize,
    /// Last error (if any)
    pub last_error: Option<String>,
}

impl ThreatFeed {
    /// Create a new threat feed
    pub fn new(config: FeedConfig) -> Self {
        Self {
            config,
            last_fetch: None,
            entry_count: 0,
            last_error: None,
        }
    }

    /// Check if feed needs refresh
    pub fn needs_refresh(&self) -> bool {
        match self.last_fetch {
            Some(last) => last.elapsed() > self.config.refresh_interval(),
            None => true,
        }
    }

    /// Mark feed as successfully fetched
    pub fn mark_fetched(&mut self, count: usize) {
        self.last_fetch = Some(std::time::Instant::now());
        self.entry_count = count;
        self.last_error = None;
    }

    /// Mark feed as failed
    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
    }
}

/// Well-known feed sources
pub mod sources {
    use super::*;

    /// Abuse.ch Feodo Tracker (banking trojans)
    pub fn feodo_tracker() -> FeedConfig {
        FeedConfig::new(
            "Feodo Tracker",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            FeedType::IpList,
        )
        .with_refresh_interval(3600) // 1 hour
    }

    /// Abuse.ch SSL Blacklist
    pub fn ssl_blacklist() -> FeedConfig {
        FeedConfig::new(
            "SSL Blacklist",
            "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
            FeedType::IpList,
        )
        .with_refresh_interval(3600)
    }

    /// Emerging Threats compromised IPs
    pub fn emerging_threats_compromised() -> FeedConfig {
        FeedConfig::new(
            "Emerging Threats Compromised",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            FeedType::IpList,
        )
        .with_refresh_interval(86400)
    }

    /// URLhaus malware URLs
    pub fn urlhaus() -> FeedConfig {
        FeedConfig::new(
            "URLhaus",
            "https://urlhaus.abuse.ch/downloads/text/",
            FeedType::UrlList,
        )
        .with_refresh_interval(3600)
    }

    /// OpenPhish phishing URLs
    pub fn openphish() -> FeedConfig {
        FeedConfig::new(
            "OpenPhish",
            "https://openphish.com/feed.txt",
            FeedType::UrlList,
        )
        .with_refresh_interval(3600)
    }

    /// Tor exit nodes (dan.me.uk)
    pub fn tor_exit_nodes() -> FeedConfig {
        FeedConfig::new(
            "Tor Exit Nodes",
            "https://www.dan.me.uk/torlist/?exit",
            FeedType::IpList,
        )
        .with_refresh_interval(3600)
    }

    /// Get all default feeds
    pub fn default_feeds() -> Vec<FeedConfig> {
        vec![
            feodo_tracker(),
            ssl_blacklist(),
            urlhaus(),
            tor_exit_nodes(),
        ]
    }
}

/// Feed parser for different formats
pub struct FeedParser;

impl FeedParser {
    /// Parse IP list (one per line)
    pub fn parse_ip_list(content: &str) -> Vec<String> {
        content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect()
    }

    /// Parse domain list (one per line)
    pub fn parse_domain_list(content: &str) -> Vec<String> {
        content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_lowercase())
            .collect()
    }

    /// Parse URL list (one per line)
    pub fn parse_url_list(content: &str) -> Vec<String> {
        content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| l.starts_with("http://") || l.starts_with("https://"))
            .map(|l| l.to_string())
            .collect()
    }

    /// Parse hash list (one per line)
    pub fn parse_hash_list(content: &str) -> Vec<String> {
        content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| l.len() == 32 || l.len() == 40 || l.len() == 64) // MD5, SHA1, SHA256
            .map(|l| l.to_lowercase())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_config() {
        let config = FeedConfig::new("Test", "http://example.com/feed.txt", FeedType::IpList)
            .with_refresh_interval(3600)
            .with_api_key("secret");

        assert_eq!(config.name, "Test");
        assert_eq!(config.refresh_interval_secs, 3600);
        assert_eq!(config.api_key, Some("secret".to_string()));
    }

    #[test]
    fn test_parse_ip_list() {
        let content = r#"
# Comment line
192.168.1.1
10.0.0.1

# Another comment
172.16.0.1
"#;
        let ips = FeedParser::parse_ip_list(content);
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "192.168.1.1");
    }

    #[test]
    fn test_parse_domain_list() {
        let content = r#"
evil.com
MALWARE.NET
phishing.org
"#;
        let domains = FeedParser::parse_domain_list(content);
        assert_eq!(domains.len(), 3);
        assert_eq!(domains[1], "malware.net"); // lowercase
    }

    #[test]
    fn test_parse_url_list() {
        let content = r#"
http://evil.com/malware
https://phishing.net/login
not-a-url
ftp://invalid
"#;
        let urls = FeedParser::parse_url_list(content);
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn test_parse_hash_list() {
        let content = r#"
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
d41d8cd98f00b204e9800998ecf8427e
invalid_hash
"#;
        let hashes = FeedParser::parse_hash_list(content);
        assert_eq!(hashes.len(), 2); // SHA256 and MD5
    }

    #[test]
    fn test_threat_feed() {
        let config = FeedConfig::new("Test", "http://example.com", FeedType::IpList);
        let mut feed = ThreatFeed::new(config);

        assert!(feed.needs_refresh());

        feed.mark_fetched(100);
        assert!(!feed.needs_refresh());
        assert_eq!(feed.entry_count, 100);
    }

    #[test]
    fn test_default_feeds() {
        let feeds = sources::default_feeds();
        assert!(!feeds.is_empty());
    }
}
