//! Bot Signature Database
//!
//! Contains signatures for identifying known bots, both good and bad.

use regex::Regex;
use std::sync::LazyLock;

/// Bot signature classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotSignature {
    /// Known good bot (search engines, monitors)
    GoodBot(String),
    /// Known bad bot (scrapers, attack tools)
    BadBot(String, u8), // name, confidence score
    /// Suspicious but not definitively bad
    SuspiciousBot(String, u8),
    /// Unknown
    Unknown,
}

/// Bot signature database
pub struct BotSignatureDb {
    good_bots: Vec<(Regex, String)>,
    bad_bots: Vec<(Regex, String, u8)>,
    suspicious_patterns: Vec<(Regex, String, u8)>,
    known_bad_tls_fingerprints: Vec<(String, String)>, // fingerprint, tool name
}

// Good bot patterns (search engines, legitimate crawlers)
static GOOD_BOT_PATTERNS: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    vec![
        (r"(?i)googlebot", "Googlebot"),
        (r"(?i)bingbot", "Bingbot"),
        (r"(?i)slurp", "Yahoo Slurp"),
        (r"(?i)duckduckbot", "DuckDuckBot"),
        (r"(?i)baiduspider", "Baidu Spider"),
        (r"(?i)yandexbot", "YandexBot"),
        (r"(?i)facebookexternalhit", "Facebook Crawler"),
        (r"(?i)twitterbot", "Twitter Bot"),
        (r"(?i)linkedinbot", "LinkedIn Bot"),
        (r"(?i)applebot", "Apple Bot"),
        (r"(?i)pingdom", "Pingdom Monitor"),
        (r"(?i)uptimerobot", "UptimeRobot"),
        (r"(?i)statuspage", "StatusPage"),
        (r"(?i)site24x7", "Site24x7"),
        (r"(?i)newrelic", "New Relic"),
        (r"(?i)datadog", "Datadog"),
    ]
});

// Known bad bot/tool patterns
static BAD_BOT_PATTERNS: LazyLock<Vec<(&'static str, &'static str, u8)>> = LazyLock::new(|| {
    vec![
        // Security scanners
        (r"(?i)nikto", "Nikto Scanner", 80),
        (r"(?i)sqlmap", "SQLMap", 90),
        (r"(?i)nmap", "Nmap", 70),
        (r"(?i)masscan", "Masscan", 75),
        (r"(?i)nuclei", "Nuclei Scanner", 70),
        (r"(?i)wpscan", "WPScan", 70),
        (r"(?i)acunetix", "Acunetix", 75),
        (r"(?i)nessus", "Nessus", 70),
        (r"(?i)openvas", "OpenVAS", 70),
        (r"(?i)burp", "Burp Suite", 60),
        (r"(?i)zap/", "OWASP ZAP", 60),
        (r"(?i)dirbuster", "DirBuster", 70),
        (r"(?i)gobuster", "Gobuster", 70),
        (r"(?i)ffuf", "FFUF", 70),
        (r"(?i)wfuzz", "WFuzz", 70),
        (r"(?i)hydra", "Hydra", 85),
        (r"(?i)metasploit", "Metasploit", 90),
        // Scrapers and spam bots
        (r"(?i)scrapy", "Scrapy", 60),
        (r"(?i)httrack", "HTTrack", 65),
        // Known malicious
        (r"(?i)hacker", "Hacker UA", 70),
        (r"(?i)attack", "Attack UA", 80),
        (r"(?i)exploit", "Exploit UA", 85),
        (r"(?i)inject", "Inject UA", 75),
    ]
});

// Suspicious patterns (not definitively bad but worth noting)
static SUSPICIOUS_PATTERNS: LazyLock<Vec<(&'static str, &'static str, u8)>> = LazyLock::new(|| {
    vec![
        // Common HTTP libraries (legitimate but often used for automation)
        (r"(?i)wget/", "Wget", 25),
        (r"(?i)curl/", "Curl", 20),
        (r"(?i)python-requests", "Python Requests", 25),
        (r"(?i)python-urllib", "Python urllib", 30),
        (r"(?i)libwww-perl", "Perl LWP", 35),
        (r"(?i)java/", "Java HTTP Client", 25),
        (r"(?i)go-http-client", "Go HTTP Client", 25),
        // Generic automation patterns
        (r"(?i)headless", "Headless Browser", 30),
        (r"(?i)phantom", "PhantomJS", 40),
        (r"(?i)selenium", "Selenium", 35),
        (r"(?i)puppeteer", "Puppeteer", 35),
        (r"(?i)playwright", "Playwright", 35),
        // Version mismatches / anomalies
        (r"Chrome/[0-3]\.", "Very Old Chrome", 50),
        (r"Firefox/[0-3]\.", "Very Old Firefox", 50),
        (r"MSIE [0-6]\.", "Ancient IE", 60),
        // Empty or single-word UA
        (r"^[A-Za-z]+$", "Single Word UA", 40),
        (r"^Mozilla/5\.0$", "Bare Mozilla UA", 45),
        // Known bad patterns
        (r"(?i)bot|spider|crawl", "Generic Bot Pattern", 25),
    ]
});

// Known bad TLS fingerprints (JA3/JA4)
static BAD_TLS_FINGERPRINTS: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    vec![
        // These are example fingerprints - real deployment would have updated list
        ("9e10692f1b7f78228b2d4e424db3a98c", "Python Requests"),
        ("555f387c53527b55cf46b75bb1a7d78a", "Curl"),
        ("e7d705a3286e19ea42f587b344ee6865", "Go HTTP"),
        ("6734f37431670b3ab4292b8f60f29984", "Nmap"),
        ("a0e9f5d64349fb13f0ab94cc128e78f5", "Metasploit"),
    ]
});

impl BotSignatureDb {
    /// Create a new signature database
    pub fn new() -> Self {
        let good_bots = GOOD_BOT_PATTERNS
            .iter()
            .filter_map(|(pattern, name)| Regex::new(pattern).ok().map(|r| (r, name.to_string())))
            .collect();

        let bad_bots = BAD_BOT_PATTERNS
            .iter()
            .filter_map(|(pattern, name, score)| {
                Regex::new(pattern)
                    .ok()
                    .map(|r| (r, name.to_string(), *score))
            })
            .collect();

        let suspicious_patterns = SUSPICIOUS_PATTERNS
            .iter()
            .filter_map(|(pattern, name, score)| {
                Regex::new(pattern)
                    .ok()
                    .map(|r| (r, name.to_string(), *score))
            })
            .collect();

        let known_bad_tls_fingerprints = BAD_TLS_FINGERPRINTS
            .iter()
            .map(|(fp, name)| (fp.to_string(), name.to_string()))
            .collect();

        Self {
            good_bots,
            bad_bots,
            suspicious_patterns,
            known_bad_tls_fingerprints,
        }
    }

    /// Classify a User-Agent string
    pub fn classify_user_agent(&self, user_agent: &str) -> BotSignature {
        // Check good bots first
        for (pattern, name) in &self.good_bots {
            if pattern.is_match(user_agent) {
                return BotSignature::GoodBot(name.clone());
            }
        }

        // Check known bad bots
        for (pattern, name, score) in &self.bad_bots {
            if pattern.is_match(user_agent) {
                return BotSignature::BadBot(name.clone(), *score);
            }
        }

        // Check suspicious patterns
        for (pattern, name, score) in &self.suspicious_patterns {
            if pattern.is_match(user_agent) {
                return BotSignature::SuspiciousBot(name.clone(), *score);
            }
        }

        BotSignature::Unknown
    }

    /// Check TLS fingerprint against known bad fingerprints
    pub fn check_tls_fingerprint(&self, fingerprint: &str) -> Option<(String, u8)> {
        for (known_fp, tool_name) in &self.known_bad_tls_fingerprints {
            if fingerprint == known_fp {
                return Some((format!("Known bad TLS: {}", tool_name), 50));
            }
        }
        None
    }

    /// Check if a User-Agent is a known good bot
    pub fn is_good_bot(&self, user_agent: &str) -> bool {
        matches!(
            self.classify_user_agent(user_agent),
            BotSignature::GoodBot(_)
        )
    }

    /// Check if a User-Agent is a known bad bot
    pub fn is_bad_bot(&self, user_agent: &str) -> bool {
        matches!(
            self.classify_user_agent(user_agent),
            BotSignature::BadBot(_, _)
        )
    }
}

impl Default for BotSignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_good_bot_detection() {
        let db = BotSignatureDb::new();

        assert!(db.is_good_bot("Googlebot/2.1"));
        assert!(db.is_good_bot("Mozilla/5.0 (compatible; Googlebot/2.1)"));
        assert!(db.is_good_bot("Mozilla/5.0 (compatible; bingbot/2.0)"));
        assert!(db.is_good_bot("facebookexternalhit/1.1"));
    }

    #[test]
    fn test_bad_bot_detection() {
        let db = BotSignatureDb::new();

        assert!(db.is_bad_bot("sqlmap/1.0"));
        assert!(db.is_bad_bot("Nikto/2.1.6"));
        assert!(db.is_bad_bot("masscan/1.0"));

        // Suspicious but not definitively bad
        assert!(!db.is_bad_bot("python-requests/2.28.0"));
    }

    #[test]
    fn test_suspicious_detection() {
        let db = BotSignatureDb::new();

        let result = db.classify_user_agent("HeadlessChrome/90.0");
        assert!(matches!(result, BotSignature::SuspiciousBot(_, _)));

        let result = db.classify_user_agent("PhantomJS/2.1");
        assert!(matches!(result, BotSignature::SuspiciousBot(_, _)));
    }

    #[test]
    fn test_normal_browser() {
        let db = BotSignatureDb::new();

        let result = db.classify_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        );
        assert!(matches!(result, BotSignature::Unknown));
    }

    #[test]
    fn test_tls_fingerprint() {
        let db = BotSignatureDb::new();

        // Known bad fingerprint
        let result = db.check_tls_fingerprint("9e10692f1b7f78228b2d4e424db3a98c");
        assert!(result.is_some());

        // Unknown fingerprint
        let result = db.check_tls_fingerprint("unknown_fingerprint_here");
        assert!(result.is_none());
    }
}
