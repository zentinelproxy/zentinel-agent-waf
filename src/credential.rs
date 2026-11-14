//! Credential Stuffing Protection
//!
//! Detects and blocks credential stuffing attacks:
//! - Login velocity tracking (failed attempts per time window)
//! - Distributed attack detection (same credentials from multiple IPs)
//! - Account enumeration detection
//! - Password spray detection
//!
//! # Rule ID Ranges
//!
//! - 96000-96099: Credential attack rules

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::detection::Detection;
use crate::rules::AttackType;

/// Credential protection configuration
#[derive(Debug, Clone)]
pub struct CredentialConfig {
    /// Enable login velocity detection
    pub velocity_detection: bool,
    /// Maximum failed logins per IP per window
    pub max_failures_per_ip: usize,
    /// Maximum failed logins per username per window
    pub max_failures_per_user: usize,
    /// Time window for tracking (seconds)
    pub window_secs: u64,
    /// Enable account enumeration detection
    pub enumeration_detection: bool,
    /// Maximum unique usernames per IP per window
    pub max_usernames_per_ip: usize,
    /// Enable distributed attack detection
    pub distributed_detection: bool,
    /// Maximum IPs per username before flagging distributed attack
    pub max_ips_per_user: usize,
    /// Paths that are considered login endpoints
    pub login_paths: Vec<String>,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            velocity_detection: true,
            max_failures_per_ip: 10,
            max_failures_per_user: 5,
            window_secs: 300, // 5 minutes
            enumeration_detection: true,
            max_usernames_per_ip: 10,
            distributed_detection: true,
            max_ips_per_user: 5,
            login_paths: vec![
                "/login".to_string(),
                "/signin".to_string(),
                "/auth".to_string(),
                "/api/login".to_string(),
                "/api/auth".to_string(),
                "/api/v1/login".to_string(),
                "/api/v1/auth".to_string(),
                "/oauth/token".to_string(),
            ],
        }
    }
}

/// Decision from credential protection check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialDecision {
    /// Allow the request
    Allow,
    /// Rate limited due to too many failures
    RateLimited { reason: String },
    /// Distributed attack detected
    DistributedAttack { reason: String },
    /// Account enumeration detected
    AccountEnumeration { reason: String },
}

impl CredentialDecision {
    /// Check if this is a blocking decision
    pub fn is_blocked(&self) -> bool {
        !matches!(self, CredentialDecision::Allow)
    }
}

/// Tracking data for an IP address
#[derive(Debug)]
struct IpTracker {
    /// Failed login attempts
    failure_count: usize,
    /// Unique usernames tried
    usernames: HashMap<String, usize>,
    /// First attempt time
    first_attempt: Instant,
    /// Last attempt time
    last_attempt: Instant,
}

impl IpTracker {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            failure_count: 0,
            usernames: HashMap::new(),
            first_attempt: now,
            last_attempt: now,
        }
    }

    fn record_attempt(&mut self, username: Option<&str>, success: bool) {
        self.last_attempt = Instant::now();
        if !success {
            self.failure_count += 1;
        }
        if let Some(username) = username {
            *self.usernames.entry(username.to_string()).or_insert(0) += 1;
        }
    }

    fn reset(&mut self) {
        let now = Instant::now();
        self.failure_count = 0;
        self.usernames.clear();
        self.first_attempt = now;
        self.last_attempt = now;
    }

    fn is_expired(&self, window: Duration) -> bool {
        self.last_attempt.elapsed() > window
    }
}

/// Tracking data for a username
#[derive(Debug)]
struct UserTracker {
    /// IPs that have attempted this username
    ips: HashMap<String, usize>,
    /// Failed attempt count
    failure_count: usize,
    /// First attempt time
    first_attempt: Instant,
    /// Last attempt time
    last_attempt: Instant,
}

impl UserTracker {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            ips: HashMap::new(),
            failure_count: 0,
            first_attempt: now,
            last_attempt: now,
        }
    }

    fn record_attempt(&mut self, ip: &str, success: bool) {
        self.last_attempt = Instant::now();
        if !success {
            self.failure_count += 1;
        }
        *self.ips.entry(ip.to_string()).or_insert(0) += 1;
    }

    fn reset(&mut self) {
        let now = Instant::now();
        self.ips.clear();
        self.failure_count = 0;
        self.first_attempt = now;
        self.last_attempt = now;
    }

    fn is_expired(&self, window: Duration) -> bool {
        self.last_attempt.elapsed() > window
    }
}

/// Credential protection tracker
pub struct CredentialProtection {
    config: CredentialConfig,
    /// Per-IP tracking
    ip_trackers: HashMap<String, IpTracker>,
    /// Per-username tracking
    user_trackers: HashMap<String, UserTracker>,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl CredentialProtection {
    /// Create a new credential protection instance
    pub fn new(config: CredentialConfig) -> Self {
        Self {
            config,
            ip_trackers: HashMap::new(),
            user_trackers: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Check if a path is a login endpoint: one of `login_paths`, or below
    /// one (`/login/sso`), ignoring case and any query string. `/auth` does not
    /// match `/authors`.
    pub fn is_login_path(&self, path: &str) -> bool {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let path_lower = path.to_lowercase();
        self.config.login_paths.iter().any(|p| {
            let p = p.to_lowercase();
            let p = p.trim_end_matches('/');
            match path_lower.strip_prefix(p) {
                Some(rest) => rest.is_empty() || rest.starts_with('/'),
                None => false,
            }
        })
    }

    /// Whether a new login attempt from `ip` (for `username`, when known)
    /// must be refused before it reaches the application, because the client
    /// or the account has already used up its failures for the window.
    ///
    /// Reads the counters without recording anything: the attempt is recorded
    /// by [`Self::record_attempt`] once its outcome (the response status) is
    /// known.
    pub fn precheck(
        &self,
        ip: &str,
        username: Option<&str>,
    ) -> (CredentialDecision, Vec<Detection>) {
        if !self.config.velocity_detection {
            return (CredentialDecision::Allow, Vec::new());
        }
        let window = Duration::from_secs(self.config.window_secs);

        let ip_failures = self
            .ip_trackers
            .get(ip)
            .filter(|t| !t.is_expired(window))
            .map_or(0, |t| t.failure_count);
        if ip_failures >= self.config.max_failures_per_ip {
            return (
                CredentialDecision::RateLimited {
                    reason: format!("Too many failed attempts from IP ({ip_failures})"),
                },
                vec![ip_rate_limit_detection(ip, self.config.max_failures_per_ip)],
            );
        }

        if let Some(username) = username {
            let user_failures = self
                .user_trackers
                .get(username)
                .filter(|t| !t.is_expired(window))
                .map_or(0, |t| t.failure_count);
            if user_failures >= self.config.max_failures_per_user {
                return (
                    CredentialDecision::RateLimited {
                        reason: format!("Too many failed attempts for user ({user_failures})"),
                    },
                    vec![user_rate_limit_detection(
                        username,
                        self.config.max_failures_per_user,
                    )],
                );
            }
        }

        (CredentialDecision::Allow, Vec::new())
    }

    /// Record a login attempt and check for attacks
    pub fn check_attempt(
        &mut self,
        ip: &str,
        username: &str,
        success: bool,
    ) -> (CredentialDecision, Vec<Detection>) {
        self.record_attempt(ip, Some(username), success)
    }

    /// Record a login attempt whose username may be unknown (`None`: only the
    /// client's counters are updated), and check for attacks.
    pub fn record_attempt(
        &mut self,
        ip: &str,
        username: Option<&str>,
        success: bool,
    ) -> (CredentialDecision, Vec<Detection>) {
        let window = Duration::from_secs(self.config.window_secs);

        // Periodic cleanup
        if self.last_cleanup.elapsed() > Duration::from_secs(60) {
            self.cleanup(window);
        }

        let mut detections = Vec::new();

        // Get or create IP tracker
        let ip_tracker = self
            .ip_trackers
            .entry(ip.to_string())
            .or_insert_with(IpTracker::new);

        // Reset if window expired
        if ip_tracker.is_expired(window) {
            ip_tracker.reset();
        }

        // Record the attempt
        ip_tracker.record_attempt(username, success);

        // Get or create user tracker (only when the username is known)
        let mut user_tracker = username.map(|username| {
            let tracker = self
                .user_trackers
                .entry(username.to_string())
                .or_insert_with(UserTracker::new);
            if tracker.is_expired(window) {
                tracker.reset();
            }
            tracker.record_attempt(ip, success);
            tracker
        });
        let username_or_unknown = username.unwrap_or("");

        // Check velocity per IP
        if self.config.velocity_detection
            && !success
            && ip_tracker.failure_count > self.config.max_failures_per_ip
        {
            detections.push(ip_rate_limit_detection(ip, self.config.max_failures_per_ip));

            return (
                CredentialDecision::RateLimited {
                    reason: format!(
                        "Too many failed attempts from IP ({})",
                        ip_tracker.failure_count
                    ),
                },
                detections,
            );
        }

        // Check velocity per username
        if let Some(user_tracker) = user_tracker.as_deref_mut() {
            if self.config.velocity_detection
                && !success
                && user_tracker.failure_count > self.config.max_failures_per_user
            {
                detections.push(user_rate_limit_detection(
                    username_or_unknown,
                    self.config.max_failures_per_user,
                ));

                return (
                    CredentialDecision::RateLimited {
                        reason: format!(
                            "Too many failed attempts for user ({})",
                            user_tracker.failure_count
                        ),
                    },
                    detections,
                );
            }
        }

        // Check account enumeration (many usernames from one IP)
        if self.config.enumeration_detection
            && !success
            && ip_tracker.usernames.len() > self.config.max_usernames_per_ip
        {
            detections.push(Detection {
                rule_id: 96003,
                rule_name: "Account Enumeration Detected".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!(
                    "IP {} tried {} unique usernames",
                    ip,
                    ip_tracker.usernames.len()
                ),
                location: "login".to_string(),
                base_score: 8,
                tags: vec!["credential-stuffing".to_string(), "enumeration".to_string()],
            });

            return (
                CredentialDecision::AccountEnumeration {
                    reason: format!(
                        "Too many unique usernames from IP ({})",
                        ip_tracker.usernames.len()
                    ),
                },
                detections,
            );
        }

        // Check distributed attack (one username from many IPs)
        let user_ips = user_tracker.as_deref().map_or(0, |t| t.ips.len());
        if self.config.distributed_detection && !success && user_ips > self.config.max_ips_per_user
        {
            detections.push(Detection {
                rule_id: 96004,
                rule_name: "Distributed Credential Attack".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!(
                    "User {} attacked from {} IPs",
                    mask_username(username_or_unknown),
                    user_ips
                ),
                location: "login".to_string(),
                base_score: 9,
                tags: vec!["credential-stuffing".to_string(), "distributed".to_string()],
            });

            return (
                CredentialDecision::DistributedAttack {
                    reason: format!("Distributed attack: {} IPs targeting user", user_ips),
                },
                detections,
            );
        }

        (CredentialDecision::Allow, detections)
    }

    /// Clean up expired trackers
    fn cleanup(&mut self, window: Duration) {
        self.ip_trackers
            .retain(|_, tracker| !tracker.is_expired(window));
        self.user_trackers
            .retain(|_, tracker| !tracker.is_expired(window));
        self.last_cleanup = Instant::now();
    }

    /// Get statistics
    pub fn stats(&self) -> CredentialStats {
        CredentialStats {
            tracked_ips: self.ip_trackers.len(),
            tracked_users: self.user_trackers.len(),
        }
    }
}

impl Default for CredentialProtection {
    fn default() -> Self {
        Self::new(CredentialConfig::default())
    }
}

/// Statistics from credential protection
#[derive(Debug, Clone)]
pub struct CredentialStats {
    /// Number of tracked IPs
    pub tracked_ips: usize,
    /// Number of tracked usernames
    pub tracked_users: usize,
}

/// The username a login body names: the first of `fields` present as a
/// top-level string in a JSON object, or as an `application/x-www-form-urlencoded`
/// field. Empty values and values over 256 bytes are ignored.
pub fn extract_username(body: &[u8], fields: &[String]) -> Option<String> {
    const MAX_LEN: usize = 256;
    let usable = |v: String| (!v.is_empty() && v.len() <= MAX_LEN).then_some(v);

    if let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(body) {
        return fields.iter().find_map(|f| {
            map.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(f))
                .and_then(|(_, v)| v.as_str())
                .and_then(|v| usable(v.to_string()))
        });
    }

    let body = std::str::from_utf8(body).ok()?;
    let pairs: Vec<(String, String)> = body
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((form_decode(k)?, form_decode(v)?))
        })
        .collect();
    fields.iter().find_map(|f| {
        pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(f))
            .and_then(|(_, v)| usable(v.clone()))
    })
}

/// Decode one `application/x-www-form-urlencoded` component.
fn form_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn ip_rate_limit_detection(ip: &str, max: usize) -> Detection {
    Detection {
        rule_id: 96001,
        rule_name: "Credential Stuffing: IP Rate Limit".to_string(),
        attack_type: AttackType::ProtocolAttack,
        matched_value: format!("IP {} exceeded {} failures", ip, max),
        location: "login".to_string(),
        base_score: 7,
        tags: vec!["credential-stuffing".to_string(), "rate-limit".to_string()],
    }
}

fn user_rate_limit_detection(username: &str, max: usize) -> Detection {
    Detection {
        rule_id: 96002,
        rule_name: "Credential Stuffing: User Rate Limit".to_string(),
        attack_type: AttackType::ProtocolAttack,
        matched_value: format!("User {} exceeded {} failures", mask_username(username), max),
        location: "login".to_string(),
        base_score: 6,
        tags: vec![
            "credential-stuffing".to_string(),
            "user-rate-limit".to_string(),
        ],
    }
}

/// Mask a username for logging (privacy)
fn mask_username(username: &str) -> String {
    // By characters: the username comes from the request body, and a byte
    // slice would panic inside a multi-byte character.
    if username.chars().count() <= 3 {
        return "***".to_string();
    }
    format!("{}***", username.chars().take(2).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_path_detection() {
        let protection = CredentialProtection::default();

        assert!(protection.is_login_path("/login"));
        assert!(protection.is_login_path("/api/login"));
        assert!(protection.is_login_path("/api/v1/auth"));
        assert!(!protection.is_login_path("/api/users"));
        assert!(!protection.is_login_path("/home"));
    }

    #[test]
    fn test_ip_rate_limiting() {
        let config = CredentialConfig {
            max_failures_per_ip: 3,
            ..Default::default()
        };
        let mut protection = CredentialProtection::new(config);

        // First few attempts should be allowed
        for i in 0..3 {
            let (decision, _) =
                protection.check_attempt("192.168.1.1", &format!("user{}", i), false);
            assert_eq!(
                decision,
                CredentialDecision::Allow,
                "Attempt {} should be allowed",
                i
            );
        }

        // Next attempt should be rate limited
        let (decision, detections) = protection.check_attempt("192.168.1.1", "user4", false);
        assert!(matches!(decision, CredentialDecision::RateLimited { .. }));
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_user_rate_limiting() {
        let config = CredentialConfig {
            max_failures_per_user: 3,
            max_failures_per_ip: 100, // High to not trigger
            ..Default::default()
        };
        let mut protection = CredentialProtection::new(config);

        // First few attempts from different IPs should be allowed
        for i in 0..3 {
            let (decision, _) =
                protection.check_attempt(&format!("192.168.1.{}", i), "target_user", false);
            assert_eq!(decision, CredentialDecision::Allow);
        }

        // Next attempt should be rate limited
        let (decision, _) = protection.check_attempt("192.168.1.100", "target_user", false);
        assert!(matches!(decision, CredentialDecision::RateLimited { .. }));
    }

    #[test]
    fn test_account_enumeration() {
        let config = CredentialConfig {
            max_usernames_per_ip: 3,
            max_failures_per_ip: 100, // High to not trigger
            ..Default::default()
        };
        let mut protection = CredentialProtection::new(config);

        // Try many usernames from one IP
        for i in 0..3 {
            let (decision, _) =
                protection.check_attempt("192.168.1.1", &format!("user{}", i), false);
            assert_eq!(decision, CredentialDecision::Allow);
        }

        // Next username should trigger enumeration detection
        let (decision, _) = protection.check_attempt("192.168.1.1", "user_new", false);
        assert!(matches!(
            decision,
            CredentialDecision::AccountEnumeration { .. }
        ));
    }

    #[test]
    fn test_distributed_attack() {
        let config = CredentialConfig {
            max_ips_per_user: 3,
            max_failures_per_ip: 100,
            max_failures_per_user: 100,
            ..Default::default()
        };
        let mut protection = CredentialProtection::new(config);

        // Attack from many IPs
        for i in 0..3 {
            let (decision, _) =
                protection.check_attempt(&format!("192.168.1.{}", i), "target", false);
            assert_eq!(decision, CredentialDecision::Allow);
        }

        // Next IP should trigger distributed attack detection
        let (decision, _) = protection.check_attempt("192.168.1.100", "target", false);
        assert!(matches!(
            decision,
            CredentialDecision::DistributedAttack { .. }
        ));
    }

    #[test]
    fn test_successful_login_allowed() {
        let mut protection = CredentialProtection::default();

        // Successful logins should always be allowed
        let (decision, detections) = protection.check_attempt("192.168.1.1", "user", true);
        assert_eq!(decision, CredentialDecision::Allow);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_login_path_is_a_path_segment_match() {
        let protection = CredentialProtection::default();
        assert!(protection.is_login_path("/auth"));
        assert!(protection.is_login_path("/auth/callback"));
        assert!(protection.is_login_path("/LOGIN?next=/"));
        assert!(!protection.is_login_path("/authors/42"));
        assert!(!protection.is_login_path("/loginhistory"));
    }

    #[test]
    fn test_precheck_reads_without_recording() {
        let config = CredentialConfig {
            max_failures_per_ip: 2,
            max_failures_per_user: 100,
            ..Default::default()
        };
        let mut protection = CredentialProtection::new(config);
        assert_eq!(
            protection.precheck("10.0.0.1", None).0,
            CredentialDecision::Allow
        );
        assert_eq!(
            protection.stats().tracked_ips,
            0,
            "precheck records nothing"
        );
        protection.record_attempt("10.0.0.1", None, false);
        protection.record_attempt("10.0.0.1", None, false);
        assert!(protection.precheck("10.0.0.1", None).0.is_blocked());
        assert!(!protection.precheck("10.0.0.2", None).0.is_blocked());
        assert_eq!(
            protection.stats().tracked_users,
            0,
            "an unknown username is not tracked as a user"
        );
    }

    #[test]
    fn test_extract_username() {
        let fields: Vec<String> = ["username", "email"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            extract_username(b"username=alice&password=x", &fields).as_deref(),
            Some("alice")
        );
        assert_eq!(
            extract_username(b"password=x&email=bob%40example.com", &fields).as_deref(),
            Some("bob@example.com")
        );
        assert_eq!(
            extract_username(br#"{"Username": "carol", "password": "x"}"#, &fields).as_deref(),
            Some("carol")
        );
        assert_eq!(extract_username(b"password=x", &fields), None);
        assert_eq!(extract_username(b"username=&password=x", &fields), None);
        assert_eq!(extract_username(br#"{"username": 7}"#, &fields), None);
    }

    #[test]
    fn test_username_masking() {
        assert_eq!(mask_username("ab"), "***");
        assert_eq!(mask_username("admin"), "ad***");
        assert_eq!(mask_username("john.doe@example.com"), "jo***");
        assert_eq!(mask_username("€uro-user"), "€u***");
    }
}
