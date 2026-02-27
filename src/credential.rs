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

    fn record_attempt(&mut self, username: &str, success: bool) {
        self.last_attempt = Instant::now();
        if !success {
            self.failure_count += 1;
        }
        *self.usernames.entry(username.to_string()).or_insert(0) += 1;
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

    /// Check if a path is a login endpoint
    pub fn is_login_path(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        self.config
            .login_paths
            .iter()
            .any(|p| path_lower.starts_with(p))
    }

    /// Record a login attempt and check for attacks
    pub fn check_attempt(
        &mut self,
        ip: &str,
        username: &str,
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

        // Get or create user tracker
        let user_tracker = self
            .user_trackers
            .entry(username.to_string())
            .or_insert_with(UserTracker::new);

        // Reset if window expired
        if user_tracker.is_expired(window) {
            user_tracker.reset();
        }

        // Record the attempt
        user_tracker.record_attempt(ip, success);

        // Check velocity per IP
        if self.config.velocity_detection
            && !success
            && ip_tracker.failure_count > self.config.max_failures_per_ip
        {
            detections.push(Detection {
                rule_id: 96001,
                rule_name: "Credential Stuffing: IP Rate Limit".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!(
                    "IP {} exceeded {} failures",
                    ip, self.config.max_failures_per_ip
                ),
                location: "login".to_string(),
                base_score: 7,
                tags: vec!["credential-stuffing".to_string(), "rate-limit".to_string()],
            });

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
        if self.config.velocity_detection
            && !success
            && user_tracker.failure_count > self.config.max_failures_per_user
        {
            detections.push(Detection {
                rule_id: 96002,
                rule_name: "Credential Stuffing: User Rate Limit".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!(
                    "User {} exceeded {} failures",
                    mask_username(username),
                    self.config.max_failures_per_user
                ),
                location: "login".to_string(),
                base_score: 6,
                tags: vec![
                    "credential-stuffing".to_string(),
                    "user-rate-limit".to_string(),
                ],
            });

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
        if self.config.distributed_detection
            && !success
            && user_tracker.ips.len() > self.config.max_ips_per_user
        {
            detections.push(Detection {
                rule_id: 96004,
                rule_name: "Distributed Credential Attack".to_string(),
                attack_type: AttackType::ProtocolAttack,
                matched_value: format!(
                    "User {} attacked from {} IPs",
                    mask_username(username),
                    user_tracker.ips.len()
                ),
                location: "login".to_string(),
                base_score: 9,
                tags: vec!["credential-stuffing".to_string(), "distributed".to_string()],
            });

            return (
                CredentialDecision::DistributedAttack {
                    reason: format!(
                        "Distributed attack: {} IPs targeting user",
                        user_tracker.ips.len()
                    ),
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

/// Mask a username for logging (privacy)
fn mask_username(username: &str) -> String {
    if username.len() <= 3 {
        return "***".to_string();
    }
    format!("{}***", &username[..2])
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
    fn test_username_masking() {
        assert_eq!(mask_username("ab"), "***");
        assert_eq!(mask_username("admin"), "ad***");
        assert_eq!(mask_username("john.doe@example.com"), "jo***");
    }
}
