//! OWASP CRS Compatibility Tests
//!
//! Tests based on OWASP Core Rule Set test cases.
//! These ensure detection parity with ModSecurity CRS.
//!
//! Note: Some tests are marked with #[ignore] because they require
//! additional rule coverage that is planned for future releases.

use zentinel_agent_waf::{Detection, WafConfig, WafEngine};

fn create_engine() -> WafEngine {
    WafEngine::new(WafConfig::default()).expect("Failed to create engine")
}

fn create_paranoid_engine(level: u8) -> WafEngine {
    let mut config = WafConfig::default();
    config.paranoia_level = level;
    WafEngine::new(config).expect("Failed to create engine")
}

fn has_detection(detections: &[Detection]) -> bool {
    !detections.is_empty()
}

// =============================================================================
// CRS 942: SQL Injection
// =============================================================================

mod crs_942_sqli {
    use super::*;

    /// 942100: SQL Injection Attack Detected
    #[test]
    fn test_942100_basic() {
        let engine = create_engine();
        // Core SQLi payloads that we MUST detect
        let payloads = vec![
            "1' OR '1'='1",
            "' OR 1=1--",
            "1 UNION SELECT password FROM users",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "942100: Failed to detect: {}",
                payload
            );
        }
    }

    /// 942140: SQL Injection - Common DB Names
    #[test]
    fn test_942140_db_names() {
        let engine = create_engine();
        let payloads = vec!["information_schema", "sys.tables", "mysql.user"];

        for payload in payloads {
            let query = format!("' UNION SELECT * FROM {}", payload);
            let detections = engine.check(&query, "query");
            assert!(
                has_detection(&detections),
                "942140: Failed to detect DB name: {}",
                payload
            );
        }
    }

    /// 942200-942260: SQL Functions
    #[test]
    fn test_942200_functions() {
        let engine = create_engine();
        let payloads = vec!["SLEEP(", "WAITFOR DELAY", "BENCHMARK("];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "942200: Failed to detect function: {}",
                payload
            );
        }
    }

    /// 942300-942360: SQL Keywords
    #[test]
    fn test_942300_keywords() {
        let engine = create_engine();
        let payloads = vec!["UNION SELECT", "UNION ALL SELECT"];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "942300: Failed to detect keyword: {}",
                payload
            );
        }
    }
}

// =============================================================================
// CRS 941: XSS
// =============================================================================

mod crs_941_xss {
    use super::*;

    /// 941100: XSS - Script Tags
    #[test]
    fn test_941100_script_tags() {
        let engine = create_engine();
        let payloads = vec![
            "<script>alert(1)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<script src=http://evil.com/evil.js>",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "941100: Failed to block: {}",
                payload
            );
        }
    }

    /// 941110: XSS - Event Handlers
    #[test]
    fn test_941110_event_handlers() {
        let engine = create_engine();
        let payloads = vec![
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<svg onload=alert(1)>",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "941110: Failed to block: {}",
                payload
            );
        }
    }

    /// 941130-941160: JavaScript URIs
    #[test]
    fn test_941130_javascript_uri() {
        let engine = create_engine();
        let payloads = vec!["javascript:alert(1)"];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "941130: Failed to detect: {}",
                payload
            );
        }
    }

    /// 941180: XSS - DOM Methods (requires additional rules)
    #[test]
    #[ignore = "Requires additional DOM method rules - planned for future"]
    fn test_941180_dom_methods() {
        let engine = create_engine();
        let payloads = vec!["document.cookie", "document.write(", "eval("];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "941180: Failed to detect: {}",
                payload
            );
        }
    }
}

// =============================================================================
// CRS 930: Local File Inclusion (LFI)
// =============================================================================

mod crs_930_lfi {
    use super::*;

    /// 930100-930110: Path Traversal
    #[test]
    fn test_930100_path_traversal() {
        let engine = create_engine();
        let payloads = vec!["../../../etc/passwd", "....//....//etc/passwd"];

        for payload in payloads {
            let detections = engine.check(payload, "path");
            assert!(
                has_detection(&detections),
                "930100: Failed to block: {}",
                payload
            );
        }
    }

    /// 930120: OS File Detection
    #[test]
    fn test_930120_os_files() {
        let engine = create_engine();
        let payloads = vec!["/etc/passwd", "/etc/shadow"];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "930120: Failed to detect: {}",
                payload
            );
        }
    }
}

// =============================================================================
// CRS 932: Remote Code Execution (RCE)
// =============================================================================

mod crs_932_rce {
    use super::*;

    /// 932100-932110: Unix Command Injection
    #[test]
    fn test_932100_unix_injection() {
        let engine = create_engine();
        let payloads = vec![";cat /etc/passwd", "|id", "$(id)", "`id`"];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "932100: Failed to block: {}",
                payload
            );
        }
    }
}

// =============================================================================
// CRS 913: Scanner Detection
// =============================================================================

mod crs_913_scanners {
    use super::*;

    /// 913100: User-Agent Based Scanner Detection
    #[test]
    fn test_913100_scanner_ua() {
        let engine = create_engine();
        let scanners = vec!["sqlmap/1.0-dev", "Nikto/2.1.6", "Nmap Scripting Engine"];

        for ua in scanners {
            let detections = engine.check(ua, "header:User-Agent");
            assert!(
                has_detection(&detections),
                "913100: Failed to detect scanner: {}",
                ua
            );
        }
    }
}

// =============================================================================
// CRS 934: Node.js/SSTI
// =============================================================================

mod crs_934_ssti {
    use super::*;

    /// 934100: Server-Side Template Injection
    #[test]
    fn test_934100_ssti() {
        let engine = create_engine();
        let payloads = vec!["{{7*7}}", "${7*7}"];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "934100: Failed to detect SSTI: {}",
                payload
            );
        }
    }
}

// =============================================================================
// Paranoia Level Tests
// =============================================================================

mod paranoia_levels {
    use super::*;

    #[test]
    fn test_paranoia_level_1() {
        let engine = create_paranoid_engine(1);
        let detections = engine.check("' OR 1=1--", "query");
        assert!(has_detection(&detections), "PL1 should detect basic SQLi");
    }

    #[test]
    fn test_paranoia_level_2() {
        let engine = create_paranoid_engine(2);
        // PL2 detects environment variable patterns
        let detections = engine.check("${PATH}", "query");
        assert!(
            has_detection(&detections),
            "PL2 should catch env var patterns"
        );
    }

    #[test]
    fn test_paranoia_level_3_xss_evasion() {
        let engine = create_paranoid_engine(3);
        // PL3 catches null byte obfuscation
        let detections = engine.check("scr\x00ipt", "query");
        assert!(
            has_detection(&detections),
            "PL3 should catch null byte XSS evasion"
        );
    }

    #[test]
    fn test_paranoia_level_3_cmdi_evasion() {
        let engine = create_paranoid_engine(3);
        // PL3 catches $IFS bypass
        let detections = engine.check("cat$IFS/etc/passwd", "query");
        assert!(has_detection(&detections), "PL3 should catch $IFS bypass");
    }

    #[test]
    fn test_paranoia_level_4_xss() {
        let engine = create_paranoid_engine(4);
        // PL4 catches any angle bracket with letter
        let detections = engine.check("<a", "query");
        assert!(
            has_detection(&detections),
            "PL4 should catch any angle bracket"
        );
    }

    #[test]
    fn test_paranoia_level_4_cmdi() {
        let engine = create_paranoid_engine(4);
        // PL4 catches any pipe character
        let detections = engine.check("hello|world", "query");
        assert!(has_detection(&detections), "PL4 should catch any pipe");
    }

    #[test]
    fn test_paranoia_level_4_traversal() {
        let engine = create_paranoid_engine(4);
        // PL4 catches any double dot
        let detections = engine.check("file..txt", "query");
        assert!(
            has_detection(&detections),
            "PL4 should catch any double dot"
        );
    }

    #[test]
    fn test_paranoia_level_4_ssti() {
        let engine = create_paranoid_engine(4);
        // PL4 catches any double brace
        let detections = engine.check("Hello {{ name }}", "query");
        assert!(
            has_detection(&detections),
            "PL4 should catch any double brace"
        );
    }

    #[test]
    fn test_paranoia_level_increasing_rules() {
        // Verify that higher paranoia levels include more rules
        let engine1 = create_paranoid_engine(1);
        let engine2 = create_paranoid_engine(2);
        let engine3 = create_paranoid_engine(3);
        let engine4 = create_paranoid_engine(4);

        let count1 = engine1.rule_count();
        let count2 = engine2.rule_count();
        let count3 = engine3.rule_count();
        let count4 = engine4.rule_count();

        assert!(
            count2 >= count1,
            "PL2 should have >= rules than PL1: {} vs {}",
            count2,
            count1
        );
        assert!(
            count3 >= count2,
            "PL3 should have >= rules than PL2: {} vs {}",
            count3,
            count2
        );
        assert!(
            count4 >= count3,
            "PL4 should have >= rules than PL3: {} vs {}",
            count4,
            count3
        );

        // Check we have meaningful coverage at each level
        assert!(
            count1 >= 140,
            "PL1 should have at least 140 rules, got {}",
            count1
        );
        assert!(
            count4 >= 280,
            "PL4 should have at least 280 rules, got {}",
            count4
        );
    }
}

// =============================================================================
// Evasion Techniques
// =============================================================================

mod evasion {
    use super::*;

    #[test]
    fn test_case_variations() {
        let engine = create_engine();
        let payloads = vec!["SELECT * FROM users", "sElEcT * fRoM users"];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Should detect case variation: {}",
                payload
            );
        }
    }

    #[test]
    fn test_comment_injection() {
        let engine = create_engine();
        let payloads = vec!["UN/**/ION/**/SEL/**/ECT", "UNION/*comment*/SELECT"];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Should detect comment injection: {}",
                payload
            );
        }
    }
}
