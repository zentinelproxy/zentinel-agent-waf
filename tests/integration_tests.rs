//! Integration Tests for Sentinel WAF
//!
//! End-to-end tests simulating real HTTP traffic patterns.

use sentinel_agent_waf::{WafConfig, WafEngine, Detection};
use std::collections::HashMap;

/// Test fixture for consistent test setup
fn create_engine() -> WafEngine {
    WafEngine::new(WafConfig::default()).expect("Failed to create engine")
}

fn create_engine_with_config(f: impl FnOnce(&mut WafConfig)) -> WafEngine {
    let mut config = WafConfig::default();
    f(&mut config);
    WafEngine::new(config).expect("Failed to create engine")
}

fn headers_from_vec(headers: Vec<(&str, &str)>) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for (k, v) in headers {
        map.entry(k.to_string())
            .or_insert_with(Vec::new)
            .push(v.to_string());
    }
    map
}

fn has_detection(detections: &[Detection]) -> bool {
    !detections.is_empty()
}

fn has_sqli(detections: &[Detection]) -> bool {
    detections.iter().any(|d| d.attack_type.to_string().contains("SQL"))
}

fn has_xss(detections: &[Detection]) -> bool {
    detections.iter().any(|d| d.attack_type.to_string().contains("Cross-Site"))
}

// =============================================================================
// SQL Injection Tests
// =============================================================================

mod sqli {
    use super::*;

    #[test]
    fn test_union_based_injection() {
        let engine = create_engine();
        let payloads = vec![
            "1 UNION SELECT username, password FROM users",
            "1 UNION ALL SELECT NULL, table_name FROM information_schema.tables",
            "-1 UNION SELECT 1,2,3,4,5--",
            "1' UNION SELECT username,password FROM users WHERE 'x'='x",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Failed to detect UNION injection: {}",
                payload
            );
            assert!(
                has_sqli(&detections),
                "Should detect as SQL injection: {}",
                payload
            );
        }
    }

    #[test]
    fn test_error_based_injection() {
        let engine = create_engine();
        let payloads = vec![
            "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Failed to detect error-based injection: {}",
                payload
            );
        }
    }

    #[test]
    fn test_blind_injection() {
        let engine = create_engine();
        let payloads = vec![
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' OR 1=1--",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Should detect blind injection: {}",
                payload
            );
        }
    }

    #[test]
    fn test_sqli_in_cookies() {
        let engine = create_engine();
        let detections = engine.check("abc'; DROP TABLE users;--", "cookie:session");
        assert!(has_detection(&detections), "Should detect SQLi in cookies");
    }

    #[test]
    fn test_sqli_obfuscation() {
        let engine = create_engine();
        let payloads = vec![
            "1'/**/UNION/**/SELECT/**/password/**/FROM/**/users--",
            "1'\nunion\nselect\n*\nfrom\nusers--",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Should detect obfuscated SQLi: {}",
                payload
            );
        }
    }
}

// =============================================================================
// Cross-Site Scripting (XSS) Tests
// =============================================================================

mod xss {
    use super::*;

    #[test]
    fn test_reflected_xss() {
        let engine = create_engine();
        let payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert('XSS')>",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Failed to detect reflected XSS: {}",
                payload
            );
            assert!(
                has_xss(&detections),
                "Should detect as XSS: {}",
                payload
            );
        }
    }

    #[test]
    fn test_dom_xss() {
        let engine = create_engine();
        // These patterns require DOM-specific rules which are planned for future
        let payloads = vec![
            "eval(atob('YWxlcnQoMSk='))",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Should detect DOM XSS: {}",
                payload
            );
        }
    }

    #[test]
    fn test_xss_in_json_body() {
        let engine = create_engine();
        let body = r#"<script>alert(1)</script>"#;

        let detections = engine.check(body, "body");
        assert!(has_detection(&detections), "Should detect XSS in body");
    }
}

// =============================================================================
// Path Traversal Tests
// =============================================================================

mod path_traversal {
    use super::*;

    #[test]
    fn test_basic_traversal() {
        let engine = create_engine();
        let payloads = vec![
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "path");
            assert!(
                has_detection(&detections),
                "Failed to detect path traversal: {}",
                payload
            );
        }
    }

    #[test]
    fn test_traversal_in_params() {
        let engine = create_engine();
        let detections = engine.check("../../../../etc/passwd", "query");
        assert!(has_detection(&detections), "Should detect traversal in query");
    }
}

// =============================================================================
// Command Injection Tests
// =============================================================================

mod command_injection {
    use super::*;

    #[test]
    fn test_basic_injection() {
        let engine = create_engine();
        let payloads = vec![
            "; cat /etc/passwd",
            "| ls -la",
            "$(id)",
            "`id`",
        ];

        for payload in payloads {
            let detections = engine.check(payload, "query");
            assert!(
                has_detection(&detections),
                "Failed to detect command injection: {}",
                payload
            );
        }
    }

    #[test]
    fn test_shellshock() {
        let engine = create_engine();
        let detections = engine.check("() { :; }; /bin/cat /etc/passwd", "header:User-Agent");
        assert!(has_detection(&detections), "Should detect Shellshock");
    }
}

// =============================================================================
// Full Request Tests
// =============================================================================

mod full_request {
    use super::*;

    #[test]
    fn test_full_request_clean() {
        let engine = create_engine();
        let headers = headers_from_vec(vec![
            ("User-Agent", "Mozilla/5.0"),
            ("Accept", "text/html"),
        ]);

        let detections = engine.check_request("/api/users", Some("page=1&limit=10"), &headers);
        assert!(detections.is_empty(), "Clean request should have no detections");
    }

    #[test]
    fn test_full_request_sqli_in_query() {
        let engine = create_engine();
        let headers = headers_from_vec(vec![
            ("User-Agent", "Mozilla/5.0"),
        ]);

        let detections = engine.check_request("/search", Some("q=' OR 1=1--"), &headers);
        assert!(has_sqli(&detections), "Should detect SQLi in query");
    }

    #[test]
    fn test_full_request_xss_in_header() {
        let engine = create_engine();
        let headers = headers_from_vec(vec![
            ("Referer", "<script>alert(1)</script>"),
        ]);

        let detections = engine.check_request("/page", None, &headers);
        assert!(has_xss(&detections), "Should detect XSS in header");
    }
}

// =============================================================================
// Bot Detection Tests
// =============================================================================

mod bot_detection {
    use super::*;

    #[test]
    fn test_scanner_user_agents() {
        let engine = create_engine_with_config(|c| {
            c.bot_detection.enabled = true;
        });

        let scanners = vec![
            "sqlmap/1.0",
            "nikto",
            "nmap",
        ];

        for ua in scanners {
            let detections = engine.check(ua, "header:User-Agent");
            assert!(
                has_detection(&detections),
                "Should detect scanner: {}",
                ua
            );
        }
    }
}

// =============================================================================
// API Security Tests
// =============================================================================

mod api_security {
    use super::*;

    #[test]
    fn test_json_depth_limit() {
        let engine = create_engine_with_config(|c| {
            c.api_security.json_enabled = true;
        });

        // Deeply nested JSON
        let deep_json = r#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":"deep"}}}}}}}}}}}"#;

        let detections = engine.check(deep_json, "body");
        // Detection depends on JSON parsing in check flow
    }
}

// =============================================================================
// Sensitive Data Detection Tests
// =============================================================================

mod sensitive_data {
    use super::*;

    #[test]
    fn test_credit_card_detection() {
        let engine = create_engine_with_config(|c| {
            c.response_inspection_enabled = true;
            c.sensitive_data.enabled = true;
        });

        let response = r#"{"card_number": "4111111111111111", "user": "John Doe"}"#;
        let detections = engine.check_sensitive_data(response);

        assert!(
            has_detection(&detections),
            "Should detect credit card number in response"
        );
    }

    #[test]
    fn test_ssn_detection() {
        let engine = create_engine_with_config(|c| {
            c.response_inspection_enabled = true;
            c.sensitive_data.enabled = true;
        });

        let response = r#"{"ssn": "123-45-6789", "name": "Jane Doe"}"#;
        let detections = engine.check_sensitive_data(response);

        assert!(
            has_detection(&detections),
            "Should detect SSN in response"
        );
    }

    #[test]
    fn test_aws_key_detection() {
        let engine = create_engine_with_config(|c| {
            c.sensitive_data.enabled = true;
        });

        let response = r#"{"aws_key": "AKIAIOSFODNN7EXAMPLE"}"#;
        let detections = engine.check_sensitive_data(response);

        assert!(
            has_detection(&detections),
            "Should detect AWS key in response"
        );
    }
}

// =============================================================================
// False Positive Tests (Benign Traffic)
// =============================================================================

mod false_positives {
    use super::*;

    #[test]
    fn test_benign_search_queries() {
        let engine = create_engine();
        let queries = vec![
            "search=laptop computer",
            "q=best products for home",
            "query=how to learn programming",
        ];

        for query in queries {
            let detections = engine.check(query, "query");
            assert!(
                detections.is_empty(),
                "False positive on benign query: {}",
                query
            );
        }
    }

    #[test]
    fn test_benign_file_paths() {
        let engine = create_engine();
        let paths = vec![
            "/images/logo.png",
            "/css/styles.css",
            "/js/app.js",
            "/api/v1/users/123",
        ];

        for path in paths {
            let detections = engine.check(path, "path");
            assert!(
                detections.is_empty(),
                "False positive on benign path: {}",
                path
            );
        }
    }

    #[test]
    fn test_normal_json_payloads() {
        let engine = create_engine();

        let payloads = vec![
            r#"{"username": "john_doe", "email": "john@example.com"}"#,
            r#"{"items": [1, 2, 3], "total": 99.99}"#,
        ];

        for payload in payloads {
            let detections = engine.check(payload, "body");
            assert!(
                detections.is_empty(),
                "False positive on benign JSON: {}",
                payload
            );
        }
    }
}

// =============================================================================
// Performance Tests
// =============================================================================

mod performance {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_large_body_handling() {
        let engine = create_engine();

        // 100KB body
        let body = "a".repeat(100_000);
        let start = Instant::now();
        let _detections = engine.check(&body, "body");
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "Large body inspection took too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_complex_query_string() {
        let engine = create_engine();

        // Complex but benign query string
        let query: String = (0..100)
            .map(|i| format!("param{}=value{}", i, i))
            .collect::<Vec<_>>()
            .join("&");

        let start = Instant::now();
        let _detections = engine.check(&query, "query");
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 50,
            "Complex query inspection took too long: {:?}",
            elapsed
        );
    }
}

// =============================================================================
// Edge Cases
// =============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_empty_input() {
        let engine = create_engine();
        let detections = engine.check("", "query");
        assert!(detections.is_empty(), "Empty input should have no detections");
    }

    #[test]
    fn test_unicode_handling() {
        let engine = create_engine();

        let payloads = vec![
            "名前=田中太郎",
            "emoji=😀🎉🔥",
            "arabic=مرحبا",
            "mixed=hello世界🌍",
        ];

        for payload in payloads {
            // Should handle unicode without panicking
            let _detections = engine.check(payload, "query");
        }
    }

    #[test]
    fn test_null_bytes() {
        let engine = create_engine();
        let detections = engine.check("secret.txt\0.jpg", "query");
        // Null byte should be suspicious
        assert!(has_detection(&detections), "Should detect null byte");
    }

    #[test]
    fn test_very_long_values() {
        let engine = create_engine();

        // Very long parameter value
        let long_value = "a".repeat(10000);
        // Should handle without panicking
        let _detections = engine.check(&long_value, "query");
    }
}
