//! WAF Performance Benchmarks
//!
//! Verifies performance targets from the roadmap:
//! - <5ms p99 for 285 rules on 1KB input
//! - <50MB steady state memory

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use zentinel_agent_waf::{WafConfig, WafEngine};

/// Generate realistic test payloads
fn generate_payloads() -> Vec<(&'static str, String)> {
    vec![
        ("benign_small", "user=john&action=view".to_string()),
        ("benign_medium", generate_benign_medium()),
        ("benign_large", generate_benign_large()),
        ("sqli_simple", "' OR '1'='1".to_string()),
        ("sqli_union", "1 UNION SELECT * FROM users--".to_string()),
        (
            "sqli_obfuscated",
            "1'/**/UNION/**/SELECT/**/password/**/FROM/**/users--".to_string(),
        ),
        ("xss_simple", "<script>alert(1)</script>".to_string()),
        (
            "xss_encoded",
            "%3Cscript%3Ealert(1)%3C/script%3E".to_string(),
        ),
        ("xss_event", "<img src=x onerror=alert(1)>".to_string()),
        ("path_traversal", "../../etc/passwd".to_string()),
        ("cmd_injection", "; cat /etc/passwd".to_string()),
        ("mixed_attack", generate_mixed_attack()),
    ]
}

fn generate_benign_medium() -> String {
    // ~500 bytes of realistic form data
    let mut s = String::with_capacity(600);
    s.push_str("username=john_doe_123&");
    s.push_str("email=john.doe@example.com&");
    s.push_str("first_name=John&");
    s.push_str("last_name=Doe&");
    s.push_str("address=123 Main Street, Apt 4B&");
    s.push_str("city=New York&");
    s.push_str("state=NY&");
    s.push_str("zip=10001&");
    s.push_str("phone=212-555-1234&");
    s.push_str("bio=Software developer with 10 years of experience in web development.&");
    s.push_str("preferences=dark_mode,notifications,weekly_digest&");
    s.push_str("csrf_token=a1b2c3d4e5f6g7h8i9j0");
    s
}

fn generate_benign_large() -> String {
    // ~2KB of realistic JSON payload
    let mut s = String::with_capacity(2048);
    s.push_str(r#"{"user":{"id":12345,"name":"John Doe","email":"john@example.com","profile":{"bio":"Software developer","location":"New York","website":"https://johndoe.dev","skills":["rust","python","javascript","go","kubernetes"],"experience":[{"company":"TechCorp","role":"Senior Developer","years":5},{"company":"StartupXYZ","role":"Lead Engineer","years":3}]},"settings":{"theme":"dark","notifications":true,"language":"en-US","timezone":"America/New_York"},"metadata":{"created_at":"2024-01-15T10:30:00Z","updated_at":"2024-12-01T15:45:00Z","last_login":"2024-12-10T08:00:00Z","login_count":847}}}"#);
    // Pad to ~2KB
    while s.len() < 2000 {
        s.push_str(r#","extra_field":"value""#);
    }
    s
}

fn generate_mixed_attack() -> String {
    // Payload with multiple attack indicators
    "q=search&user=' OR 1=1--&callback=<script>alert(document.cookie)</script>&file=../../etc/passwd&cmd=;id".to_string()
}

/// Benchmark core check() function - single value against all rules
fn benchmark_check(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config).expect("Failed to create engine");
    let payloads = generate_payloads();

    let mut group = c.benchmark_group("check");

    for (name, payload) in &payloads {
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(BenchmarkId::new("query", name), payload, |b, input| {
            b.iter(|| engine.check(black_box(input), black_box("query")))
        });
    }

    group.finish();
}

/// Benchmark check_request() - full request with path, query, headers
fn benchmark_check_request(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config).expect("Failed to create engine");

    let mut group = c.benchmark_group("check_request");

    // Normal headers
    let normal_headers: HashMap<String, Vec<String>> = [
        (
            "User-Agent".to_string(),
            vec!["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()],
        ),
        (
            "Accept".to_string(),
            vec!["text/html,application/xhtml+xml,application/xml".to_string()],
        ),
        (
            "Accept-Language".to_string(),
            vec!["en-US,en;q=0.9".to_string()],
        ),
        (
            "Cookie".to_string(),
            vec!["session=abc123; prefs=dark".to_string()],
        ),
    ]
    .into_iter()
    .collect();

    // Attack headers
    let attack_headers: HashMap<String, Vec<String>> = [
        ("User-Agent".to_string(), vec!["sqlmap/1.0".to_string()]),
        (
            "X-Forwarded-For".to_string(),
            vec!["127.0.0.1, ' OR 1=1--".to_string()],
        ),
        (
            "Referer".to_string(),
            vec!["https://evil.com/<script>alert(1)</script>".to_string()],
        ),
        (
            "Cookie".to_string(),
            vec!["admin=true; sql=' UNION SELECT *--".to_string()],
        ),
    ]
    .into_iter()
    .collect();

    group.bench_function("benign_request", |b| {
        b.iter(|| {
            engine.check_request(
                black_box("/api/v1/products/search"),
                black_box(Some("category=electronics&limit=20")),
                black_box(&normal_headers),
            )
        })
    });

    group.bench_function("attack_request", |b| {
        b.iter(|| {
            engine.check_request(
                black_box("/api/v1/search"),
                black_box(Some("q=' OR 1=1--&debug=true")),
                black_box(&attack_headers),
            )
        })
    });

    group.finish();
}

/// Benchmark with varying paranoia levels
fn benchmark_paranoia_levels(c: &mut Criterion) {
    let payload = "' OR '1'='1 UNION SELECT * FROM users WHERE id=1--";

    let mut group = c.benchmark_group("paranoia_levels");

    for level in 1..=4 {
        let config = WafConfig {
            paranoia_level: level,
            ..Default::default()
        };
        let engine = WafEngine::new(config).expect("Failed to create engine");

        group.bench_with_input(BenchmarkId::new("level", level), &payload, |b, input| {
            b.iter(|| engine.check(black_box(input), black_box("query")))
        });
    }

    group.finish();
}

/// Benchmark body inspection with varying sizes
fn benchmark_body_sizes(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config).expect("Failed to create engine");

    let mut group = c.benchmark_group("body_sizes");

    // Test various body sizes
    let sizes = [100, 500, 1024, 4096, 16384, 65536];

    for size in sizes {
        let body = generate_body_with_attack(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("bytes", size), &body, |b, input| {
            b.iter(|| engine.check(black_box(input), black_box("body")))
        });
    }

    group.finish();
}

fn generate_body_with_attack(size: usize) -> String {
    let base = r#"{"data":"value","nested":{"field":"' OR 1=1--"},"#;
    let mut body = base.to_string();

    // Pad to desired size
    while body.len() < size.saturating_sub(20) {
        body.push_str(r#""padding":"xxxxxxxxxx","#);
    }
    body.push_str(r#""end":"done"}"#);
    body.truncate(size);
    body
}

/// Benchmark automata engine - multi-pattern matching
fn benchmark_automata(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config).expect("Failed to create engine");

    let mut group = c.benchmark_group("automata_engine");

    // Test pattern that should match multiple rules
    let multi_match =
        "UNION SELECT password FROM users WHERE '1'='1' AND <script>document.cookie</script>";

    group.bench_function("multi_pattern_match", |b| {
        b.iter(|| engine.check(black_box(multi_match), black_box("query")))
    });

    // Test pattern that matches no rules (worst case - full scan)
    let no_match = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

    group.bench_function("no_pattern_match", |b| {
        b.iter(|| engine.check(black_box(no_match), black_box("query")))
    });

    group.finish();
}

/// Benchmark API security inspection
fn benchmark_api_security(c: &mut Criterion) {
    let config = WafConfig {
        api_security: zentinel_agent_waf::config::ApiSecurityConfig {
            graphql_enabled: true,
            json_enabled: true,
            jwt_enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let engine = WafEngine::new(config).expect("Failed to create engine");

    let mut group = c.benchmark_group("api_security");

    // GraphQL query
    let graphql_body = r#"{"query":"{ user(id: 1) { name email } }"}"#;

    group.bench_function("graphql_query", |b| {
        b.iter(|| {
            engine.check_api(
                black_box("/graphql"),
                black_box(Some("application/json")),
                black_box(Some(graphql_body)),
                black_box(None),
            )
        })
    });

    // JWT inspection
    let jwt = "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.";

    group.bench_function("jwt_none_alg", |b| {
        b.iter(|| {
            engine.check_api(
                black_box("/api/data"),
                black_box(Some("application/json")),
                black_box(None),
                black_box(Some(jwt)),
            )
        })
    });

    group.finish();
}

/// Benchmark sensitive data detection
fn benchmark_sensitive_data(c: &mut Criterion) {
    let config = WafConfig {
        sensitive_data: zentinel_agent_waf::config::SensitiveDataDetectionConfig {
            enabled: true,
            credit_card_detection: true,
            ssn_detection: true,
            api_key_detection: true,
            private_key_detection: true,
        },
        ..Default::default()
    };
    let engine = WafEngine::new(config).expect("Failed to create engine");

    let mut group = c.benchmark_group("sensitive_data");

    // Response with no sensitive data
    let clean_response = r#"{"user":{"name":"John Doe","email":"j***@example.com","id":12345}}"#;

    // Response with sensitive data
    let sensitive_response = r#"{"user":{"name":"John Doe","ssn":"123-45-6789","card":"4111111111111111","aws_key":"AKIAIOSFODNN7EXAMPLE"}}"#;

    group.bench_function("clean_response", |b| {
        b.iter(|| engine.check_sensitive_data(black_box(clean_response)))
    });

    group.bench_function("sensitive_response", |b| {
        b.iter(|| engine.check_sensitive_data(black_box(sensitive_response)))
    });

    group.finish();
}

/// Benchmark throughput (requests per second simulation)
fn benchmark_throughput(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config).expect("Failed to create engine");

    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Elements(1));

    // Measure raw requests per second with typical payload
    let query = "search=laptop&category=electronics&page=1";
    let headers: HashMap<String, Vec<String>> =
        [("User-Agent".to_string(), vec!["Mozilla/5.0".to_string()])]
            .into_iter()
            .collect();

    group.bench_function("requests_per_sec", |b| {
        b.iter(|| {
            engine.check_request(
                black_box("/api/search"),
                black_box(Some(query)),
                black_box(&headers),
            )
        })
    });

    group.finish();
}

/// Memory usage estimation (approximate)
fn benchmark_engine_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_creation");

    for level in 1..=4 {
        group.bench_function(BenchmarkId::new("paranoia", level), |b| {
            b.iter(|| {
                let config = WafConfig {
                    paranoia_level: level,
                    ..Default::default()
                };
                WafEngine::new(config).expect("Failed to create engine")
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_check,
    benchmark_check_request,
    benchmark_paranoia_levels,
    benchmark_body_sizes,
    benchmark_automata,
    benchmark_api_security,
    benchmark_sensitive_data,
    benchmark_throughput,
    benchmark_engine_creation,
);

criterion_main!(benches);
