//! Integration tests for the WAF agent using the zentinel-agent-protocol v2.
//!
//! These tests spin up a UDS v2 agent server and connect via the v2 UDS client
//! to verify the full protocol flow.

use base64::Engine;
use zentinel_agent_protocol::{
    Decision, RequestBodyChunkEvent,
    RequestHeadersEvent, RequestMetadata, ResponseBodyChunkEvent,
};
use zentinel_agent_protocol::v2::{AgentClientV2Uds, UdsAgentServerV2};
use zentinel_agent_waf::{WafAgent, WafConfig};
use std::collections::HashMap;
use std::time::Duration;
use tempfile::tempdir;

/// Helper to start a WAF agent server and return the socket path
async fn start_test_server(config: WafConfig) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("Failed to create temp dir");
    let socket_path = dir.path().join("waf-test.sock");

    let agent = WafAgent::new(config).expect("Failed to create WAF agent");
    let server = UdsAgentServerV2::new("test-waf", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (dir, socket_path)
}

/// Create a client connected to the test server
async fn create_client(socket_path: &std::path::Path) -> AgentClientV2Uds {
    let client = AgentClientV2Uds::new(
        "test-client",
        socket_path.to_string_lossy().to_string(),
        Duration::from_secs(5),
    )
    .await
    .expect("Failed to create client");
    client.connect().await.expect("Failed to connect to agent");
    client
}

/// Create a basic request metadata
fn make_metadata() -> RequestMetadata {
    let id = uuid::Uuid::new_v4().to_string();
    RequestMetadata {
        correlation_id: id.clone(),
        request_id: id,
        client_ip: "127.0.0.1".to_string(),
        client_port: 12345,
        server_name: Some("example.com".to_string()),
        protocol: "HTTP/1.1".to_string(),
        tls_version: Some("TLSv1.3".to_string()),
        tls_cipher: None,
        route_id: Some("default".to_string()),
        upstream_id: None,
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        traceparent: None,
    }
}

/// Create a basic request headers event
fn make_request_headers(uri: &str, headers: HashMap<String, Vec<String>>) -> RequestHeadersEvent {
    RequestHeadersEvent {
        metadata: make_metadata(),
        method: "GET".to_string(),
        uri: uri.to_string(),
        headers,
    }
}

/// Create a request body chunk event
fn make_body_chunk(correlation_id: &str, data: &str, is_last: bool) -> RequestBodyChunkEvent {
    RequestBodyChunkEvent {
        correlation_id: correlation_id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        is_last,
        total_size: None,
        chunk_index: 0,
        bytes_received: data.len(),
    }
}

/// Create a response body chunk event
fn make_response_body_chunk(
    correlation_id: &str,
    data: &str,
    is_last: bool,
) -> ResponseBodyChunkEvent {
    ResponseBodyChunkEvent {
        correlation_id: correlation_id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        is_last,
        total_size: None,
        chunk_index: 0,
        bytes_sent: data.len(),
    }
}

/// Check if decision is Block
fn is_block(decision: &Decision) -> bool {
    matches!(decision, Decision::Block { .. })
}

/// Check if decision is Allow
fn is_allow(decision: &Decision) -> bool {
    matches!(decision, Decision::Allow)
}

// ============================================================================
// SQL Injection Tests
// ============================================================================

#[tokio::test]
async fn test_sqli_in_query_string_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");

    // Check for WAF headers
    let has_waf_blocked = response.response_headers.iter().any(|h| match h {
        zentinel_agent_protocol::HeaderOp::Set { name, value } => {
            name == "X-WAF-Blocked" && value == "true"
        }
        _ => false,
    });
    assert!(has_waf_blocked, "Expected X-WAF-Blocked header");
}

#[tokio::test]
async fn test_sqli_union_select_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/api?q=1 UNION SELECT * FROM users", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_sqli_detect_only_mode() {
    let config = WafConfig {
        block_mode: false,
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    // Should allow but add detection header
    assert!(is_allow(&response.decision), "Expected Allow decision");

    let has_waf_detected = response.request_headers.iter().any(|h| match h {
        zentinel_agent_protocol::HeaderOp::Set { name, .. } => name == "X-WAF-Detected",
        _ => false,
    });
    assert!(has_waf_detected, "Expected X-WAF-Detected header");
}

#[tokio::test]
async fn test_sqli_disabled_allows_attack() {
    let config = WafConfig {
        sqli_enabled: false,
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    // Should allow when SQLi detection is disabled
    assert!(is_allow(&response.decision), "Expected Allow decision");
}

// ============================================================================
// XSS Tests
// ============================================================================

#[tokio::test]
async fn test_xss_script_tag_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/page?name=<script>alert('xss')</script>", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_xss_event_handler_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/page?input=<img src=x onerror=alert(1)>", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_xss_javascript_uri_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/redirect?url=javascript:alert(1)", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_xss_in_header_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "X-Custom".to_string(),
        vec!["<script>evil()</script>".to_string()],
    );

    let event = make_request_headers("/api", headers);
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Path Traversal Tests
// ============================================================================

#[tokio::test]
async fn test_path_traversal_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/files/../../../etc/passwd", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_path_traversal_encoded_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // URL-encoded path traversal with sensitive file access triggers multiple rules
    let event = make_request_headers("/files/..%2f..%2f..%2fetc/passwd", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Command Injection Tests
// ============================================================================

#[tokio::test]
async fn test_command_injection_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/run?cmd=`whoami`", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_command_injection_pipe_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let event = make_request_headers("/exec?input=foo | cat /etc/passwd", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Path Exclusion Tests
// ============================================================================

#[tokio::test]
async fn test_excluded_path_allows_attack() {
    let config = WafConfig {
        exclude_paths: vec!["/health".to_string(), "/api/internal".to_string()],
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // Attack on excluded path should be allowed
    let event = make_request_headers("/health?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
}

#[tokio::test]
async fn test_non_excluded_path_blocks_attack() {
    let config = WafConfig {
        exclude_paths: vec!["/health".to_string()],
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // Attack on non-excluded path should be blocked
    let event = make_request_headers("/api?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Request Body Inspection Tests
// ============================================================================

#[tokio::test]
async fn test_body_sqli_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // First send headers (will pass)
    let headers_event = make_request_headers("/api/users", HashMap::new());
    let response = client
        .send_request_headers(&headers_event.metadata.correlation_id, &headers_event)
        .await
        .expect("Failed to send headers event");
    assert!(is_allow(&response.decision), "Expected Allow decision");

    // Then send malicious body
    let body_event = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"query": "SELECT * FROM users WHERE id=' OR '1'='1"}"#,
        true,
    );
    let response = client
        .send_request_body_chunk(&body_event.correlation_id, &body_event)
        .await
        .expect("Failed to send body event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_body_xss_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/comments", HashMap::new());
    let _ = client
        .send_request_headers(&headers_event.metadata.correlation_id, &headers_event)
        .await
        .expect("Failed to send headers event");

    let body_event = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"comment": "<script>document.cookie</script>"}"#,
        true,
    );
    let response = client
        .send_request_body_chunk(&body_event.correlation_id, &body_event)
        .await
        .expect("Failed to send body event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_body_chunked_attack_blocked() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/data", HashMap::new());
    let _ = client
        .send_request_headers(&headers_event.metadata.correlation_id, &headers_event)
        .await
        .expect("Failed to send headers event");

    // Send attack spread across multiple chunks
    let chunk1 = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"data": "foo"#,
        false,
    );
    let response = client
        .send_request_body_chunk(&chunk1.correlation_id, &chunk1)
        .await
        .expect("Failed to send chunk 1");
    assert!(
        is_allow(&response.decision),
        "Expected Allow for non-last chunk"
    );

    let chunk2 = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#" <script>alert(1)</script>"}"#,
        true,
    );
    let response = client
        .send_request_body_chunk(&chunk2.correlation_id, &chunk2)
        .await
        .expect("Failed to send chunk 2");
    assert!(is_block(&response.decision), "Expected Block for full body");
}

#[tokio::test]
async fn test_body_inspection_disabled_allows_attack() {
    let config = WafConfig {
        body_inspection_enabled: false,
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/users", HashMap::new());
    let _ = client
        .send_request_headers(&headers_event.metadata.correlation_id, &headers_event)
        .await
        .expect("Failed to send headers event");

    let body_event = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"query": "SELECT * FROM users WHERE id=' OR '1'='1"}"#,
        true,
    );
    let response = client
        .send_request_body_chunk(&body_event.correlation_id, &body_event)
        .await
        .expect("Failed to send body event");

    // Should allow when body inspection is disabled
    assert!(is_allow(&response.decision), "Expected Allow decision");
}

#[tokio::test]
async fn test_body_exceeds_max_size_skips_inspection() {
    let config = WafConfig {
        max_body_size: 50, // Very small limit
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/upload", HashMap::new());
    let _ = client
        .send_request_headers(&headers_event.metadata.correlation_id, &headers_event)
        .await
        .expect("Failed to send headers event");

    // Send a body that exceeds max size with an attack
    let large_body = format!(
        r#"{{"data": "{}' OR '1'='1"}}"#,
        "x".repeat(100) // Exceeds 50 byte limit
    );
    let body_event = make_body_chunk(&headers_event.metadata.correlation_id, &large_body, true);
    let response = client
        .send_request_body_chunk(&body_event.correlation_id, &body_event)
        .await
        .expect("Failed to send body event");

    // Should allow because body exceeds max size (skip inspection)
    assert!(is_allow(&response.decision), "Expected Allow decision");
}

// ============================================================================
// Response Body Inspection Tests
// ============================================================================

#[tokio::test]
async fn test_response_body_xss_detected() {
    let config = WafConfig {
        response_inspection_enabled: true,
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let correlation_id = uuid::Uuid::new_v4().to_string();
    let response_body = make_response_body_chunk(
        &correlation_id,
        "<html><script>alert('reflected')</script></html>",
        true,
    );
    let response = client
        .send_response_body_chunk(&response_body.correlation_id, &response_body)
        .await
        .expect("Failed to send response body event");

    // Response inspection adds detection header but doesn't block
    assert!(is_allow(&response.decision), "Expected Allow decision");

    let has_detection_header = response.response_headers.iter().any(|h| match h {
        zentinel_agent_protocol::HeaderOp::Set { name, .. } => name == "X-WAF-Response-Detected",
        _ => false,
    });
    assert!(
        has_detection_header,
        "Expected X-WAF-Response-Detected header"
    );
}

#[tokio::test]
async fn test_response_body_inspection_disabled_ignores_attack() {
    let config = WafConfig {
        response_inspection_enabled: false, // Default
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let correlation_id = uuid::Uuid::new_v4().to_string();
    let response_body = make_response_body_chunk(
        &correlation_id,
        "<html><script>alert('reflected')</script></html>",
        true,
    );
    let response = client
        .send_response_body_chunk(&response_body.correlation_id, &response_body)
        .await
        .expect("Failed to send response body event");

    // Should allow without detection headers when disabled
    assert!(is_allow(&response.decision), "Expected Allow decision");

    let has_detection_header = response.response_headers.iter().any(|h| match h {
        zentinel_agent_protocol::HeaderOp::Set { name, .. } => name == "X-WAF-Response-Detected",
        _ => false,
    });
    assert!(
        !has_detection_header,
        "Should not have detection header when disabled"
    );
}

// ============================================================================
// Clean Request Tests
// ============================================================================

#[tokio::test]
async fn test_clean_request_allowed() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["Mozilla/5.0".to_string()]);
    headers.insert("Accept".to_string(), vec!["text/html".to_string()]);

    let event = make_request_headers("/api/users?page=1&limit=10", headers);
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
    assert!(response.response_headers.is_empty());
}

#[tokio::test]
async fn test_clean_body_allowed() {
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/users", HashMap::new());
    let _ = client
        .send_request_headers(&headers_event.metadata.correlation_id, &headers_event)
        .await
        .expect("Failed to send headers event");

    let body_event = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"name": "John Doe", "email": "john@example.com"}"#,
        true,
    );
    let response = client
        .send_request_body_chunk(&body_event.correlation_id, &body_event)
        .await
        .expect("Failed to send body event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
}

// ============================================================================
// Scanner Detection Tests
// ============================================================================

#[tokio::test]
async fn test_scanner_user_agent_detected() {
    // With anomaly scoring, a single scanner detection may not reach block threshold
    // Use lower scoring threshold or detect-only mode
    let config = WafConfig {
        scoring: zentinel_agent_waf::ScoringConfig {
            block_threshold: 10, // Lower threshold for single detections
            ..Default::default()
        },
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["sqlmap/1.0".to_string()]);

    let event = make_request_headers("/api", headers);
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Paranoia Level Tests
// ============================================================================

#[tokio::test]
async fn test_paranoia_level_2_detects_more_attacks() {
    let config = WafConfig {
        paranoia_level: 2,
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // At paranoia level 2, more patterns are detected with lower threshold
    // Using a clearer attack pattern that triggers at paranoia 2
    let event = make_request_headers("/api?q='; WAITFOR DELAY '0:0:5'--", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_paranoia_level_1_less_sensitive() {
    let config = WafConfig {
        paranoia_level: 1,
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // At paranoia level 1, some ambiguous patterns are allowed
    // Simple keyword without context should be allowed
    let event = make_request_headers("/api?q=SELECT", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
}

// ============================================================================
// Configure Event Tests (Config Block)
// ============================================================================

/// Send a configuration update via the v2 protocol and return the response
async fn send_config(client: &AgentClientV2Uds, config_json: serde_json::Value) -> zentinel_agent_protocol::AgentResponse {
    let correlation_id = uuid::Uuid::new_v4().to_string();
    client
        .send_configure(&correlation_id, &config_json)
        .await
        .expect("Failed to send configure event")
}

#[tokio::test]
async fn test_configure_event_applies_paranoia_level() {
    // Start with default config (paranoia level 1)
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // First verify simple keyword is allowed at paranoia level 1
    let event = make_request_headers("/api?q=SELECT", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.decision), "Expected Allow at paranoia 1");

    // Send configure event to increase paranoia level to 2
    let response = send_config(&client, serde_json::json!({
        "paranoia-level": 2
    })).await;
    assert!(
        is_allow(&response.decision),
        "Expected Allow for valid config"
    );

    // Now use a clear attack pattern that blocks at paranoia 2
    let event = make_request_headers("/api?q='; WAITFOR DELAY '0:0:5'--", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(is_block(&response.decision), "Expected Block at paranoia 2");
}

#[tokio::test]
async fn test_configure_event_disables_sqli() {
    // Start with default config (SQLi enabled)
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // First verify SQLi is blocked
    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_block(&response.decision),
        "Expected Block with SQLi enabled"
    );

    // Send configure event to disable SQLi
    let response = send_config(&client, serde_json::json!({
        "sqli": false
    })).await;
    assert!(
        is_allow(&response.decision),
        "Expected Allow for valid config"
    );

    // Now SQLi should be allowed
    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_allow(&response.decision),
        "Expected Allow with SQLi disabled"
    );
}

#[tokio::test]
async fn test_configure_event_sets_detect_only_mode() {
    // Start with default config (block mode)
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // First verify XSS is blocked
    let event = make_request_headers("/page?x=<script>alert(1)</script>", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(is_block(&response.decision), "Expected Block in block mode");

    // Send configure event to set detect-only mode
    let response = send_config(&client, serde_json::json!({
        "block-mode": false
    })).await;
    assert!(
        is_allow(&response.decision),
        "Expected Allow for valid config"
    );

    // Now XSS should be detected but allowed
    let event = make_request_headers("/page?x=<script>alert(1)</script>", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_allow(&response.decision),
        "Expected Allow in detect-only mode"
    );

    // Verify detection header is present
    let has_waf_detected = response.request_headers.iter().any(|h| match h {
        zentinel_agent_protocol::HeaderOp::Set { name, .. } => name == "X-WAF-Detected",
        _ => false,
    });
    assert!(has_waf_detected, "Expected X-WAF-Detected header");
}

#[tokio::test]
async fn test_configure_event_sets_exclude_paths() {
    // Start with default config (no exclusions)
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // First verify /health is blocked with SQLi
    let event = make_request_headers("/health?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_block(&response.decision),
        "Expected Block without exclusions"
    );

    // Send configure event to exclude /health
    let response = send_config(&client, serde_json::json!({
        "exclude-paths": ["/health", "/metrics"]
    })).await;
    assert!(
        is_allow(&response.decision),
        "Expected Allow for valid config"
    );

    // Now /health should be excluded
    let event = make_request_headers("/health?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_allow(&response.decision),
        "Expected Allow for excluded path"
    );

    // But /api should still be blocked
    let event = make_request_headers("/api?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_block(&response.decision),
        "Expected Block for non-excluded path"
    );
}

#[tokio::test]
async fn test_configure_event_full_config() {
    // Start with default config
    let config = WafConfig::default();
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // Send full configuration via configure event
    let response = send_config(&client, serde_json::json!({
        "paranoia-level": 2,
        "sqli": true,
        "xss": true,
        "path-traversal": true,
        "command-injection": true,
        "protocol": true,
        "block-mode": true,
        "exclude-paths": ["/health"],
        "body-inspection": true,
        "max-body-size": 1048576,
        "response-inspection": false
    })).await;
    assert!(
        is_allow(&response.decision),
        "Expected Allow for valid config"
    );

    // Verify SQLi is blocked with clear attack pattern
    let event = make_request_headers("/api?q=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_block(&response.decision),
        "Expected Block for SQLi attack"
    );

    // Verify exclusion is active
    let event = make_request_headers("/health?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_allow(&response.decision),
        "Expected Allow for excluded path"
    );
}

#[tokio::test]
async fn test_configure_event_with_empty_config() {
    // Start with custom config
    let config = WafConfig {
        paranoia_level: 3,
        sqli_enabled: false,
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let client = create_client(&socket_path).await;

    // Send empty config - should use defaults
    let response = send_config(&client, serde_json::json!({})).await;
    assert!(
        is_allow(&response.decision),
        "Expected Allow for empty config"
    );

    // Defaults: paranoia_level=1, sqli=true, block_mode=true
    // SQLi should now be blocked (was disabled before reconfigure)
    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("Failed to send event");
    assert!(
        is_block(&response.decision),
        "Expected Block after reset to defaults"
    );
}
