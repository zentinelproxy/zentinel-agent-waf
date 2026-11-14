//! Credential-stuffing protection on live traffic (#7).
//!
//! These drive the agent the way the proxy does, over the v2 UDS protocol:
//! request headers (and body) for a login, then the response headers whose
//! status says whether the login failed. Before #7 the agent never called
//! credential protection from the request path, so none of this blocked.

use base64::Engine;
use std::collections::HashMap;
use std::time::Duration;
use tempfile::tempdir;
use zentinel_agent_protocol::v2::{AgentClientV2Uds, UdsAgentServerV2};
use zentinel_agent_protocol::{
    Decision, RequestBodyChunkEvent, RequestHeadersEvent, RequestMetadata, ResponseHeadersEvent,
};
use zentinel_agent_waf::config::CredentialProtectionConfig;
use zentinel_agent_waf::{WafAgent, WafConfig};

async fn start(config: WafConfig) -> (tempfile::TempDir, AgentClientV2Uds) {
    let dir = tempdir().expect("temp dir");
    let socket = dir.path().join("waf-cred.sock");
    let agent = WafAgent::new(config).expect("agent");
    let server = UdsAgentServerV2::new("test-waf", socket.clone(), Box::new(agent));
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = AgentClientV2Uds::new(
        "test-client",
        socket.to_string_lossy().to_string(),
        Duration::from_secs(5),
    )
    .await
    .expect("client");
    client.connect().await.expect("connect");
    (dir, client)
}

fn config(max_failures_per_ip: usize) -> WafConfig {
    WafConfig {
        credential_protection: CredentialProtectionConfig {
            enabled: true,
            max_failures_per_ip,
            max_failures_per_user: 100,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn headers_event(client_ip: &str, method: &str, uri: &str) -> RequestHeadersEvent {
    let id = uuid::Uuid::new_v4().to_string();
    let mut headers = HashMap::new();
    headers.insert("Host".to_string(), vec!["example.com".to_string()]);
    headers.insert(
        "Content-Type".to_string(),
        vec!["application/x-www-form-urlencoded".to_string()],
    );
    RequestHeadersEvent {
        metadata: RequestMetadata {
            correlation_id: id.clone(),
            request_id: id,
            client_ip: client_ip.to_string(),
            client_port: 40000,
            server_name: Some("example.com".to_string()),
            protocol: "HTTP/1.1".to_string(),
            tls_version: None,
            tls_cipher: None,
            route_id: None,
            upstream_id: None,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            traceparent: None,
        },
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
    }
}

/// One login through the agent: headers, a form body naming `username`, and
/// (if the request was let through) the upstream's response with `status`.
/// Returns the request-phase decision that blocked it, if any.
async fn login(
    client: &AgentClientV2Uds,
    client_ip: &str,
    method: &str,
    uri: &str,
    username: &str,
    status: u16,
) -> Option<Decision> {
    let event = headers_event(client_ip, method, uri);
    let id = event.metadata.correlation_id.clone();
    let r = client
        .send_request_headers(&id, &event)
        .await
        .expect("headers");
    if !matches!(r.decision, Decision::Allow) {
        return Some(r.decision);
    }
    let body = format!("username={username}&password=hunter2");
    let chunk = RequestBodyChunkEvent {
        correlation_id: id.clone(),
        data: base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
        is_last: true,
        total_size: Some(body.len()),
        chunk_index: 0,
        bytes_received: body.len(),
    };
    let r = client
        .send_request_body_chunk(&id, &chunk)
        .await
        .expect("body");
    if !matches!(r.decision, Decision::Allow) {
        return Some(r.decision);
    }
    let response = ResponseHeadersEvent {
        correlation_id: id.clone(),
        status,
        headers: HashMap::new(),
    };
    client
        .send_response_headers(&id, &response)
        .await
        .expect("response headers");
    None
}

#[tokio::test]
async fn repeated_failed_logins_from_one_client_are_blocked() {
    let (_dir, client) = start(config(3)).await;

    for i in 0..3 {
        assert_eq!(
            login(&client, "203.0.113.9", "POST", "/login", "alice", 401).await,
            None,
            "failed login {i} is within the limit"
        );
    }
    match login(&client, "203.0.113.9", "POST", "/login", "alice", 401).await {
        Some(Decision::Block { status, .. }) => assert_eq!(status, 429),
        other => panic!("the 4th login after 3 failures must be blocked, got {other:?}"),
    }
    // A different user from the same client is blocked too: the limit is
    // per client, not per username.
    assert!(
        login(&client, "203.0.113.9", "POST", "/login", "bob", 401)
            .await
            .is_some(),
        "the client is over its limit for every username"
    );

    // Another client is not affected.
    assert_eq!(
        login(&client, "198.51.100.7", "POST", "/login", "alice", 401).await,
        None
    );
    // Non-login traffic from the blocked client is not affected.
    assert_eq!(
        login(&client, "203.0.113.9", "POST", "/search", "alice", 401).await,
        None
    );
}

#[tokio::test]
async fn successful_logins_and_non_login_methods_do_not_count() {
    let (_dir, client) = start(config(2)).await;

    for _ in 0..10 {
        assert_eq!(
            login(&client, "203.0.113.10", "POST", "/login", "alice", 200).await,
            None,
            "successful logins are not failures"
        );
        assert_eq!(
            login(&client, "203.0.113.10", "GET", "/login", "alice", 401).await,
            None,
            "a GET of the login page is not a login attempt"
        );
    }
}

#[tokio::test]
async fn repeated_failures_against_one_username_are_blocked() {
    let mut config = config(100);
    config.credential_protection.max_failures_per_user = 2;
    let (_dir, client) = start(config).await;

    // Two clients each fail once against the same account.
    assert_eq!(
        login(&client, "203.0.113.11", "POST", "/login", "victim", 401).await,
        None
    );
    assert_eq!(
        login(&client, "203.0.113.12", "POST", "/login", "victim", 401).await,
        None
    );
    // A third client trying the same account is refused once its body names
    // the user.
    assert!(
        login(&client, "203.0.113.13", "POST", "/login", "victim", 401)
            .await
            .is_some(),
        "the account is over its failure limit"
    );
    // Other accounts from that client still go through.
    assert_eq!(
        login(&client, "203.0.113.13", "POST", "/login", "someone", 401).await,
        None
    );
}

#[tokio::test]
async fn disabled_protection_never_blocks() {
    let mut config = config(1);
    config.credential_protection.enabled = false;
    let (_dir, client) = start(config).await;
    for _ in 0..5 {
        assert_eq!(
            login(&client, "203.0.113.14", "POST", "/login", "alice", 401).await,
            None
        );
    }
}

#[tokio::test]
async fn detect_only_mode_marks_but_does_not_block() {
    let mut config = config(1);
    config.block_mode = false;
    let (_dir, client) = start(config).await;
    assert_eq!(
        login(&client, "203.0.113.15", "POST", "/login", "alice", 401).await,
        None
    );
    let event = headers_event("203.0.113.15", "POST", "/login");
    let r = client
        .send_request_headers(&event.metadata.correlation_id, &event)
        .await
        .expect("headers");
    assert!(matches!(r.decision, Decision::Allow));
    assert!(
        r.audit.rule_ids.contains(&"96001".to_string()),
        "the over-limit attempt is reported: {:?}",
        r.audit
    );
}
