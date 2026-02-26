//! WebSocket Inspection Tests for Zentinel WAF
//!
//! Tests for WebSocket frame inspection including attack detection,
//! fragmentation handling, and configuration options.

use zentinel_agent_waf::{WafAgent, WafConfig, WebSocketConfig};
use zentinel_agent_protocol::v2::AgentHandlerV2;
use zentinel_agent_protocol::{WebSocketFrameEvent, AgentResponse, WebSocketDecision};
use base64::Engine as Base64Engine;

/// Create a WebSocket-enabled agent for testing
fn create_websocket_agent() -> WafAgent {
    let mut config = WafConfig::default();
    config.websocket = WebSocketConfig {
        enabled: true,
        inspect_text_frames: true,
        inspect_binary_frames: false,
        max_frame_size: 65536,
        block_mode: true,
        accumulate_fragments: true,
        max_message_size: 1048576,
        block_close_code: 1008,
        block_close_reason: "WAF policy violation".to_string(),
    };
    WafAgent::new(config).expect("Failed to create agent")
}

/// Create a WebSocket agent with custom config
fn create_websocket_agent_with_config(f: impl FnOnce(&mut WebSocketConfig)) -> WafAgent {
    let mut config = WafConfig::default();
    config.websocket = WebSocketConfig::default();
    config.websocket.enabled = true;
    f(&mut config.websocket);
    WafAgent::new(config).expect("Failed to create agent")
}

/// Encode payload as base64 for WebSocket frame data
fn encode_payload(payload: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
}

/// Create a text frame event
fn text_frame(correlation_id: &str, payload: &str, fin: bool) -> WebSocketFrameEvent {
    WebSocketFrameEvent {
        correlation_id: correlation_id.to_string(),
        opcode: "text".to_string(),
        data: encode_payload(payload),
        client_to_server: true,
        frame_index: 0,
        fin,
        route_id: Some("test-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    }
}

/// Create a binary frame event
fn binary_frame(correlation_id: &str, data: &[u8], fin: bool) -> WebSocketFrameEvent {
    WebSocketFrameEvent {
        correlation_id: correlation_id.to_string(),
        opcode: "binary".to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        client_to_server: true,
        frame_index: 0,
        fin,
        route_id: Some("test-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    }
}

/// Create a continuation frame event
fn continuation_frame(correlation_id: &str, payload: &str, fin: bool, frame_index: u64) -> WebSocketFrameEvent {
    WebSocketFrameEvent {
        correlation_id: correlation_id.to_string(),
        opcode: "continuation".to_string(),
        data: encode_payload(payload),
        client_to_server: true,
        frame_index,
        fin,
        route_id: Some("test-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    }
}

/// Check if response indicates a block (close connection)
fn is_blocked(response: &AgentResponse) -> bool {
    match &response.websocket_decision {
        Some(WebSocketDecision::Close { .. }) => true,
        Some(WebSocketDecision::Drop) => true,
        _ => false,
    }
}

/// Check if response indicates allow
fn is_allowed(response: &AgentResponse) -> bool {
    match &response.websocket_decision {
        Some(WebSocketDecision::Allow) => true,
        None => true, // Default is allow
        _ => false,
    }
}

// =============================================================================
// SQL Injection via WebSocket Tests
// =============================================================================

mod sqli {
    use super::*;

    #[tokio::test]
    async fn test_sqli_in_text_frame() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-1", "1' OR '1'='1", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block SQL injection in WebSocket");
    }

    #[tokio::test]
    async fn test_union_injection_in_websocket() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-2", "1 UNION SELECT username, password FROM users", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block UNION injection in WebSocket");
    }

    #[tokio::test]
    async fn test_sqli_in_json_message() {
        let agent = create_websocket_agent();
        let json_payload = r#"{"query": "SELECT * FROM users WHERE id = '1' OR '1'='1'"}"#;
        let event = text_frame("ws-3", json_payload, true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should detect SQL injection in JSON WebSocket message");
    }
}

// =============================================================================
// XSS via WebSocket Tests
// =============================================================================

mod xss {
    use super::*;

    #[tokio::test]
    async fn test_xss_in_text_frame() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-xss-1", "<script>alert('XSS')</script>", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block XSS in WebSocket");
    }

    #[tokio::test]
    async fn test_xss_event_handler() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-xss-2", "<img src=x onerror=alert(1)>", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block XSS event handler in WebSocket");
    }

    #[tokio::test]
    async fn test_xss_in_chat_message() {
        let agent = create_websocket_agent();
        let json_payload = r#"{"type": "chat", "message": "<script>document.cookie</script>"}"#;
        let event = text_frame("ws-xss-3", json_payload, true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should detect XSS in chat message");
    }
}

// =============================================================================
// Command Injection via WebSocket Tests
// =============================================================================

mod command_injection {
    use super::*;

    #[tokio::test]
    async fn test_command_injection_in_websocket() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-cmd-1", "; cat /etc/passwd", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block command injection in WebSocket");
    }

    #[tokio::test]
    async fn test_command_substitution() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-cmd-2", "$(whoami)", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block command substitution in WebSocket");
    }
}

// =============================================================================
// Safe Content Tests
// =============================================================================

mod safe_content {
    use super::*;

    #[tokio::test]
    async fn test_normal_text_message() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-safe-1", "Hello, how are you today?", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow normal text message");
    }

    #[tokio::test]
    async fn test_normal_json_message() {
        let agent = create_websocket_agent();
        let json_payload = r#"{"type": "ping", "timestamp": 1234567890}"#;
        let event = text_frame("ws-safe-2", json_payload, true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow normal JSON message");
    }

    #[tokio::test]
    async fn test_safe_chat_message() {
        let agent = create_websocket_agent();
        let json_payload = r#"{"user": "alice", "message": "The quick brown fox jumps over the lazy dog"}"#;
        let event = text_frame("ws-safe-3", json_payload, true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow safe chat message");
    }
}

// =============================================================================
// Fragmented Message Tests
// =============================================================================

mod fragmentation {
    use super::*;

    #[tokio::test]
    async fn test_attack_split_across_fragments() {
        let agent = create_websocket_agent();

        // First fragment - partial attack
        let frame1 = WebSocketFrameEvent {
            correlation_id: "ws-frag-1".to_string(),
            opcode: "text".to_string(),
            data: encode_payload("1' OR "),
            client_to_server: true,
            frame_index: 0,
            fin: false,
            route_id: Some("test-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        // Should allow partial frame (not yet complete)
        let response1 = agent.on_websocket_frame(frame1).await;
        assert!(is_allowed(&response1), "Should allow partial frame");

        // Second fragment - completes the attack
        let frame2 = continuation_frame("ws-frag-1", "'1'='1", true, 1);

        let response2 = agent.on_websocket_frame(frame2).await;
        assert!(is_blocked(&response2), "Should block completed attack across fragments");
    }

    #[tokio::test]
    async fn test_safe_fragmented_message() {
        let agent = create_websocket_agent();

        // Fragment 1
        let frame1 = WebSocketFrameEvent {
            correlation_id: "ws-frag-safe".to_string(),
            opcode: "text".to_string(),
            data: encode_payload("Hello, "),
            client_to_server: true,
            frame_index: 0,
            fin: false,
            route_id: Some("test-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };
        let response1 = agent.on_websocket_frame(frame1).await;
        assert!(is_allowed(&response1), "Should allow first fragment");

        // Fragment 2
        let frame2 = continuation_frame("ws-frag-safe", "World!", true, 1);
        let response2 = agent.on_websocket_frame(frame2).await;
        assert!(is_allowed(&response2), "Should allow safe completed message");
    }
}

// =============================================================================
// Configuration Tests
// =============================================================================

mod configuration {
    use super::*;

    #[tokio::test]
    async fn test_websocket_inspection_disabled() {
        let agent = create_websocket_agent_with_config(|ws| {
            ws.enabled = false;
        });

        // Even with attack payload, should allow when disabled
        let event = text_frame("ws-disabled", "<script>alert('XSS')</script>", true);
        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow when WebSocket inspection disabled");
    }

    #[tokio::test]
    async fn test_text_frames_disabled() {
        let agent = create_websocket_agent_with_config(|ws| {
            ws.enabled = true;
            ws.inspect_text_frames = false;
        });

        let event = text_frame("ws-text-disabled", "<script>alert('XSS')</script>", true);
        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow text frames when inspection disabled");
    }

    #[tokio::test]
    async fn test_binary_frames_enabled() {
        let agent = create_websocket_agent_with_config(|ws| {
            ws.enabled = true;
            ws.inspect_binary_frames = true;
        });

        // Binary frame with text attack pattern
        let attack_bytes = b"<script>alert('XSS')</script>";
        let event = binary_frame("ws-binary", attack_bytes, true);
        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should detect attack in binary frame when enabled");
    }

    #[tokio::test]
    async fn test_binary_frames_disabled_by_default() {
        let agent = create_websocket_agent();

        // Binary frame with attack pattern should be allowed when binary inspection disabled
        let attack_bytes = b"<script>alert('XSS')</script>";
        let event = binary_frame("ws-binary-default", attack_bytes, true);
        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should skip binary frames by default");
    }

    #[tokio::test]
    async fn test_detect_only_mode() {
        let agent = create_websocket_agent_with_config(|ws| {
            ws.enabled = true;
            ws.block_mode = false;
        });

        let event = text_frame("ws-detect-only", "<script>alert('XSS')</script>", true);
        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow in detect-only mode");
    }
}

// =============================================================================
// Control Frame Tests
// =============================================================================

mod control_frames {
    use super::*;

    #[tokio::test]
    async fn test_ping_frame_passthrough() {
        let agent = create_websocket_agent();
        let event = WebSocketFrameEvent {
            correlation_id: "ws-ping".to_string(),
            opcode: "ping".to_string(),
            data: encode_payload(""),
            client_to_server: true,
            frame_index: 0,
            fin: true,
            route_id: Some("test-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow ping frames");
    }

    #[tokio::test]
    async fn test_pong_frame_passthrough() {
        let agent = create_websocket_agent();
        let event = WebSocketFrameEvent {
            correlation_id: "ws-pong".to_string(),
            opcode: "pong".to_string(),
            data: encode_payload(""),
            client_to_server: false,
            frame_index: 0,
            fin: true,
            route_id: Some("test-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow pong frames");
    }

    #[tokio::test]
    async fn test_close_frame_passthrough() {
        let agent = create_websocket_agent();
        let event = WebSocketFrameEvent {
            correlation_id: "ws-close".to_string(),
            opcode: "close".to_string(),
            data: encode_payload(""),
            client_to_server: true,
            frame_index: 0,
            fin: true,
            route_id: Some("test-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        let response = agent.on_websocket_frame(event).await;
        assert!(is_allowed(&response), "Should allow close frames");
    }
}

// =============================================================================
// Direction Tests
// =============================================================================

mod direction {
    use super::*;

    #[tokio::test]
    async fn test_client_to_server_inspection() {
        let agent = create_websocket_agent();
        let event = WebSocketFrameEvent {
            correlation_id: "ws-c2s".to_string(),
            opcode: "text".to_string(),
            data: encode_payload("<script>alert('XSS')</script>"),
            client_to_server: true,
            frame_index: 0,
            fin: true,
            route_id: Some("test-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block attack from client");
    }

    #[tokio::test]
    async fn test_server_to_client_inspection() {
        let agent = create_websocket_agent();
        let event = WebSocketFrameEvent {
            correlation_id: "ws-s2c".to_string(),
            opcode: "text".to_string(),
            data: encode_payload("<script>alert('XSS')</script>"),
            client_to_server: false,
            frame_index: 0,
            fin: true,
            route_id: Some("test-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block attack from server too");
    }
}

// =============================================================================
// SSTI Tests
// =============================================================================

mod ssti {
    use super::*;

    #[tokio::test]
    async fn test_ssti_jinja2() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-ssti-1", "{{7*7}}", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block Jinja2 SSTI in WebSocket");
    }

    #[tokio::test]
    async fn test_ssti_in_json() {
        let agent = create_websocket_agent();
        let json_payload = r#"{"template": "{{config.items()}}"}"#;
        let event = text_frame("ws-ssti-2", json_payload, true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block SSTI in JSON message");
    }
}

// =============================================================================
// Path Traversal Tests
// =============================================================================

mod path_traversal {
    use super::*;

    #[tokio::test]
    async fn test_path_traversal_in_websocket() {
        let agent = create_websocket_agent();
        let event = text_frame("ws-pt-1", "../../../etc/passwd", true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block path traversal in WebSocket");
    }

    #[tokio::test]
    async fn test_path_traversal_in_file_request() {
        let agent = create_websocket_agent();
        let json_payload = r#"{"action": "read_file", "path": "../../secret.txt"}"#;
        let event = text_frame("ws-pt-2", json_payload, true);

        let response = agent.on_websocket_frame(event).await;
        assert!(is_blocked(&response), "Should block path traversal in file request");
    }
}
