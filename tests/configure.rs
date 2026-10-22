//! The proxy sends the agent's `config { }` block on every connection (each
//! pooled connection at startup, and again on every reconnect). These tests
//! pin down what applying it repeatedly or partially must do.

use serde_json::json;
use zentinel_agent_protocol::v2::AgentHandlerV2;
use zentinel_agent_waf::{ConfigureOutcome, WafAgent, WafConfig};

fn agent_with(f: impl FnOnce(&mut WafConfig)) -> WafAgent {
    let mut config = WafConfig::default();
    f(&mut config);
    WafAgent::new(config).expect("agent")
}

/// Fails `n` logins from one IP; returns whether the last one was blocked.
async fn fail_logins(agent: &WafAgent, n: usize) -> bool {
    let mut blocked = false;
    for _ in 0..n {
        blocked = agent
            .check_credential_attempt("/login", "203.0.113.9", "alice", false)
            .await;
    }
    blocked
}

fn credential_block() -> serde_json::Value {
    json!({"credential-protection": {"enabled": true, "max-failures-per-ip": 3}})
}

#[tokio::test]
async fn identical_config_twice_keeps_credential_counters() {
    let agent = agent_with(|_| {});
    assert!(agent.on_configure(credential_block(), None).await);

    // Three failures: at the limit, not over it.
    assert!(!fail_logins(&agent, 3).await);

    // The proxy reconnects and sends the same block again.
    assert!(agent.on_configure(credential_block(), None).await);
    assert_eq!(
        agent.apply_config(&credential_block()).await.unwrap(),
        ConfigureOutcome::Unchanged
    );

    // The fourth failure goes over the limit: the counter survived.
    assert!(
        fail_logins(&agent, 1).await,
        "a repeated configure reset the credential-stuffing counter"
    );
}

#[tokio::test]
async fn unrelated_change_keeps_credential_counters() {
    let agent = agent_with(|_| {});
    assert!(agent.on_configure(credential_block(), None).await);
    assert!(!fail_logins(&agent, 3).await);

    let mut changed = credential_block();
    changed["paranoia-level"] = json!(2);
    match agent.apply_config(&changed).await.unwrap() {
        ConfigureOutcome::Applied { changed } => {
            assert_eq!(changed, vec!["paranoia-level".to_string()])
        }
        other => panic!("expected Applied, got {other:?}"),
    }
    assert!(fail_logins(&agent, 1).await);

    // Changing credential protection's own settings starts it fresh.
    let mut retuned = changed.clone();
    retuned["credential-protection"]["max-failures-per-ip"] = json!(4);
    assert!(agent.on_configure(retuned, None).await);
    assert_eq!(agent.credential_tracked_ips().await, 0);
}

#[tokio::test]
async fn partial_config_keeps_cli_values() {
    let agent = agent_with(|c| {
        c.paranoia_level = 3;
        c.block_mode = false;
        c.exclude_paths = vec!["/health".to_string()];
        c.max_body_size = 4096;
    });
    assert!(agent.on_configure(json!({"sqli": false}), None).await);

    let active = agent.active_config().await;
    assert_eq!(active["sqli"], json!(false));
    assert_eq!(active["paranoia-level"], json!(3));
    assert_eq!(active["block-mode"], json!(false));
    assert_eq!(active["exclude-paths"], json!(["/health"]));
    assert_eq!(active["max-body-size"], json!(4096));

    // A nested block merges too: other scoring settings keep their values.
    let before = active["scoring"].clone();
    assert!(
        agent
            .on_configure(json!({"scoring": {"block-threshold": 40}}), None)
            .await
    );
    let after = agent.active_config().await["scoring"].clone();
    assert_eq!(after["block-threshold"], json!(40));
    assert_eq!(after["log-threshold"], before["log-threshold"]);
}

#[tokio::test]
async fn single_item_list_arrives_as_a_scalar() {
    // `exclude-paths "/metrics"` in KDL reaches the agent as a string.
    let agent = agent_with(|_| {});
    assert!(
        agent
            .on_configure(json!({"exclude-paths": "/metrics"}), None)
            .await
    );
    assert_eq!(
        agent.active_config().await["exclude-paths"],
        json!(["/metrics"])
    );
}

#[tokio::test]
async fn unknown_keys_are_rejected_and_change_nothing() {
    let agent = agent_with(|c| c.paranoia_level = 2);
    let before = agent.active_config().await;

    assert!(
        !agent.on_configure(json!({"paranoia-levle": 4}), None).await,
        "a misspelled top-level key was accepted"
    );
    assert!(
        !agent
            .on_configure(json!({"scoring": {"block-treshold": 1}}), None)
            .await,
        "a misspelled nested key was accepted"
    );
    assert!(!agent.on_configure(json!({"sqli": "maybe"}), None).await);
    assert!(
        !agent
            .on_configure(json!(["not", "an", "object"]), None)
            .await
    );

    assert_eq!(agent.active_config().await, before);
}
