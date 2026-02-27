//! Zentinel WAF Agent Library
//!
//! A next-generation Web Application Firewall agent for Zentinel proxy that detects
//! and blocks common web attacks with anomaly-based scoring to reduce false positives.
//!
//! # Features
//!
//! - **200+ Detection Rules**: SQLi, XSS, command injection, SSTI, SSRF, and more
//! - **Anomaly Scoring**: Cumulative risk scores instead of binary block/allow
//! - **Rule Management**: Enable/disable rules, exclusions, overrides
//! - **Low False Positives**: Context-aware scoring with configurable thresholds
//!
//! # Example
//!
//! ```ignore
//! use zentinel_agent_waf::{WafAgent, WafConfig};
//! use zentinel_agent_protocol::v2::UdsAgentServerV2;
//!
//! let config = WafConfig::default();
//! let agent = WafAgent::new(config)?;
//! let server = UdsAgentServerV2::new("waf", "/tmp/waf.sock", Box::new(agent));
//! server.run().await?;
//! ```

pub mod api;
pub mod automata;
pub mod bot;
pub mod config;
pub mod credential;
pub mod detection;
pub mod engine;
pub mod federated;
pub mod intel;
pub mod metrics;
pub mod ml;
pub mod plugin;
pub mod rules;
pub mod scoring;
pub mod sensitive;
pub mod streaming;
pub mod supplychain;
pub mod vpatching;

// Re-exports for convenience
pub use config::{ScoringConfig, WafConfig, WafConfigJson, WebSocketConfig};
pub use detection::{AnomalyScore, Detection, WafDecision};
pub use engine::WafEngine;
pub use rules::{AttackType, Confidence, Rule, Severity};

use anyhow::Result;
use base64::Engine as Base64Engine;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestBodyChunkEvent, RequestHeadersEvent,
    ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketFrameEvent,
};

use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, CounterMetric, DrainReason, GaugeMetric,
    HealthStatus as V2HealthStatus, MetricsReport, ShutdownReason,
};

use std::sync::atomic::{AtomicU64, Ordering};

/// Body accumulator for tracking in-progress bodies (buffered mode)
#[derive(Debug, Default)]
struct BodyAccumulator {
    data: Vec<u8>,
}

/// Body inspection state - either buffered or streaming
enum BodyInspectionState {
    /// Buffered mode - accumulate full body before inspection
    Buffered(BodyAccumulator),
    /// Streaming mode - inspect incrementally with overlap buffer
    Streaming(streaming::StreamingInspector),
}

impl Default for BodyInspectionState {
    fn default() -> Self {
        BodyInspectionState::Buffered(BodyAccumulator::default())
    }
}

/// WebSocket message accumulator for fragmented messages
///
/// WebSocket messages can be split across multiple frames. This accumulator
/// collects frames until the FIN bit is set, then inspects the complete message.
#[derive(Debug, Default)]
struct WebSocketMessageAccumulator {
    /// Accumulated message data
    data: Vec<u8>,
    /// Opcode of the first frame (determines message type) - used for Debug
    #[allow(dead_code)]
    opcode: String,
    /// Whether this is a client-to-server message - used for Debug
    #[allow(dead_code)]
    client_to_server: bool,
    /// Number of frames accumulated
    frame_count: u64,
}

impl WebSocketMessageAccumulator {
    fn new(opcode: String, client_to_server: bool) -> Self {
        Self {
            data: Vec::new(),
            opcode,
            client_to_server,
            frame_count: 0,
        }
    }
}

/// Key for tracking WebSocket messages (per connection + direction)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct WebSocketKey {
    correlation_id: String,
    client_to_server: bool,
}

/// Health status for the WAF agent
///
/// Used for readiness/liveness probes in container orchestration.
#[derive(Debug, Clone, Default)]
pub struct HealthStatus {
    /// Overall health - true if all components are functional
    pub healthy: bool,
    /// Whether the WAF engine lock is acquirable
    pub engine_ok: bool,
    /// Number of rules loaded
    pub rule_count: usize,
    /// Current paranoia level
    pub paranoia_level: u8,
    /// Number of pending request body inspections
    pub pending_requests: usize,
    /// Number of pending response body inspections
    pub pending_responses: usize,
    /// List of issues encountered
    pub issues: Vec<String>,
}

impl HealthStatus {
    /// Returns true if the agent is healthy and ready to serve requests
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }
}

/// Metrics counters for v2 protocol reporting
#[derive(Debug, Default)]
pub struct WafMetrics {
    /// Total requests processed
    pub requests_total: AtomicU64,
    /// Total requests blocked
    pub blocks_total: AtomicU64,
    /// Total detections by attack type
    pub detections_sqli: AtomicU64,
    pub detections_xss: AtomicU64,
    pub detections_path_traversal: AtomicU64,
    pub detections_command_injection: AtomicU64,
    pub detections_other: AtomicU64,
}

impl WafMetrics {
    /// Increment detection counter by attack type
    fn increment_detection(&self, attack_type: &AttackType) {
        match attack_type {
            AttackType::SqlInjection => self.detections_sqli.fetch_add(1, Ordering::Relaxed),
            AttackType::Xss => self.detections_xss.fetch_add(1, Ordering::Relaxed),
            AttackType::PathTraversal => self
                .detections_path_traversal
                .fetch_add(1, Ordering::Relaxed),
            AttackType::CommandInjection => self
                .detections_command_injection
                .fetch_add(1, Ordering::Relaxed),
            _ => self.detections_other.fetch_add(1, Ordering::Relaxed),
        };
    }
}

/// WAF agent implementing the Zentinel agent protocol
pub struct WafAgent {
    engine: Arc<RwLock<WafEngine>>,
    pending_request_bodies: Arc<RwLock<HashMap<String, BodyInspectionState>>>,
    pending_response_bodies: Arc<RwLock<HashMap<String, BodyAccumulator>>>,
    /// WebSocket message accumulators for fragmented messages
    pending_websocket_messages: Arc<RwLock<HashMap<WebSocketKey, WebSocketMessageAccumulator>>>,
    /// Metrics counters for v2 protocol reporting
    metrics: Arc<WafMetrics>,
}

impl WafAgent {
    /// Create a new WAF agent with the given configuration
    pub fn new(config: WafConfig) -> Result<Self> {
        let engine = WafEngine::new(config)?;
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            pending_request_bodies: Arc::new(RwLock::new(HashMap::new())),
            pending_response_bodies: Arc::new(RwLock::new(HashMap::new())),
            pending_websocket_messages: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(WafMetrics::default()),
        })
    }

    /// Reconfigure the WAF engine with new settings
    pub async fn reconfigure(&self, config: WafConfig) -> Result<()> {
        let new_engine = WafEngine::new(config)?;
        *self.engine.write().await = new_engine;
        Ok(())
    }

    /// Health check for the WAF agent
    ///
    /// Returns a HealthStatus indicating whether all components are functional.
    /// Use this for readiness/liveness probes in container orchestration.
    pub async fn health_check(&self) -> HealthStatus {
        let mut status = HealthStatus::default();

        // Check engine lock is acquirable
        match tokio::time::timeout(std::time::Duration::from_millis(100), self.engine.read()).await
        {
            Ok(engine) => {
                status.engine_ok = true;
                status.rule_count = engine.rules().len();
                status.paranoia_level = engine.config.paranoia_level;
            }
            Err(_) => {
                status.engine_ok = false;
                status.issues.push("Engine lock timeout".to_string());
            }
        }

        // Check pending bodies maps are accessible
        match tokio::time::timeout(
            std::time::Duration::from_millis(50),
            self.pending_request_bodies.read(),
        )
        .await
        {
            Ok(pending) => {
                status.pending_requests = pending.len();
            }
            Err(_) => {
                status
                    .issues
                    .push("Request bodies lock timeout".to_string());
            }
        }

        match tokio::time::timeout(
            std::time::Duration::from_millis(50),
            self.pending_response_bodies.read(),
        )
        .await
        {
            Ok(pending) => {
                status.pending_responses = pending.len();
            }
            Err(_) => {
                status
                    .issues
                    .push("Response bodies lock timeout".to_string());
            }
        }

        status.healthy = status.engine_ok && status.issues.is_empty();
        status
    }

    /// Process detections and make a decision based on scoring
    fn make_decision(
        &self,
        engine: &WafEngine,
        detections: Vec<Detection>,
        location_type: &str,
    ) -> (WafDecision, Vec<Detection>) {
        // Track metrics - increment request counter
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        if detections.is_empty() {
            return (WafDecision::Allow, detections);
        }

        let decision = scoring::decide(
            &detections,
            engine.rules(),
            &engine.config.scoring,
            engine.config.block_mode,
        );

        // Track detection metrics by attack type
        for detection in &detections {
            self.metrics.increment_detection(&detection.attack_type);
        }

        // Track block metrics
        if decision.is_block() {
            self.metrics.blocks_total.fetch_add(1, Ordering::Relaxed);
        }

        // Log detections
        for detection in &detections {
            let level = if decision.is_block() {
                "BLOCK"
            } else {
                "DETECT"
            };
            warn!(
                rule_id = detection.rule_id,
                rule_name = %detection.rule_name,
                attack_type = %detection.attack_type,
                location = %detection.location,
                matched = %detection.matched_value,
                level = level,
                "WAF detection in {}", location_type
            );
        }

        (decision, detections)
    }

    /// Build response based on decision
    fn build_response(
        &self,
        decision: WafDecision,
        detections: &[Detection],
        tags: Vec<String>,
    ) -> AgentResponse {
        let rule_ids: Vec<String> = detections.iter().map(|d| d.rule_id.to_string()).collect();

        match decision {
            WafDecision::Allow => AgentResponse::default_allow(),

            WafDecision::AllowWithWarning { score } => {
                info!(
                    detections = detections.len(),
                    score = score.total,
                    "WAF detections (below block threshold)"
                );
                AgentResponse::default_allow()
                    .add_request_header(HeaderOp::Set {
                        name: "X-WAF-Detected".to_string(),
                        value: rule_ids.join(","),
                    })
                    .add_request_header(HeaderOp::Set {
                        name: "X-WAF-Score".to_string(),
                        value: score.total.to_string(),
                    })
                    .with_audit(AuditMetadata {
                        tags: [tags, vec!["detected".to_string()]].concat(),
                        rule_ids,
                        ..Default::default()
                    })
            }

            WafDecision::Block { score } => {
                info!(
                    detections = detections.len(),
                    score = score.total,
                    first_rule = detections.first().map(|d| d.rule_id).unwrap_or(0),
                    "Request blocked by WAF"
                );
                AgentResponse::block(403, Some("Forbidden".to_string()))
                    .add_response_header(HeaderOp::Set {
                        name: "X-WAF-Blocked".to_string(),
                        value: "true".to_string(),
                    })
                    .add_response_header(HeaderOp::Set {
                        name: "X-WAF-Rule".to_string(),
                        value: rule_ids.first().cloned().unwrap_or_default(),
                    })
                    .add_response_header(HeaderOp::Set {
                        name: "X-WAF-Score".to_string(),
                        value: score.total.to_string(),
                    })
                    .with_audit(AuditMetadata {
                        tags: [tags, vec!["blocked".to_string()]].concat(),
                        rule_ids,
                        ..Default::default()
                    })
            }
        }
    }
}

/// Version from Cargo.toml
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[async_trait::async_trait]
impl AgentHandlerV2 for WafAgent {
    /// Get agent capabilities for v2 protocol handshake
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("zentinel-waf-agent", "Zentinel WAF Agent", VERSION)
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
            .with_event(EventType::ResponseHeaders)
            .with_event(EventType::ResponseBodyChunk)
            .with_event(EventType::WebSocketFrame)
            .with_event(EventType::Configure)
            .with_features(AgentFeatures {
                streaming_body: true,
                websocket: true,
                config_push: true,
                metrics_export: true,
                health_reporting: true,
                cancellation: true,
                concurrent_requests: 100,
                flow_control: false,
                guardrails: false,
            })
    }

    /// Get current health status for v2 protocol
    fn health_status(&self) -> V2HealthStatus {
        V2HealthStatus::healthy("zentinel-waf-agent")
    }

    /// Get current metrics report for v2 protocol
    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("zentinel-waf-agent", 10_000);

        // Add counter metrics
        report.counters.push(CounterMetric::new(
            "waf_requests_total",
            self.metrics.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "waf_blocks_total",
            self.metrics.blocks_total.load(Ordering::Relaxed),
        ));

        // Add detection counters by attack type
        let mut sqli_counter = CounterMetric::new(
            "waf_detections_total",
            self.metrics.detections_sqli.load(Ordering::Relaxed),
        );
        sqli_counter
            .labels
            .insert("attack_type".to_string(), "sqli".to_string());
        report.counters.push(sqli_counter);

        let mut xss_counter = CounterMetric::new(
            "waf_detections_total",
            self.metrics.detections_xss.load(Ordering::Relaxed),
        );
        xss_counter
            .labels
            .insert("attack_type".to_string(), "xss".to_string());
        report.counters.push(xss_counter);

        let mut path_traversal_counter = CounterMetric::new(
            "waf_detections_total",
            self.metrics
                .detections_path_traversal
                .load(Ordering::Relaxed),
        );
        path_traversal_counter
            .labels
            .insert("attack_type".to_string(), "path_traversal".to_string());
        report.counters.push(path_traversal_counter);

        let mut cmd_injection_counter = CounterMetric::new(
            "waf_detections_total",
            self.metrics
                .detections_command_injection
                .load(Ordering::Relaxed),
        );
        cmd_injection_counter
            .labels
            .insert("attack_type".to_string(), "command_injection".to_string());
        report.counters.push(cmd_injection_counter);

        let mut other_counter = CounterMetric::new(
            "waf_detections_total",
            self.metrics.detections_other.load(Ordering::Relaxed),
        );
        other_counter
            .labels
            .insert("attack_type".to_string(), "other".to_string());
        report.counters.push(other_counter);

        // Add gauge for current score (placeholder - would need to track per-request)
        report
            .gauges
            .push(GaugeMetric::new("waf_current_score", 0.0));

        Some(report)
    }

    /// Handle a configuration update from the proxy
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        info!(config_version = ?version, "Received configuration update");
        debug!(config = ?config, "Configuration content");

        // Parse the JSON config
        let json_config: WafConfigJson =
            match serde_json::from_value::<WafConfigJson>(config.clone()) {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "Failed to parse WAF configuration");
                    return false;
                }
            };

        // Convert to WafConfig and reconfigure
        let new_config: WafConfig = json_config.into();
        info!(
            paranoia_level = new_config.paranoia_level,
            sqli = new_config.sqli_enabled,
            xss = new_config.xss_enabled,
            block_mode = new_config.block_mode,
            "Applying WAF configuration"
        );

        match self.reconfigure(new_config).await {
            Ok(()) => {
                info!("WAF agent reconfigured successfully");
                true
            }
            Err(e) => {
                warn!(error = %e, "Failed to reconfigure WAF engine");
                false
            }
        }
    }

    /// Handle a shutdown request from the proxy
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );
        // Clean up pending bodies
        self.pending_request_bodies.write().await.clear();
        self.pending_response_bodies.write().await.clear();
        self.pending_websocket_messages.write().await.clear();
    }

    /// Handle a drain request from the proxy
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            reason = ?reason,
            duration_ms = duration_ms,
            "Received drain request - stopping acceptance of new requests"
        );
        // In drain mode, we continue processing existing requests but don't accept new ones
        // The proxy handles this at the transport level
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let engine = self.engine.read().await;
        let path = &event.uri;

        // Check exclusions
        if engine.is_excluded(path) {
            debug!(path = path, "Path excluded from WAF");
            return AgentResponse::default_allow();
        }

        // Extract query string from path
        let (path_only, query) = path
            .split_once('?')
            .map(|(p, q)| (p, Some(q)))
            .unwrap_or((path, None));

        // Check request
        let detections = engine.check_request(path_only, query, &event.headers);

        let (decision, detections) = self.make_decision(&engine, detections, "headers");
        self.build_response(decision, &detections, vec!["waf".to_string()])
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let engine = self.engine.read().await;

        // Skip if body inspection is disabled
        if !engine.config.body_inspection_enabled {
            return AgentResponse::default_allow();
        }

        // Decode base64 chunk
        let chunk = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "Failed to decode body chunk");
                return AgentResponse::default_allow();
            }
        };

        let mut pending = self.pending_request_bodies.write().await;

        // Get or create inspection state
        // Use streaming mode if enabled and this is the first chunk
        let state = pending
            .entry(event.correlation_id.clone())
            .or_insert_with(|| {
                if engine.config.streaming.enabled {
                    BodyInspectionState::Streaming(streaming::StreamingInspector::new(
                        &engine.config.streaming,
                    ))
                } else {
                    BodyInspectionState::Buffered(BodyAccumulator::default())
                }
            });

        match state {
            BodyInspectionState::Buffered(accumulator) => {
                // Check size limit before accumulating
                if accumulator.data.len() + chunk.len() > engine.config.max_body_size {
                    debug!(
                        correlation_id = %event.correlation_id,
                        current_size = accumulator.data.len(),
                        chunk_size = chunk.len(),
                        max_size = engine.config.max_body_size,
                        "Body exceeds max size, skipping inspection"
                    );
                    pending.remove(&event.correlation_id);
                    return AgentResponse::default_allow();
                }

                accumulator.data.extend(chunk);

                // If this is the last chunk, inspect the full body
                if event.is_last {
                    if let Some(BodyInspectionState::Buffered(body_data)) =
                        pending.remove(&event.correlation_id)
                    {
                        let body_str = String::from_utf8_lossy(&body_data.data);

                        debug!(
                            correlation_id = %event.correlation_id,
                            body_size = body_data.data.len(),
                            "Inspecting request body (buffered mode)"
                        );

                        let detections = engine.check(&body_str, "body");
                        let (decision, detections) =
                            self.make_decision(&engine, detections, "body");
                        return self.build_response(
                            decision,
                            &detections,
                            vec!["waf".to_string(), "body".to_string()],
                        );
                    }
                }

                AgentResponse::default_allow()
            }

            BodyInspectionState::Streaming(inspector) => {
                // Check if already terminated early
                if inspector.is_terminated() {
                    // Already decided to block - maintain decision
                    if event.is_last {
                        let result = pending.remove(&event.correlation_id);
                        if let Some(BodyInspectionState::Streaming(inspector)) = result {
                            let streaming_result = inspector.finalize();
                            info!(
                                correlation_id = %event.correlation_id,
                                bytes_processed = streaming_result.bytes_processed,
                                detections = streaming_result.detections.len(),
                                score = streaming_result.score.total,
                                "Early termination - body inspection complete"
                            );
                            let (decision, detections) =
                                self.make_decision(&engine, streaming_result.detections, "body");
                            return self.build_response(
                                decision,
                                &detections,
                                vec![
                                    "waf".to_string(),
                                    "body".to_string(),
                                    "streaming".to_string(),
                                ],
                            );
                        }
                    }
                    return AgentResponse::default_allow();
                }

                // Prepare chunk for inspection (includes overlap from previous chunk)
                if let Some(inspection_text) = inspector.prepare_chunk(&chunk) {
                    // Inspect the chunk
                    let detections = engine.check(&inspection_text, "body");

                    // Add detections and check for early termination
                    let location_weight = engine.config.scoring.location_weights.body;
                    if !inspector.add_detections_with_weights(detections, location_weight, 1.0) {
                        // Early termination triggered
                        info!(
                            correlation_id = %event.correlation_id,
                            bytes_processed = inspector.bytes_processed(),
                            score = inspector.score().total,
                            "Early termination triggered - score threshold exceeded"
                        );

                        // If not last chunk, just return allow and wait for final chunk
                        if !event.is_last {
                            return AgentResponse::default_allow();
                        }
                    }
                }

                // If this is the last chunk, finalize and make decision
                if event.is_last {
                    if let Some(BodyInspectionState::Streaming(inspector)) =
                        pending.remove(&event.correlation_id)
                    {
                        let streaming_result = inspector.finalize();

                        debug!(
                            correlation_id = %event.correlation_id,
                            bytes_processed = streaming_result.bytes_processed,
                            detections = streaming_result.detections.len(),
                            score = streaming_result.score.total,
                            duration_ms = streaming_result.duration.as_millis(),
                            "Streaming body inspection complete"
                        );

                        let (decision, detections) =
                            self.make_decision(&engine, streaming_result.detections, "body");
                        return self.build_response(
                            decision,
                            &detections,
                            vec![
                                "waf".to_string(),
                                "body".to_string(),
                                "streaming".to_string(),
                            ],
                        );
                    }
                }

                AgentResponse::default_allow()
            }
        }
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        let engine = self.engine.read().await;

        // Skip if response inspection is disabled
        if !engine.config.response_inspection_enabled {
            return AgentResponse::default_allow();
        }

        // Decode base64 chunk
        let chunk = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "Failed to decode response body chunk");
                return AgentResponse::default_allow();
            }
        };

        // Accumulate chunk
        let mut pending = self.pending_response_bodies.write().await;
        let accumulator = pending
            .entry(event.correlation_id.clone())
            .or_insert_with(BodyAccumulator::default);

        // Check size limit before accumulating
        if accumulator.data.len() + chunk.len() > engine.config.max_body_size {
            debug!(
                correlation_id = %event.correlation_id,
                current_size = accumulator.data.len(),
                chunk_size = chunk.len(),
                max_size = engine.config.max_body_size,
                "Response body exceeds max size, skipping inspection"
            );
            pending.remove(&event.correlation_id);
            return AgentResponse::default_allow();
        }

        accumulator.data.extend(chunk);

        // If this is the last chunk, inspect the full body
        if event.is_last {
            let body_data = match pending.remove(&event.correlation_id) {
                Some(data) => data,
                None => {
                    warn!(
                        correlation_id = %event.correlation_id,
                        "Response body correlation ID not found, skipping inspection"
                    );
                    return AgentResponse::default_allow();
                }
            };
            let body_str = String::from_utf8_lossy(&body_data.data);

            debug!(
                correlation_id = %event.correlation_id,
                body_size = body_data.data.len(),
                "Inspecting response body"
            );

            let detections = engine.check(&body_str, "response_body");

            if !detections.is_empty() {
                // Log detections for response bodies (cannot block)
                for detection in &detections {
                    warn!(
                        rule_id = detection.rule_id,
                        rule_name = %detection.rule_name,
                        attack_type = %detection.attack_type,
                        location = %detection.location,
                        matched = %detection.matched_value,
                        "WAF detection in response body"
                    );
                }

                let rule_ids: Vec<String> =
                    detections.iter().map(|d| d.rule_id.to_string()).collect();

                info!(
                    detections = detections.len(),
                    first_rule = detections.first().map(|d| d.rule_id).unwrap_or(0),
                    "WAF detection in response (logged)"
                );

                return AgentResponse::default_allow()
                    .add_response_header(HeaderOp::Set {
                        name: "X-WAF-Response-Detected".to_string(),
                        value: rule_ids.join(","),
                    })
                    .with_audit(AuditMetadata {
                        tags: vec![
                            "waf".to_string(),
                            "detected".to_string(),
                            "response_body".to_string(),
                        ],
                        rule_ids,
                        ..Default::default()
                    });
            }
        }

        AgentResponse::default_allow()
    }

    /// Handle WebSocket frame inspection
    ///
    /// Inspects WebSocket frames for attacks. Supports both single frames
    /// and fragmented messages (accumulated until FIN bit is set).
    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        let engine = self.engine.read().await;

        // Skip if WebSocket inspection is disabled
        if !engine.config.websocket.enabled {
            return AgentResponse::websocket_allow();
        }

        // Skip control frames (ping, pong, close) - they don't carry attack payloads
        let opcode = event.opcode.to_lowercase();
        if opcode == "ping" || opcode == "pong" || opcode == "close" {
            debug!(
                correlation_id = %event.correlation_id,
                opcode = %event.opcode,
                "Skipping control frame"
            );
            return AgentResponse::websocket_allow();
        }

        // Check frame type inspection settings
        let is_text = opcode == "text" || opcode == "continuation";
        let is_binary = opcode == "binary";

        if is_text && !engine.config.websocket.inspect_text_frames {
            return AgentResponse::websocket_allow();
        }
        if is_binary && !engine.config.websocket.inspect_binary_frames {
            return AgentResponse::websocket_allow();
        }

        // Decode base64 frame data
        let frame_data = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(
                    correlation_id = %event.correlation_id,
                    error = %e,
                    "Failed to decode WebSocket frame data"
                );
                return AgentResponse::websocket_allow();
            }
        };

        // Check frame size limit
        if frame_data.len() > engine.config.websocket.max_frame_size {
            debug!(
                correlation_id = %event.correlation_id,
                frame_size = frame_data.len(),
                max_size = engine.config.websocket.max_frame_size,
                "WebSocket frame exceeds max size, skipping inspection"
            );
            return AgentResponse::websocket_allow();
        }

        // Handle fragmented messages
        let data_to_inspect = if engine.config.websocket.accumulate_fragments && !event.fin {
            // This is a fragment, accumulate it
            let key = WebSocketKey {
                correlation_id: event.correlation_id.clone(),
                client_to_server: event.client_to_server,
            };

            let mut pending = self.pending_websocket_messages.write().await;
            let accumulator = pending.entry(key).or_insert_with(|| {
                WebSocketMessageAccumulator::new(event.opcode.clone(), event.client_to_server)
            });

            // Check accumulated size
            if accumulator.data.len() + frame_data.len() > engine.config.websocket.max_message_size
            {
                warn!(
                    correlation_id = %event.correlation_id,
                    accumulated_size = accumulator.data.len(),
                    frame_size = frame_data.len(),
                    max_size = engine.config.websocket.max_message_size,
                    "WebSocket message exceeds max size, dropping"
                );
                pending.remove(&WebSocketKey {
                    correlation_id: event.correlation_id.clone(),
                    client_to_server: event.client_to_server,
                });

                if engine.config.websocket.block_mode {
                    return AgentResponse::websocket_close(
                        engine.config.websocket.block_close_code,
                        engine.config.websocket.block_close_reason.clone(),
                    );
                } else {
                    return AgentResponse::websocket_drop();
                }
            }

            accumulator.data.extend(&frame_data);
            accumulator.frame_count += 1;

            debug!(
                correlation_id = %event.correlation_id,
                frame_index = event.frame_index,
                accumulated_frames = accumulator.frame_count,
                accumulated_size = accumulator.data.len(),
                "Accumulated WebSocket fragment"
            );

            // Not the final frame, don't inspect yet
            return AgentResponse::websocket_allow();
        } else if engine.config.websocket.accumulate_fragments && event.fin {
            // Final frame, get accumulated data if any
            let key = WebSocketKey {
                correlation_id: event.correlation_id.clone(),
                client_to_server: event.client_to_server,
            };

            let mut pending = self.pending_websocket_messages.write().await;
            if let Some(mut accumulator) = pending.remove(&key) {
                // Add final frame data
                accumulator.data.extend(&frame_data);
                accumulator.data
            } else {
                // Single frame message (no prior fragments)
                frame_data
            }
        } else {
            // Not accumulating, inspect each frame individually
            frame_data
        };

        // Convert to string for inspection (lossy for binary)
        let payload_str = String::from_utf8_lossy(&data_to_inspect);

        // Determine location for scoring
        let direction = if event.client_to_server { "c2s" } else { "s2c" };
        let location = format!("websocket:{}:{}", direction, event.opcode);

        debug!(
            correlation_id = %event.correlation_id,
            frame_index = event.frame_index,
            direction = direction,
            opcode = %event.opcode,
            payload_size = data_to_inspect.len(),
            "Inspecting WebSocket frame"
        );

        // Run detection
        let detections = engine.check(&payload_str, &location);

        if detections.is_empty() {
            return AgentResponse::websocket_allow();
        }

        // Calculate decision using scoring
        let decision = scoring::decide(
            &detections,
            engine.rules(),
            &engine.config.scoring,
            engine.config.websocket.block_mode,
        );

        // Log detections
        for detection in &detections {
            let level = if decision.is_block() {
                "BLOCK"
            } else {
                "DETECT"
            };
            warn!(
                correlation_id = %event.correlation_id,
                rule_id = detection.rule_id,
                rule_name = %detection.rule_name,
                attack_type = %detection.attack_type,
                location = %detection.location,
                matched = %detection.matched_value,
                level = level,
                direction = direction,
                "WAF detection in WebSocket frame"
            );
        }

        if decision.is_block() {
            let rule_ids: Vec<String> = detections.iter().map(|d| d.rule_id.to_string()).collect();
            let first_rule = detections.first().map(|d| d.rule_id).unwrap_or(0);
            let attack_type = detections
                .first()
                .map(|d| d.attack_type.to_string())
                .unwrap_or_default();

            info!(
                correlation_id = %event.correlation_id,
                detections = detections.len(),
                first_rule = first_rule,
                attack_type = %attack_type,
                "WebSocket frame blocked"
            );

            // Close connection for blocked attacks
            AgentResponse::websocket_close(
                engine.config.websocket.block_close_code,
                format!(
                    "{}: rule {} ({})",
                    engine.config.websocket.block_close_reason, first_rule, attack_type
                ),
            )
            .with_audit(AuditMetadata {
                tags: vec![
                    "waf".to_string(),
                    "blocked".to_string(),
                    "websocket".to_string(),
                    direction.to_string(),
                ],
                rule_ids,
                ..Default::default()
            })
        } else {
            // Detection below threshold, allow but log
            let rule_ids: Vec<String> = detections.iter().map(|d| d.rule_id.to_string()).collect();

            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags: vec![
                    "waf".to_string(),
                    "detected".to_string(),
                    "websocket".to_string(),
                    direction.to_string(),
                ],
                rule_ids,
                ..Default::default()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> WafEngine {
        let config = WafConfig {
            paranoia_level: 2,
            ..Default::default()
        };
        WafEngine::new(config).unwrap()
    }

    #[test]
    fn test_sqli_detection() {
        let engine = test_engine();

        // Should detect
        let detections = engine.check("' OR '1'='1", "query");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::SqlInjection);
    }

    #[test]
    fn test_xss_detection() {
        let engine = test_engine();

        let detections = engine.check("<script>alert('xss')</script>", "body");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::Xss);
    }

    #[test]
    fn test_default_config() {
        let config = WafConfig::default();
        assert_eq!(config.paranoia_level, 1);
        assert!(config.sqli_enabled);
        assert!(config.block_mode);
        assert!(config.scoring.enabled);
        assert_eq!(config.scoring.block_threshold, 25);
    }

    #[test]
    fn test_scoring_decision() {
        let config = WafConfig {
            paranoia_level: 2,
            scoring: ScoringConfig {
                enabled: true,
                block_threshold: 25,
                log_threshold: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        let engine = WafEngine::new(config).unwrap();

        // Single low-score detection should not block
        let detections = engine.check("SELECT", "query"); // Might match some rules
        if !detections.is_empty() {
            let decision = scoring::decide(
                &detections,
                engine.rules(),
                &engine.config.scoring,
                engine.config.block_mode,
            );
            // The actual decision depends on rule scores
            println!("Decision: {:?}", decision.is_block());
        }
    }
}
