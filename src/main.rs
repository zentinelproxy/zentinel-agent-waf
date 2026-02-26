//! Zentinel WAF Agent CLI
//!
//! Command-line interface for the Web Application Firewall agent.
//! Supports both Unix Domain Socket and gRPC transports using the v2 protocol.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info};

use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};
use zentinel_agent_waf::{WafAgent, WafConfig, WebSocketConfig};

/// Version information
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Global shutdown flag for graceful termination
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Transport mode for the agent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportMode {
    /// Unix Domain Socket (v2 protocol)
    Uds,
    /// gRPC over TCP (v2 protocol)
    Grpc,
}

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "zentinel-waf-agent")]
#[command(about = "Web Application Firewall agent for Zentinel reverse proxy")]
#[command(version = VERSION)]
struct Args {
    /// Path to Unix socket (UDS transport)
    #[arg(long, default_value = "/tmp/zentinel-waf.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// gRPC server address (e.g., "0.0.0.0:50051")
    /// When specified, the agent uses gRPC transport with v2 protocol
    #[arg(long, env = "AGENT_GRPC_ADDRESS")]
    grpc_address: Option<String>,

    /// Paranoia level (1-4, higher = more strict)
    #[arg(long, default_value = "1", env = "WAF_PARANOIA_LEVEL")]
    paranoia_level: u8,

    /// Enable SQL injection detection
    #[arg(long, default_value = "true", env = "WAF_SQLI")]
    sqli: bool,

    /// Enable XSS detection
    #[arg(long, default_value = "true", env = "WAF_XSS")]
    xss: bool,

    /// Enable path traversal detection
    #[arg(long, default_value = "true", env = "WAF_PATH_TRAVERSAL")]
    path_traversal: bool,

    /// Enable command injection detection
    #[arg(long, default_value = "true", env = "WAF_COMMAND_INJECTION")]
    command_injection: bool,

    /// Enable protocol attacks detection
    #[arg(long, default_value = "true", env = "WAF_PROTOCOL")]
    protocol: bool,

    /// Block mode (true) or detect-only mode (false)
    #[arg(long, default_value = "true", env = "WAF_BLOCK_MODE")]
    block_mode: bool,

    /// Paths to exclude from WAF (comma-separated)
    #[arg(long, env = "WAF_EXCLUDE_PATHS")]
    exclude_paths: Option<String>,

    /// Enable request body inspection
    #[arg(long, default_value = "true", env = "WAF_BODY_INSPECTION")]
    body_inspection: bool,

    /// Maximum body size to inspect in bytes (default 1MB)
    #[arg(long, default_value = "1048576", env = "WAF_MAX_BODY_SIZE")]
    max_body_size: usize,

    /// Enable response body inspection (detect attacks in server responses)
    #[arg(long, default_value = "false", env = "WAF_RESPONSE_INSPECTION")]
    response_inspection: bool,

    /// Enable WebSocket frame inspection
    #[arg(long, default_value = "false", env = "WAF_WEBSOCKET_INSPECTION")]
    websocket_inspection: bool,

    /// Inspect WebSocket text frames
    #[arg(long, default_value = "true", env = "WAF_WEBSOCKET_TEXT_FRAMES")]
    websocket_text_frames: bool,

    /// Inspect WebSocket binary frames
    #[arg(long, default_value = "false", env = "WAF_WEBSOCKET_BINARY_FRAMES")]
    websocket_binary_frames: bool,

    /// Maximum WebSocket frame size to inspect (default 64KB)
    #[arg(long, default_value = "65536", env = "WAF_WEBSOCKET_MAX_FRAME_SIZE")]
    websocket_max_frame_size: usize,

    /// Enable verbose logging
    #[arg(short, long, env = "WAF_VERBOSE")]
    verbose: bool,
}

impl Args {
    fn to_config(&self) -> WafConfig {
        let exclude_paths = self
            .exclude_paths
            .as_ref()
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let websocket = WebSocketConfig {
            enabled: self.websocket_inspection,
            inspect_text_frames: self.websocket_text_frames,
            inspect_binary_frames: self.websocket_binary_frames,
            max_frame_size: self.websocket_max_frame_size,
            ..Default::default()
        };

        WafConfig {
            paranoia_level: self.paranoia_level.clamp(1, 4),
            sqli_enabled: self.sqli,
            xss_enabled: self.xss,
            path_traversal_enabled: self.path_traversal,
            command_injection_enabled: self.command_injection,
            protocol_enabled: self.protocol,
            block_mode: self.block_mode,
            exclude_paths,
            body_inspection_enabled: self.body_inspection,
            max_body_size: self.max_body_size,
            response_inspection_enabled: self.response_inspection,
            websocket,
            ..Default::default()
        }
    }

    fn transport_mode(&self) -> TransportMode {
        if self.grpc_address.is_some() {
            TransportMode::Grpc
        } else {
            TransportMode::Uds
        }
    }
}

/// Install panic hook for production diagnostics
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Log panic with structured fields for observability
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic_info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("Unknown panic payload");

        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        // Use eprintln for panic logging as tracing may not work during panic
        eprintln!(
            "PANIC: WAF agent panicked at {}: {}",
            location, payload
        );

        // Also try to log via tracing if available
        error!(
            panic_payload = %payload,
            panic_location = %location,
            "WAF agent panicked - this should not happen in production"
        );

        // Call default hook for stack traces in debug builds
        default_hook(panic_info);
    }));
}

/// Setup signal handlers for graceful shutdown
fn setup_signal_handlers() {
    // Handle SIGINT (Ctrl+C) and SIGTERM
    tokio::spawn(async {
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
            }
        }

        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    });
}

/// Run the agent with UDS transport (v2 protocol)
async fn run_uds_server(agent: WafAgent, socket_path: PathBuf) -> Result<()> {
    info!(
        socket = ?socket_path,
        transport = "uds",
        protocol = "v2",
        "Starting WAF agent with UDS v2 transport"
    );

    let server = UdsAgentServerV2::new("zentinel-waf-agent", socket_path, Box::new(agent));

    match server.run().await {
        Ok(()) => {
            info!("WAF agent shutdown complete (UDS)");
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "WAF agent server error (UDS)");
            Err(anyhow::anyhow!("UDS server error: {}", e))
        }
    }
}

/// Run the agent with gRPC transport (v2 protocol)
async fn run_grpc_server(agent: WafAgent, address: String) -> Result<()> {
    let addr: std::net::SocketAddr = address.parse().map_err(|e| {
        error!(address = %address, error = %e, "Invalid gRPC address");
        anyhow::anyhow!("Invalid gRPC address '{}': {}", address, e)
    })?;

    info!(
        address = %addr,
        transport = "grpc",
        protocol = "v2",
        "Starting WAF agent with gRPC transport"
    );

    // Wrap agent in Arc for the gRPC server (it takes Box<dyn AgentHandlerV2>)
    let server = GrpcAgentServerV2::new("zentinel-waf-agent", Box::new(agent));

    match server.run(addr).await {
        Ok(()) => {
            info!("WAF agent shutdown complete (gRPC)");
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "WAF agent server error (gRPC)");
            Err(anyhow::anyhow!("gRPC server error: {}", e))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install panic hook first for early crash diagnostics
    install_panic_hook();

    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},zentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!(
        version = VERSION,
        "Starting Zentinel WAF Agent"
    );

    // Setup signal handlers for graceful shutdown
    setup_signal_handlers();

    // Build configuration
    let config = args.to_config();
    let transport = args.transport_mode();

    info!(
        paranoia_level = config.paranoia_level,
        sqli = config.sqli_enabled,
        xss = config.xss_enabled,
        path_traversal = config.path_traversal_enabled,
        command_injection = config.command_injection_enabled,
        block_mode = config.block_mode,
        body_inspection = config.body_inspection_enabled,
        response_inspection = config.response_inspection_enabled,
        websocket_inspection = config.websocket.enabled,
        max_body_size = config.max_body_size,
        transport = ?transport,
        "Configuration loaded"
    );

    // Create agent with error context
    let agent = WafAgent::new(config).map_err(|e| {
        error!(error = %e, "Failed to initialize WAF agent");
        e
    })?;

    info!("WAF agent initialized successfully");

    // Start the appropriate server based on transport mode
    match transport {
        TransportMode::Uds => run_uds_server(agent, args.socket).await,
        TransportMode::Grpc => {
            let address = args.grpc_address.expect("gRPC address should be set");
            run_grpc_server(agent, address).await
        }
    }
}
