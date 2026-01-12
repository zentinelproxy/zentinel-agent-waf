//! Sentinel WAF Agent CLI
//!
//! Command-line interface for the Web Application Firewall agent.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info};

use sentinel_agent_protocol::AgentServer;
use sentinel_agent_waf::{WafAgent, WafConfig};

/// Version information
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Global shutdown flag for graceful termination
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-waf-agent")]
#[command(about = "Web Application Firewall agent for Sentinel reverse proxy")]
struct Args {
    /// Path to Unix socket
    #[arg(long, default_value = "/tmp/sentinel-waf.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

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
            ..Default::default()
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
            .map(|s| *s)
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
            "{}={},sentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!(
        version = VERSION,
        "Starting Sentinel WAF Agent"
    );

    // Setup signal handlers for graceful shutdown
    setup_signal_handlers();

    // Build configuration
    let config = args.to_config();

    info!(
        paranoia_level = config.paranoia_level,
        sqli = config.sqli_enabled,
        xss = config.xss_enabled,
        path_traversal = config.path_traversal_enabled,
        command_injection = config.command_injection_enabled,
        block_mode = config.block_mode,
        body_inspection = config.body_inspection_enabled,
        response_inspection = config.response_inspection_enabled,
        max_body_size = config.max_body_size,
        "Configuration loaded"
    );

    // Create agent with error context
    let agent = WafAgent::new(config).map_err(|e| {
        error!(error = %e, "Failed to initialize WAF agent");
        e
    })?;

    info!(
        socket = ?args.socket,
        "WAF agent initialized successfully, starting server"
    );

    // Start agent server
    let server = AgentServer::new("sentinel-waf-agent", args.socket, Box::new(agent));

    match server.run().await {
        Ok(()) => {
            info!("WAF agent shutdown complete");
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "WAF agent server error");
            Err(anyhow::anyhow!("Server error: {}", e))
        }
    }
}
