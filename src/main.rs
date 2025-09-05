use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

mod protocol;
mod websocket_server;

use websocket_server::WebSocketServer;

#[derive(Parser, Debug)]
#[command(author, version, about = "Mercury - Hecate storage server (WebSocket)", long_about = None)]
struct Args {
    #[arg(
        short,
        long,
        default_value = "./storage",
        help = "Directory to store received files"
    )]
    store: PathBuf,

    #[arg(short, long, default_value = "10112", help = "Port to listen on")]
    port: u16,

    #[arg(short, long, help = "Verbose logging")]
    verbose: bool,

    #[arg(short('k'), long, help = "Authentication key required for access")]
    auth_key: Option<String>,

    #[arg(long, help = "Enable TLS with certificate file")]
    tls_cert: Option<PathBuf>,

    #[arg(long, help = "TLS private key file")]
    tls_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();

    // Check environment variable for auth key if not provided via CLI
    if args.auth_key.is_none() {
        if let Ok(env_key) = std::env::var("MERCURY_AUTH_KEY") {
            args.auth_key = Some(env_key);
        }
    }

    // Set up logging
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt().with_max_level(log_level).init();

    info!("Mercury WebSocket server starting");
    info!("Storage directory: {:?}", args.store);
    info!("Port: {}", args.port);

    if args.auth_key.is_some() {
        info!("Authentication enabled");
    } else {
        warn!("Running without authentication - anyone can access this server");
    }

    // TLS is mandatory
    if args.tls_cert.is_none() || args.tls_key.is_none() {
        error!("TLS is required for security. Please provide --tls-cert and --tls-key");
        anyhow::bail!(
            "TLS certificates are required. Use --tls-cert and --tls-key to specify certificate paths"
        );
    }

    info!("TLS enabled with certificate: {:?}", args.tls_cert);

    // Create the WebSocket server with mandatory TLS
    let server = WebSocketServer::new(args.store.clone(), args.auth_key.clone())
        .await?
        .with_tls(&args.tls_cert.unwrap(), &args.tls_key.unwrap())
        .await?;

    let server = Arc::new(server);

    // Bind address
    let addr = format!("0.0.0.0:{}", args.port);

    // Run the server
    server.run(&addr).await?;

    Ok(())
}
