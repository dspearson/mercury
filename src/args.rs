use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Mercury - Hecate storage server (WebSocket)", long_about = None)]
pub struct Args {
    #[arg(short, long, help = "Path to TOML configuration file")]
    pub config: Option<PathBuf>,

    #[arg(long, help = "Generate example config file and exit")]
    pub generate_config: bool,

    #[arg(long, help = "Validate configuration and exit")]
    pub validate: bool,

    #[arg(
        short,
        long,
        default_value = "./storage",
        help = "Directory to store received files"
    )]
    pub store: PathBuf,

    #[arg(short, long, default_value = "10112", help = "Port to listen on")]
    pub port: u16,

    #[arg(short, long, help = "Verbose logging")]
    pub verbose: bool,

    #[arg(short('k'), long, help = "Authentication key required for access")]
    pub auth_key: Option<String>,

    #[arg(long, help = "Path to JSON file containing client credentials")]
    pub auth_config: Option<PathBuf>,

    #[arg(long, help = "Enable TLS with certificate file")]
    pub tls_cert: Option<PathBuf>,

    #[arg(long, help = "TLS private key file")]
    pub tls_key: Option<PathBuf>,
}
