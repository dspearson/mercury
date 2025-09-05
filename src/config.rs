use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(default)]
    pub health: HealthConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_bind")]
    pub bind: String,

    #[serde(default = "default_storage")]
    pub storage_path: PathBuf,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub auth_key: Option<String>,
    pub auth_config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    #[serde(default = "default_health_enabled")]
    pub enabled: bool,

    #[serde(default = "default_health_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default = "default_log_format")]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

// Default values
fn default_port() -> u16 {
    10112
}
fn default_bind() -> String {
    "0.0.0.0".to_string()
}
fn default_storage() -> PathBuf {
    PathBuf::from("/var/lib/mercury/storage")
}
fn default_max_connections() -> usize {
    50
}
fn default_connection_timeout() -> u64 {
    300
}
fn default_health_enabled() -> bool {
    true
}
fn default_health_port() -> u16 {
    9090
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> LogFormat {
    LogFormat::Text
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            tls: TlsConfig::default(),
            auth: AuthConfig::default(),
            health: HealthConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            bind: default_bind(),
            storage_path: default_storage(),
            max_connections: default_max_connections(),
            connection_timeout_secs: default_connection_timeout(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            auth_key: None,
            auth_config_path: None,
        }
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: default_health_enabled(),
            port: default_health_port(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

impl Config {
    /// Load config from TOML file
    pub async fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        toml::from_str(&content).with_context(|| format!("Failed to parse config file: {:?}", path))
    }

    /// Merge with command-line arguments (CLI takes precedence)
    pub fn merge_with_args(&mut self, args: &crate::args::Args) {
        // Server settings
        if args.port != default_port() {
            self.server.port = args.port;
        }

        if args.store != PathBuf::from("./storage") {
            self.server.storage_path = args.store.clone();
        }

        // TLS settings
        if args.tls_cert.is_some() {
            self.tls.cert_path = args.tls_cert.clone();
        }

        if args.tls_key.is_some() {
            self.tls.key_path = args.tls_key.clone();
        }

        // Auth settings
        if args.auth_key.is_some() {
            self.auth.auth_key = args.auth_key.clone();
        }

        if args.auth_config.is_some() {
            self.auth.auth_config_path = args.auth_config.clone();
        }

        // Logging
        if args.verbose {
            self.logging.level = "debug".to_string();
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // TLS is mandatory - no exceptions
        if self.tls.cert_path.is_none() || self.tls.key_path.is_none() {
            anyhow::bail!(
                "TLS certificates are required. Configure tls.cert_path and tls.key_path"
            );
        }

        // Authentication is mandatory - no exceptions
        if self.auth.auth_key.is_none() && self.auth.auth_config_path.is_none() {
            anyhow::bail!(
                "Authentication is required. Configure auth.auth_key or auth.auth_config_path"
            );
        }

        // Verify cert files exist
        if let Some(ref cert) = self.tls.cert_path {
            if !cert.exists() {
                anyhow::bail!("Certificate file not found: {:?}", cert);
            }
        }

        if let Some(ref key) = self.tls.key_path {
            if !key.exists() {
                anyhow::bail!("Key file not found: {:?}", key);
            }
        }

        // Verify auth config exists if specified
        if let Some(ref auth_config) = self.auth.auth_config_path {
            if !auth_config.exists() {
                anyhow::bail!("Auth config file not found: {:?}", auth_config);
            }
        }

        Ok(())
    }

    /// Create an example config file
    pub fn example() -> String {
        toml::to_string_pretty(&Config {
            server: ServerConfig {
                port: 10112,
                bind: "0.0.0.0".to_string(),
                storage_path: PathBuf::from("/var/lib/mercury/storage"),
                max_connections: 50,
                connection_timeout_secs: 300,
            },
            tls: TlsConfig {
                cert_path: Some(PathBuf::from("/etc/mercury/cert.pem")),
                key_path: Some(PathBuf::from("/etc/mercury/key.pem")),
            },
            auth: AuthConfig {
                auth_key: None,
                auth_config_path: Some(PathBuf::from("/etc/mercury/auth.json")),
            },
            health: HealthConfig {
                enabled: true,
                port: 9090,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: LogFormat::Json,
            },
        })
        .unwrap()
    }
}
