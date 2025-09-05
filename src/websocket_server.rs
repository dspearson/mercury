use anyhow::{Context, Result};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys};
use std::collections::HashMap;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Arc as StdArc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::protocol::{
    ClientMessage, ErrorCode, FileInfo, ServerMessage, validate_chunk_size, validate_file_size,
    validate_filename,
};

// Rate limiting configuration
const MAX_REQUESTS_PER_MINUTE: u32 = 100;
const MAX_UPLOADS_PER_HOUR: u32 = 10;
const MAX_CONCURRENT_CONNECTIONS: usize = 50;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Clone)]
struct RateLimiter {
    requests: Arc<RwLock<HashMap<SocketAddr, Vec<Instant>>>>,
    uploads: Arc<RwLock<HashMap<SocketAddr, Vec<Instant>>>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            uploads: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn check_request_rate(&self, addr: SocketAddr) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        let entry = requests.entry(addr).or_insert_with(Vec::new);
        entry.retain(|&t| t > one_minute_ago);

        if entry.len() >= MAX_REQUESTS_PER_MINUTE as usize {
            false
        } else {
            entry.push(now);
            true
        }
    }

    async fn check_upload_rate(&self, addr: SocketAddr) -> bool {
        let mut uploads = self.uploads.write().await;
        let now = Instant::now();
        let one_hour_ago = now - Duration::from_secs(3600);

        let entry = uploads.entry(addr).or_insert_with(Vec::new);
        entry.retain(|&t| t > one_hour_ago);

        if entry.len() >= MAX_UPLOADS_PER_HOUR as usize {
            false
        } else {
            entry.push(now);
            true
        }
    }
}

pub struct WebSocketServer {
    store_path: PathBuf,
    auth_key: Option<String>,
    rate_limiter: RateLimiter,
    active_connections: Arc<Mutex<usize>>,
    tls_acceptor: Option<TlsAcceptor>,
}

impl WebSocketServer {
    pub async fn new(store_path: PathBuf, auth_key: Option<String>) -> Result<Self> {
        fs::create_dir_all(&store_path)
            .await
            .with_context(|| format!("Failed to create storage directory {:?}", store_path))?;

        Ok(Self {
            store_path,
            auth_key,
            rate_limiter: RateLimiter::new(),
            active_connections: Arc::new(Mutex::new(0)),
            tls_acceptor: None,
        })
    }

    pub fn set_auth_key(&mut self, key: String) {
        self.auth_key = Some(key);
    }

    pub async fn reload_auth_config(&mut self, _config_path: &str) -> Result<()> {
        info!("Auth config reload not implemented for simple key auth");
        Ok(())
    }

    pub async fn with_tls(mut self, cert_path: &PathBuf, key_path: &PathBuf) -> Result<Self> {
        // Read cert and key files
        let cert_pem = fs::read_to_string(cert_path)
            .await
            .with_context(|| format!("Failed to read certificate from {:?}", cert_path))?;
        let key_pem = fs::read_to_string(key_path)
            .await
            .with_context(|| format!("Failed to read key from {:?}", key_path))?;

        // Parse certificates
        let cert_reader = &mut BufReader::new(cert_pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = certs(cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificate")?;

        if certs.is_empty() {
            anyhow::bail!("No certificates found in certificate file");
        }

        // Parse private key - try EC key first, then PKCS8
        let key_reader = &mut BufReader::new(key_pem.as_bytes());
        let ec_keys = ec_private_keys(key_reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|_| Vec::new());

        let key: PrivateKeyDer<'static> = if !ec_keys.is_empty() {
            PrivateKeyDer::Sec1(ec_keys.into_iter().next().unwrap())
        } else {
            // Try PKCS8 format
            let key_reader = &mut BufReader::new(key_pem.as_bytes());
            let pkcs8_keys = pkcs8_private_keys(key_reader)
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse private key")?;

            if pkcs8_keys.is_empty() {
                anyhow::bail!("No private keys found in key file");
            }

            PrivateKeyDer::Pkcs8(pkcs8_keys.into_iter().next().unwrap())
        };

        // Create TLS config with P-521 support using aws-lc-rs
        let config = ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create TLS configuration")?;

        self.tls_acceptor = Some(TlsAcceptor::from(StdArc::new(config)));
        Ok(self)
    }

    pub async fn run(self: Arc<Self>, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind to {}", addr))?;

        info!("WebSocket server listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;

            // Check connection limit
            {
                let mut connections = self.active_connections.lock().await;
                if *connections >= MAX_CONCURRENT_CONNECTIONS {
                    warn!("Connection limit reached, rejecting {}", peer_addr);
                    continue;
                }
                *connections += 1;
            }

            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream, peer_addr).await {
                    error!("Error handling connection from {}: {}", peer_addr, e);
                }

                // Decrement connection count
                let mut connections = server.active_connections.lock().await;
                *connections = connections.saturating_sub(1);
            });
        }
    }

    async fn handle_connection(&self, stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        let mut handler = ConnectionHandler::new(
            self.store_path.clone(),
            self.auth_key.clone(),
            peer_addr,
            &self.rate_limiter,
        );

        // Apply TLS if configured
        if let Some(acceptor) = &self.tls_acceptor {
            info!("New secure WebSocket connection from {}", peer_addr);
            let tls_stream = acceptor.accept(stream).await.map_err(|e| {
                error!("TLS handshake failed: {:?}", e);
                anyhow::anyhow!("Failed to accept TLS connection: {}", e)
            })?;
            let ws_stream = accept_async(tls_stream)
                .await
                .context("Failed to accept WebSocket connection")?;
            handler.handle(ws_stream).await
        } else {
            info!("New WebSocket connection from {}", peer_addr);
            let ws_stream = accept_async(stream)
                .await
                .context("Failed to accept WebSocket connection")?;
            handler.handle(ws_stream).await
        }
    }
}

struct ConnectionHandler {
    store_path: PathBuf,
    auth_key: Option<String>,
    peer_addr: SocketAddr,
    authenticated: bool,
    rate_limiter: RateLimiter,
    current_upload: Option<UploadState>,
    last_activity: Instant,
}

struct UploadState {
    filename: String,
    temp_path: PathBuf,
    expected_size: u64,
    received_size: u64,
    writer: Option<tokio::fs::File>,
    is_complete: bool,
}

impl ConnectionHandler {
    fn new(
        store_path: PathBuf,
        auth_key: Option<String>,
        peer_addr: SocketAddr,
        rate_limiter: &RateLimiter,
    ) -> Self {
        let authenticated = auth_key.is_none(); // No auth required if no key set
        Self {
            store_path,
            auth_key,
            authenticated,
            peer_addr,
            rate_limiter: rate_limiter.clone(),
            current_upload: None,
            last_activity: Instant::now(),
        }
    }

    async fn handle(
        &mut self,
        ws_stream: WebSocketStream<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>,
    ) -> Result<()> {
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // Don't send anything proactively - wait for client to initiate
        while let Some(msg) = ws_receiver.next().await {
            // Check timeout
            if self.last_activity.elapsed() > CONNECTION_TIMEOUT {
                warn!("Connection from {} timed out", self.peer_addr);
                break;
            }
            self.last_activity = Instant::now();

            let msg = msg?;

            match msg {
                Message::Text(text) => match serde_json::from_str::<ClientMessage>(&text) {
                    Ok(client_msg) => {
                        let responses = self.handle_message(client_msg).await?;
                        for response in responses {
                            let json = serde_json::to_string(&response)?;
                            ws_sender.send(Message::Text(json)).await?;
                        }
                    }
                    Err(e) => {
                        error!("Invalid message from {}: {}", self.peer_addr, e);
                        let response = ServerMessage::Error {
                            code: ErrorCode::InvalidRequest,
                            message: "Invalid message format".to_string(),
                        };
                        let json = serde_json::to_string(&response)?;
                        ws_sender.send(Message::Text(json)).await?;
                    }
                },
                Message::Binary(_) => {
                    let response = ServerMessage::Error {
                        code: ErrorCode::InvalidRequest,
                        message: "Binary messages not supported".to_string(),
                    };
                    let json = serde_json::to_string(&response)?;
                    ws_sender.send(Message::Text(json)).await?;
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                _ => {}
            }
        }

        // Cleanup any incomplete upload
        if let Some(upload) = &self.current_upload {
            if let Err(e) = fs::remove_file(&upload.temp_path).await {
                debug!("Failed to remove temp file: {}", e);
            }
        }

        Ok(())
    }

    async fn handle_message(&mut self, msg: ClientMessage) -> Result<Vec<ServerMessage>> {
        match msg {
            ClientMessage::Auth { key } => self.handle_auth(key).await,
            ClientMessage::UploadRequest { name, size } => {
                if !self.authenticated {
                    return Ok(vec![ServerMessage::Error {
                        code: ErrorCode::AuthRequired,
                        message: "Authentication required".to_string(),
                    }]);
                }
                self.handle_upload_request(name, size).await
            }
            ClientMessage::DataChunk { data, is_final } => {
                if !self.authenticated {
                    return Ok(vec![ServerMessage::Error {
                        code: ErrorCode::AuthRequired,
                        message: "Authentication required".to_string(),
                    }]);
                }
                self.handle_data_chunk(data, is_final).await
            }
            ClientMessage::ListRequest => {
                if !self.authenticated {
                    return Ok(vec![ServerMessage::Error {
                        code: ErrorCode::AuthRequired,
                        message: "Authentication required".to_string(),
                    }]);
                }
                self.handle_list_request().await
            }
            ClientMessage::GetRequest { name } => {
                if !self.authenticated {
                    return Ok(vec![ServerMessage::Error {
                        code: ErrorCode::AuthRequired,
                        message: "Authentication required".to_string(),
                    }]);
                }
                self.handle_get_request(name).await
            }
            ClientMessage::Ping => Ok(vec![ServerMessage::Pong]),
        }
    }

    async fn handle_auth(&mut self, key: String) -> Result<Vec<ServerMessage>> {
        if let Some(ref expected_key) = self.auth_key {
            if key == *expected_key {
                self.authenticated = true;
                debug!("Client {} authenticated successfully", self.peer_addr);
                Ok(vec![ServerMessage::AuthResult {
                    success: true,
                    message: None,
                }])
            } else {
                warn!("Client {} failed authentication", self.peer_addr);
                Ok(vec![ServerMessage::AuthResult {
                    success: false,
                    message: Some("Invalid authentication key".to_string()),
                }])
            }
        } else {
            self.authenticated = true;
            Ok(vec![ServerMessage::AuthResult {
                success: true,
                message: None,
            }])
        }
    }

    async fn handle_upload_request(
        &mut self,
        name: String,
        size: u64,
    ) -> Result<Vec<ServerMessage>> {
        // Validate request
        if let Err(e) = validate_filename(&name) {
            return Ok(vec![ServerMessage::UploadRejected { reason: e }]);
        }

        if let Err(e) = validate_file_size(size) {
            return Ok(vec![ServerMessage::UploadRejected { reason: e }]);
        }

        // Check rate limit
        if !self.rate_limiter.check_upload_rate(self.peer_addr).await {
            return Ok(vec![ServerMessage::Error {
                code: ErrorCode::RateLimited,
                message: "Upload rate limit exceeded".to_string(),
            }]);
        }

        // Check for existing upload
        if self.current_upload.is_some() {
            return Ok(vec![ServerMessage::Error {
                code: ErrorCode::InvalidRequest,
                message: "Upload already in progress".to_string(),
            }]);
        }

        // Generate unique filename if needed
        let final_name = self.generate_unique_filename(&name).await?;

        // Create temp file
        let temp_name = format!(".{}.tmp", Uuid::new_v4());
        let temp_path = self.store_path.join(&temp_name);
        let writer = fs::File::create(&temp_path).await?;

        self.current_upload = Some(UploadState {
            filename: final_name.clone(),
            temp_path,
            expected_size: size,
            received_size: 0,
            writer: Some(writer),
            is_complete: false,
        });

        info!(
            "Starting upload of {} from {} (size: {})",
            final_name, self.peer_addr, size
        );

        Ok(vec![ServerMessage::UploadAccepted { name: final_name }])
    }

    async fn handle_data_chunk(
        &mut self,
        data: Vec<u8>,
        is_final: bool,
    ) -> Result<Vec<ServerMessage>> {
        if let Some(ref mut upload) = self.current_upload {
            // Validate chunk
            if let Err(e) = validate_chunk_size(&data) {
                // Clean up - get temp_path before clearing
                let temp_path = upload.temp_path.clone();
                self.current_upload = None;
                if let Err(e) = fs::remove_file(&temp_path).await {
                    debug!("Failed to remove temp file: {}", e);
                }
                return Ok(vec![ServerMessage::Error {
                    code: ErrorCode::InvalidRequest,
                    message: e,
                }]);
            }

            // Write chunk
            if let Some(ref mut writer) = upload.writer {
                writer.write_all(&data).await?;
                upload.received_size += data.len() as u64;
            }

            // Always send ChunkReceived first
            let bytes_received = upload.received_size;
            
            if is_final {
                // Close writer
                if let Some(writer) = upload.writer.take() {
                    writer.sync_all().await?;
                    drop(writer);
                }

                // Move to final location
                let final_path = self.store_path.join(&upload.filename);
                fs::rename(&upload.temp_path, &final_path).await?;

                info!(
                    "Completed upload of {} from {} (received: {} bytes)",
                    upload.filename, self.peer_addr, upload.received_size
                );

                // Mark upload as complete but don't clear it yet
                upload.is_complete = true;
            }
            
            // Send ChunkReceived first
            let mut responses = vec![ServerMessage::ChunkReceived {
                bytes_received,
            }];
            
            // If upload is complete, also send UploadComplete
            if upload.is_complete {
                let total = upload.received_size;
                self.current_upload = None;
                responses.push(ServerMessage::UploadComplete {
                    total_bytes: total,
                });
            }
            
            Ok(responses)
        } else {
            Ok(vec![ServerMessage::Error {
                code: ErrorCode::InvalidRequest,
                message: "No upload in progress".to_string(),
            }])
        }
    }

    async fn handle_list_request(&mut self) -> Result<Vec<ServerMessage>> {
        let mut entries = fs::read_dir(&self.store_path).await?;
        let mut files = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".hecate") && !name.starts_with(".") {
                    let modified = metadata
                        .modified()?
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs();
                    let datetime = chrono::DateTime::<Utc>::from_timestamp(modified as i64, 0)
                        .unwrap_or_else(|| Utc::now());

                    files.push(FileInfo {
                        name,
                        size: metadata.len(),
                        created: datetime.to_rfc3339(),
                    });
                }
            }
        }

        // Sort by name
        files.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(vec![ServerMessage::FileList { files }])
    }

    async fn handle_get_request(&mut self, name: String) -> Result<Vec<ServerMessage>> {
        if let Err(e) = validate_filename(&name) {
            return Ok(vec![ServerMessage::Error {
                code: ErrorCode::InvalidRequest,
                message: e,
            }]);
        }

        let file_path = self.store_path.join(&name);

        // Check if file exists
        if !file_path.exists() {
            return Ok(vec![ServerMessage::Error {
                code: ErrorCode::FileNotFound,
                message: format!("File not found: {}", name),
            }]);
        }

        // Get file size
        let metadata = fs::metadata(&file_path).await?;
        let file_size = metadata.len();

        // Read and send file in chunks
        let mut file = fs::File::open(&file_path).await?;
        let mut buffer = vec![0u8; 1024 * 1024]; // 1MB chunks
        let mut total_sent = 0u64;

        loop {
            use tokio::io::AsyncReadExt;
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }

            total_sent += n as u64;
            let is_final = total_sent >= file_size;

            // This would normally be sent through the WebSocket
            // For now we just return the first chunk as a response
            return Ok(vec![ServerMessage::DataChunk {
                data: buffer[..n].to_vec(),
                is_final,
            }]);
        }

        Ok(vec![])
    }

    async fn generate_unique_filename(&self, name: &str) -> Result<String> {
        let path = self.store_path.join(name);
        if !path.exists() {
            return Ok(name.to_string());
        }

        // Extract base name and extension
        let base = name.trim_end_matches(".hecate");

        // Try timestamp-based name
        let timestamp = Utc::now().timestamp();
        let new_name = format!("{}-{}.hecate", base, timestamp);
        let new_path = self.store_path.join(&new_name);

        if !new_path.exists() {
            return Ok(new_name);
        }

        // Fall back to UUID
        let uuid = Uuid::new_v4();
        Ok(format!("{}-{}.hecate", base, uuid))
    }
}
