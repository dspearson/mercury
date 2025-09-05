use anyhow::{Context, Result};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::{
    accept_async, tungstenite::Message, WebSocketStream, MaybeTlsStream,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use native_tls::{Identity, TlsAcceptor};
use tokio_native_tls::TlsAcceptor as TokioTlsAcceptor;

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

    async fn cleanup_old_entries(&self) {
        let mut requests = self.requests.write().await;
        let mut uploads = self.uploads.write().await;
        let now = Instant::now();

        requests.retain(|_, times| {
            times.retain(|&t| now.duration_since(t) < Duration::from_secs(60));
            !times.is_empty()
        });

        uploads.retain(|_, times| {
            times.retain(|&t| now.duration_since(t) < Duration::from_secs(3600));
            !times.is_empty()
        });
    }
}

pub struct WebSocketServer {
    store_path: PathBuf,
    auth_key: Option<String>,
    rate_limiter: RateLimiter,
    active_connections: Arc<Mutex<usize>>,
    tls_acceptor: Option<TokioTlsAcceptor>,
}

impl WebSocketServer {
    pub async fn new(store_path: PathBuf, auth_key: Option<String>) -> Result<Self> {
        fs::create_dir_all(&store_path)
            .await
            .with_context(|| format!("Failed to create storage directory: {:?}", store_path))?;

        Ok(Self {
            store_path,
            auth_key,
            rate_limiter: RateLimiter::new(),
            active_connections: Arc::new(Mutex::new(0)),
            tls_acceptor: None,
        })
    }

    pub async fn with_tls(mut self, cert_path: &PathBuf, key_path: &PathBuf) -> Result<Self> {
        // Read cert and key files
        let cert_pem = fs::read(cert_path)
            .await
            .with_context(|| format!("Failed to read certificate from {:?}", cert_path))?;
        let key_pem = fs::read(key_path)
            .await
            .with_context(|| format!("Failed to read key from {:?}", key_path))?;

        // For native-tls, we need to convert PEM to PKCS12
        // We'll use a temporary in-memory conversion
        use std::io::Write;
        use tempfile::NamedTempFile;
        
        // Write cert and key to temp files
        let mut cert_file = NamedTempFile::new()?;
        cert_file.write_all(&cert_pem)?;
        let mut key_file = NamedTempFile::new()?;
        key_file.write_all(&key_pem)?;
        
        // Use openssl command to convert to PKCS12
        let output = std::process::Command::new("openssl")
            .args(&[
                "pkcs12", "-export",
                "-out", "/dev/stdout",
                "-inkey", key_file.path().to_str().unwrap(),
                "-in", cert_file.path().to_str().unwrap(),
                "-password", "pass:",
            ])
            .output()
            .context("Failed to run openssl command")?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("OpenSSL conversion failed: {}", stderr);
        }
        
        let identity = Identity::from_pkcs12(&output.stdout, "")
            .context("Failed to create TLS identity from PKCS12")?;

        let acceptor = TlsAcceptor::new(identity)
            .context("Failed to create TLS acceptor")?;

        self.tls_acceptor = Some(TokioTlsAcceptor::from(acceptor));
        Ok(self)
    }

    pub async fn run(self: Arc<Self>, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind to {}", addr))?;

        info!("WebSocket server listening on {}", addr);

        // Spawn cleanup task
        let rate_limiter = self.rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                rate_limiter.cleanup_old_entries().await;
            }
        });

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            // Check concurrent connection limit
            let mut conn_count = self.active_connections.lock().await;
            if *conn_count >= MAX_CONCURRENT_CONNECTIONS {
                warn!("Rejecting connection from {} - too many concurrent connections", peer_addr);
                continue;
            }
            *conn_count += 1;
            drop(conn_count);

            let server = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream, peer_addr).await {
                    error!("Error handling connection from {}: {}", peer_addr, e);
                }
                
                // Decrement connection count
                let mut conn_count = server.active_connections.lock().await;
                *conn_count = conn_count.saturating_sub(1);
            });
        }
    }

    async fn handle_connection(&self, stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        info!("New secure WebSocket connection from {}", peer_addr);

        // TLS is required
        let tls_acceptor = self.tls_acceptor.as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS acceptor not configured - server misconfiguration"))?;
        
        // Handle TLS connection
        let tls_stream = tls_acceptor.accept(stream)
            .await
            .context("Failed to accept TLS connection")?;
        let ws_stream = accept_async(MaybeTlsStream::NativeTls(tls_stream))
            .await
            .context("Failed to accept WebSocket connection over TLS")?;

        let mut handler = ConnectionHandler {
            ws: ws_stream,
            peer_addr,
            authenticated: self.auth_key.is_none(), // No auth required if no key set
            server: self,
            last_activity: Instant::now(),
            current_upload: None,
        };

        handler.run().await
    }
}

struct CurrentUpload {
    name: String,
    data: Vec<u8>,
    bytes_received: u64,
}

struct ConnectionHandler<'a> {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    peer_addr: SocketAddr,
    authenticated: bool,
    server: &'a WebSocketServer,
    last_activity: Instant,
    current_upload: Option<CurrentUpload>,
}

impl<'a> ConnectionHandler<'a> {
    async fn run(&mut self) -> Result<()> {
        while let Some(msg) = self.ws.next().await {
            // Check timeout
            if self.last_activity.elapsed() > CONNECTION_TIMEOUT {
                warn!("Connection timeout for {}", self.peer_addr);
                self.send_error(ErrorCode::ServerError, "Connection timeout").await?;
                break;
            }

            self.last_activity = Instant::now();

            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    error!("WebSocket error from {}: {}", self.peer_addr, e);
                    break;
                }
            };

            match msg {
                Message::Text(text) => {
                    // Rate limiting check
                    if !self.server.rate_limiter.check_request_rate(self.peer_addr).await {
                        self.send_error(ErrorCode::RateLimited, "Too many requests").await?;
                        continue;
                    }

                    if let Err(e) = self.handle_text_message(text).await {
                        error!("Error handling message from {}: {}", self.peer_addr, e);
                        self.send_error(ErrorCode::ServerError, "Internal server error").await?;
                    }
                }
                Message::Binary(_) => {
                    self.send_error(ErrorCode::InvalidRequest, "Binary messages not supported").await?;
                }
                Message::Close(_) => {
                    info!("Client {} closed connection", self.peer_addr);
                    break;
                }
                Message::Ping(_) | Message::Pong(_) => {
                    // Handled automatically by tungstenite
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn handle_text_message(&mut self, text: String) -> Result<()> {
        let msg: ClientMessage = serde_json::from_str(&text)
            .context("Failed to deserialize client message")?;

        match msg {
            ClientMessage::Auth { key } => {
                self.handle_auth(key).await?;
            }
            ClientMessage::UploadRequest { name, size } => {
                if !self.authenticated {
                    self.send_error(ErrorCode::AuthRequired, "Authentication required").await?;
                    return Ok(());
                }
                self.handle_upload_request(name, size).await?;
            }
            ClientMessage::DataChunk { data, is_final } => {
                if !self.authenticated {
                    self.send_error(ErrorCode::AuthRequired, "Authentication required").await?;
                    return Ok(());
                }
                self.handle_data_chunk(data, is_final).await?;
            }
            ClientMessage::ListRequest => {
                if !self.authenticated {
                    self.send_error(ErrorCode::AuthRequired, "Authentication required").await?;
                    return Ok(());
                }
                self.handle_list_request().await?;
            }
            ClientMessage::GetRequest { name } => {
                if !self.authenticated {
                    self.send_error(ErrorCode::AuthRequired, "Authentication required").await?;
                    return Ok(());
                }
                self.handle_get_request(name).await?;
            }
            ClientMessage::Ping => {
                self.send_message(ServerMessage::Pong).await?;
            }
        }

        Ok(())
    }

    async fn handle_auth(&mut self, key: String) -> Result<()> {
        if let Some(ref expected_key) = self.server.auth_key {
            if key == *expected_key {
                self.authenticated = true;
                debug!("Client {} authenticated successfully", self.peer_addr);
                self.send_message(ServerMessage::AuthResult {
                    success: true,
                    message: None,
                }).await?;
            } else {
                warn!("Client {} failed authentication", self.peer_addr);
                self.send_message(ServerMessage::AuthResult {
                    success: false,
                    message: Some("Invalid authentication key".to_string()),
                }).await?;
            }
        } else {
            self.authenticated = true;
            self.send_message(ServerMessage::AuthResult {
                success: true,
                message: None,
            }).await?;
        }
        Ok(())
    }

    async fn handle_upload_request(&mut self, name: String, size: u64) -> Result<()> {
        // Validate inputs
        if let Err(e) = validate_filename(&name) {
            self.send_message(ServerMessage::UploadRejected {
                reason: e,
            }).await?;
            return Ok(());
        }

        if let Err(e) = validate_file_size(size) {
            self.send_message(ServerMessage::UploadRejected {
                reason: e,
            }).await?;
            return Ok(());
        }

        // Check upload rate limit
        if !self.server.rate_limiter.check_upload_rate(self.peer_addr).await {
            self.send_message(ServerMessage::UploadRejected {
                reason: "Upload rate limit exceeded".to_string(),
            }).await?;
            return Ok(());
        }

        // Generate unique filename
        let accepted_name = self.generate_unique_name(&name).await?;

        info!("Accepting upload from {} as {}", self.peer_addr, accepted_name);

        // Initialise the upload state
        self.current_upload = Some(CurrentUpload {
            name: accepted_name.clone(),
            data: Vec::with_capacity(size as usize),
            bytes_received: 0,
        });

        self.send_message(ServerMessage::UploadAccepted {
            name: accepted_name,
        }).await?;

        Ok(())
    }

    async fn handle_data_chunk(&mut self, data: Vec<u8>, is_final: bool) -> Result<()> {
        // Validate chunk
        if let Err(e) = validate_chunk_size(&data) {
            self.send_error(ErrorCode::InvalidRequest, &e).await?;
            return Ok(());
        }

        // Check if there's an upload in progress
        if self.current_upload.is_some() {
            let bytes_received = {
                let upload = self.current_upload.as_mut().unwrap();
                upload.data.extend_from_slice(&data);
                upload.bytes_received += data.len() as u64;
                upload.bytes_received
            };
            
            self.send_message(ServerMessage::ChunkReceived {
                bytes_received,
            }).await?;
            
            if is_final {
                // Extract upload data for saving
                let upload = self.current_upload.take().unwrap();
                let file_path = self.server.store_path.join(&upload.name);
                let upload_name = upload.name.clone();
                let total_bytes = upload.bytes_received;
                
                fs::write(&file_path, &upload.data).await
                    .context("Failed to save file")?;
                
                self.send_message(ServerMessage::UploadComplete {
                    total_bytes,
                }).await?;
                
                info!("Saved file {} ({} bytes) from {}", upload_name, total_bytes, self.peer_addr);
            }
        } else {
            self.send_error(ErrorCode::InvalidRequest, "No upload in progress").await?;
        }

        Ok(())
    }

    async fn handle_list_request(&mut self) -> Result<()> {
        let mut files = Vec::new();
        let mut entries = fs::read_dir(&self.server.store_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".hecate") {
                    let metadata = entry.metadata().await?;
                    files.push(FileInfo {
                        name: name.to_string(),
                        size: metadata.len(),
                        created: Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        self.send_message(ServerMessage::FileList { files }).await?;
        Ok(())
    }

    async fn handle_get_request(&mut self, name: String) -> Result<()> {
        // Validate filename
        if let Err(e) = validate_filename(&name) {
            self.send_error(ErrorCode::InvalidRequest, &e).await?;
            return Ok(());
        }

        let file_path = self.server.store_path.join(&name);
        
        if !file_path.exists() {
            self.send_error(ErrorCode::FileNotFound, "File not found").await?;
            return Ok(());
        }

        // Read and send file in chunks
        let file_data = fs::read(&file_path).await?;
        let chunks: Vec<_> = file_data.chunks(1024 * 1024).collect();
        let total_chunks = chunks.len();

        for (i, chunk) in chunks.into_iter().enumerate() {
            self.send_message(ServerMessage::DataChunk {
                data: chunk.to_vec(),
                is_final: i == total_chunks - 1,
            }).await?;
        }

        Ok(())
    }

    async fn generate_unique_name(&self, requested: &str) -> Result<String> {
        let base = requested.trim_end_matches(".hecate");
        let candidate = format!("{}.hecate", base);
        let path = self.server.store_path.join(&candidate);

        if !path.exists() {
            return Ok(candidate);
        }

        let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
        let candidate = format!("{}-{}.hecate", base, timestamp);
        let path = self.server.store_path.join(&candidate);

        if !path.exists() {
            return Ok(candidate);
        }

        let uuid = Uuid::new_v4();
        Ok(format!("{}-{}-{}.hecate", base, timestamp, uuid))
    }

    async fn send_message(&mut self, msg: ServerMessage) -> Result<()> {
        let json = serde_json::to_string(&msg)?;
        self.ws.send(Message::Text(json)).await?;
        self.ws.flush().await?;
        Ok(())
    }

    async fn send_error(&mut self, code: ErrorCode, message: &str) -> Result<()> {
        self.send_message(ServerMessage::Error {
            code,
            message: message.to_string(),
        }).await
    }
}