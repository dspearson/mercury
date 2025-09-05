# Mercury Server Configuration Guide

## Overview

Mercury supports configuration through:
1. TOML configuration file (recommended)
2. Command-line arguments
3. Environment variables

Priority order: CLI args > Config file > Environment > Defaults

## Quick Start

Generate an example configuration:
```bash
mercury --generate-config > mercury.toml
```

Run with config file:
```bash
mercury --config mercury.toml
```

## Configuration File

### Full Example

```toml
# Mercury Server Configuration

[server]
# Port for WebSocket connections
port = 10112

# Interface to bind to
bind = "0.0.0.0"

# Storage directory for encrypted archives
storage_path = "/var/lib/mercury/storage"

# Maximum concurrent connections
max_connections = 50

# Connection timeout in seconds
connection_timeout_secs = 300

[tls]
# TLS certificate and key (required)
cert_path = "/etc/mercury/cert.pem"
key_path = "/etc/mercury/key.pem"

[auth]
# Option 1: Single shared key
auth_key = "your-secret-key"

# Option 2: Per-client credentials file
auth_config_path = "/etc/mercury/auth.json"

[health]
# Enable health check endpoint
enabled = true

# Port for health check HTTP server
port = 9090

[logging]
# Log level: trace, debug, info, warn, error
level = "info"

# Format: text or json
format = "json"  # Use json for production
```

### Minimal Configuration

```toml
[tls]
cert_path = "cert.pem"
key_path = "key.pem"

[auth]
auth_key = "secret-key"
```

## Health Check Endpoints

When `health.enabled = true`, Mercury provides HTTP endpoints for monitoring:

### `/health` - Detailed health status
```bash
curl http://localhost:9090/health
```

Response:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 3600,
  "storage_path": "/var/lib/mercury/storage",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### `/livez` - Kubernetes liveness probe
```bash
curl http://localhost:9090/livez
```

Response:
```json
{"alive": true}
```

### `/readyz` - Kubernetes readiness probe
```bash
curl http://localhost:9090/readyz
```

Response:
```json
{
  "ready": true,
  "storage_accessible": true
}
```

Returns HTTP 200 when ready, 503 when not ready.

## Authentication Configuration

### Single Key (Simple)

Config file:
```toml
[auth]
auth_key = "your-secret-key"
```

Or environment:
```bash
export MERCURY_AUTH_KEY="your-secret-key"
```

### Multi-Client (Production)

1. Create client credentials:
```bash
mercury-hash-password 'alice-password' > alice.hash
mercury-hash-password 'bob-password' > bob.hash
```

2. Create auth.json:
```json
[
  {
    "client_id": "alice",
    "key_hash": "<contents of alice.hash>",
    "permissions": {
      "can_upload": true,
      "can_download": true,
      "can_list": true,
      "max_file_size": 10737418240
    }
  },
  {
    "client_id": "bob",
    "key_hash": "<contents of bob.hash>",
    "permissions": {
      "can_upload": true,
      "can_download": false,
      "can_list": true,
      "max_file_size": 1073741824
    }
  }
]
```

3. Reference in config:
```toml
[auth]
auth_config_path = "/etc/mercury/auth.json"
```

## Logging Configuration

### Development
```toml
[logging]
level = "debug"
format = "text"
```

### Production
```toml
[logging]
level = "info"
format = "json"  # For log aggregation systems
```

### Debug Specific Modules
```bash
RUST_LOG=mercury=debug,tokio=warn mercury --config mercury.toml
```

## Command-Line Override

CLI arguments override config file values:

```bash
# Use config but override port
mercury --config mercury.toml --port 10113

# Use config but override log level
mercury --config mercury.toml --verbose  # Sets debug level
```

## Docker Configuration

### Using Config File

Dockerfile:
```dockerfile
FROM rust:1.75 as builder
# ... build steps ...

FROM debian:bookworm-slim
COPY --from=builder /app/mercury /usr/local/bin/
COPY mercury.toml /etc/mercury/

CMD ["mercury", "--config", "/etc/mercury/mercury.toml"]
```

### Using Environment Variables

docker-compose.yml:
```yaml
version: '3.8'
services:
  mercury:
    image: mercury:latest
    environment:
      - MERCURY_AUTH_KEY=${MERCURY_AUTH_KEY}
    volumes:
      - ./config/mercury.toml:/etc/mercury/mercury.toml
      - ./certs:/etc/mercury/certs
      - mercury-data:/var/lib/mercury/storage
    ports:
      - "10112:10112"  # WebSocket
      - "9090:9090"    # Health check
    command: ["--config", "/etc/mercury/mercury.toml"]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9090/readyz"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  mercury-data:
```

## Kubernetes Configuration

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mercury-config
data:
  mercury.toml: |
    [server]
    port = 10112
    storage_path = "/data"
    
    [tls]
    cert_path = "/tls/tls.crt"
    key_path = "/tls/tls.key"
    
    [auth]
    auth_config_path = "/auth/auth.json"
    
    [health]
    enabled = true
    port = 9090
    
    [logging]
    level = "info"
    format = "json"
```

### Deployment with Config

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mercury
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mercury
  template:
    metadata:
      labels:
        app: mercury
    spec:
      containers:
      - name: mercury
        image: mercury:latest
        args: ["--config", "/config/mercury.toml"]
        ports:
        - containerPort: 10112
          name: websocket
        - containerPort: 9090
          name: health
        volumeMounts:
        - name: config
          mountPath: /config
        - name: tls
          mountPath: /tls
        - name: storage
          mountPath: /data
        livenessProbe:
          httpGet:
            path: /livez
            port: health
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: health
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: mercury-config
      - name: tls
        secret:
          secretName: mercury-tls
      - name: storage
        persistentVolumeClaim:
          claimName: mercury-storage
```

## Systemd with Config File

/etc/systemd/system/mercury.service:
```ini
[Unit]
Description=Mercury Storage Server
After=network.target

[Service]
Type=simple
User=mercury
Group=mercury
WorkingDirectory=/var/lib/mercury

# Use config file
ExecStart=/usr/local/bin/mercury --config /etc/mercury/mercury.toml

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### Config File Not Found
```
Error: Failed to read config file: /etc/mercury/mercury.toml
```
Solution: Check file exists and has correct permissions

### Invalid TOML Syntax
```
Error: Failed to parse config file: expected value at line 5 column 10
```
Solution: Validate TOML syntax at https://www.toml-lint.com/

### TLS Not Configured
```
Error: TLS certificates are required. Configure tls.cert_path and tls.key_path
```
Solution: Add TLS configuration to config file or use --tls-cert and --tls-key

### Health Check Not Responding
Check if port is blocked by firewall:
```bash
sudo firewall-cmd --add-port=9090/tcp
```

### Storage Not Accessible
```json
{"ready":false,"storage_accessible":false}
```
Solution: Verify storage_path exists and has correct permissions