# Mercury Server Security Documentation

## Security Features Implemented

### 1. Mandatory TLS
- **Enforced**: Server refuses to start without TLS certificates
- **Implementation**: Uses rustls (pure Rust TLS) instead of OpenSSL
- **Configuration**: Requires PEM-encoded certificate and private key files

### 2. Per-Client Authentication
- **Multi-client support**: Each client has unique credentials and permissions
- **Secure storage**: Passwords hashed with Argon2id (industry-standard)
- **Backward compatible**: Supports legacy single-key authentication

#### Authentication Methods:
1. **Legacy mode**: Single shared key via `-k` flag or `MERCURY_AUTH_KEY` env var
2. **Multi-client mode**: JSON config file with per-client credentials
3. **Token format**: `client_id:password` for multi-client authentication

### 3. Fine-Grained Permissions
Each client can have individual permissions:
- `can_upload`: Allow file uploads
- `can_download`: Allow file downloads  
- `can_list`: Allow listing files
- `max_file_size`: Maximum size per file (enforced)
- `max_total_storage`: Total quota (defined but not enforced)

### 4. Streaming File Operations
- **Memory-efficient**: Files streamed to disk, not buffered in memory
- **Temporary files**: Uploads written to `.filename.tmp` then atomically moved
- **Size validation**: Enforces declared file size during upload

### 5. Path Security
- **Path canonicalisation**: All file paths canonicalised to prevent traversal
- **Directory confinement**: Files restricted to storage directory
- **Filename validation**: Strict rules preventing directory traversal

### 6. Connection Management
- **Connection limiting**: Maximum 50 concurrent connections
- **Timeout protection**: 5-minute connection timeout
- **Note**: No rate limiting for authenticated clients (trusted users)

### 7. Input Validation
- **Filename validation**: Must end with `.hecate`, no path separators
- **File size limits**: 100GB maximum file size
- **Chunk size limits**: 1MB maximum chunk size
- **Control character blocking**: No control characters in filenames

## Configuration Examples

### Single-Key Authentication (Legacy)
```bash
# Via command line
mercury --store /storage --port 10112 \
        --tls-cert cert.pem --tls-key key.pem \
        --auth-key "my-secret-key"

# Via environment variable
export MERCURY_AUTH_KEY="my-secret-key"
mercury --store /storage --port 10112 \
        --tls-cert cert.pem --tls-key key.pem
```

### Multi-Client Authentication
```bash
# Create password hash
cargo run --bin hash_password -- "alice-password"

# Create auth config (auth-config.json)
[
  {
    "client_id": "alice",
    "key_hash": "$argon2id$...", 
    "permissions": {
      "can_upload": true,
      "can_download": true,
      "can_list": true,
      "max_file_size": 10737418240,
      "max_total_storage": 107374182400
    }
  }
]

# Run server with config
mercury --store /storage --port 10112 \
        --tls-cert cert.pem --tls-key key.pem \
        --auth-config auth-config.json
```

### Client Connection
```bash
# Legacy authentication
hecate files/ --online --name backup \
       --server localhost:10112 \
       --auth-key "my-secret-key"

# Multi-client authentication  
hecate files/ --online --name backup \
       --server localhost:10112 \
       --auth-key "alice:alice-password"
```

## Security Best Practices

1. **Certificate Management**
   - Use certificates from trusted CA in production
   - Regularly rotate certificates
   - Protect private keys with appropriate file permissions

2. **Authentication Keys**
   - Use strong, unique passwords for each client
   - Rotate passwords regularly
   - Never commit passwords to version control

3. **Network Security**
   - Run behind reverse proxy for additional security layers
   - Implement firewall rules to restrict access
   - Monitor logs for suspicious activity

4. **Storage Security**
   - Set appropriate filesystem permissions on storage directory
   - Regular backups of encrypted archives
   - Monitor disk usage to prevent DoS

5. **Monitoring**
   - Enable verbose logging in production
   - Set up alerts for rate limit violations
   - Monitor authentication failures

## Threat Model

### Protected Against:
- **Path traversal attacks**: Canonicalisation and validation
- **Memory exhaustion**: Streaming writes, size limits
- **Brute force**: Argon2id hashing (authentication required)
- **Unauthorised access**: Per-client auth and permissions
- **Man-in-the-middle**: Mandatory TLS encryption
- **Resource exhaustion**: Connection limits, timeouts

### Assumptions:
- TLS certificates are properly managed
- Storage directory has appropriate permissions
- Host system is secure and updated
- Clients protect their authentication credentials

## Audit Log Format

The server logs security-relevant events:
- Authentication attempts (success/failure)
- File uploads/downloads with client ID
- Permission denials
- TLS connection errors
- Connection limit reached events

Enable verbose logging with `-v` flag for detailed security monitoring.