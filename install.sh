#!/usr/bin/env bash
# Installation script for Mercury server

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
   echo "Please run as root (use sudo)"
   exit 1
fi

echo "Installing Mercury server..."

# Create user and group
if ! id -u mercury >/dev/null 2>&1; then
    useradd --system --home /var/lib/mercury --shell /bin/false mercury
    echo "Created mercury user"
fi

# Create directories
mkdir -p /var/lib/mercury/storage
mkdir -p /etc/mercury
mkdir -p /var/log/mercury

# Set permissions
chown -R mercury:mercury /var/lib/mercury
chown -R mercury:mercury /var/log/mercury
chown mercury:mercury /etc/mercury
chmod 750 /var/lib/mercury
chmod 750 /etc/mercury

# Build and install binary
echo "Building Mercury..."
cargo build --release
cp target/release/mercury /usr/local/bin/
chmod 755 /usr/local/bin/mercury

# Install hash_password utility
cp target/release/hash_password /usr/local/bin/mercury-hash-password
chmod 755 /usr/local/bin/mercury-hash-password

# Copy systemd service file
cp mercury.service /etc/systemd/system/
systemctl daemon-reload

# Create default config files
if [ ! -f /etc/mercury/mercury.env ]; then
    cat > /etc/mercury/mercury.env <<EOF
# Mercury environment configuration
# Uncomment and modify as needed

# Authentication key (legacy mode)
# MERCURY_AUTH_KEY=your-secret-key-here

# Log level
# RUST_LOG=info
EOF
    chmod 640 /etc/mercury/mercury.env
    chown root:mercury /etc/mercury/mercury.env
fi

if [ ! -f /etc/mercury/auth.json ]; then
    cat > /etc/mercury/auth.json <<EOF
[
  {
    "client_id": "admin",
    "key_hash": "$(mercury-hash-password 'change-me-immediately')",
    "permissions": {
      "can_upload": true,
      "can_download": true,
      "can_list": true,
      "max_file_size": null,
      "max_total_storage": null
    }
  }
]
EOF
    chmod 640 /etc/mercury/auth.json
    chown root:mercury /etc/mercury/auth.json
fi

echo ""
echo "Mercury server installed successfully!"
echo ""
echo "Next steps:"
echo "1. Copy your TLS certificates to /etc/mercury/cert.pem and /etc/mercury/key.pem"
echo "2. Set proper permissions: chmod 644 cert.pem && chmod 640 key.pem"
echo "3. Edit /etc/mercury/auth.json to configure client authentication"
echo "4. Optionally edit /etc/mercury/mercury.env for environment variables"
echo "5. Start the service: systemctl start mercury"
echo "6. Enable at boot: systemctl enable mercury"
echo "7. Check status: systemctl status mercury"
echo "8. View logs: journalctl -u mercury -f"
echo ""
echo "To generate password hashes for auth.json:"
echo "  mercury-hash-password 'your-password'"