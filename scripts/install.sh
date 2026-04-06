#!/bin/bash
# WAF Installation Script
# Installs WAF on a fresh Linux system

set -e

echo "======================================"
echo " WAF Installation Script"
echo "======================================"

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/debian_version ]; then
    PKG_MANAGER="apt-get"
    echo "Detected Debian/Ubuntu system"
elif [ -f /etc/redhat-release ]; then
    PKG_MANAGER="yum"
    echo "Detected RedHat/CentOS system"
elif [ -f /etc/arch-release ]; then
    PKG_MANAGER="pacman"
    echo "Detected Arch Linux system"
else
    echo "Unsupported distribution"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
case $PKG_MANAGER in
    apt-get)
        apt-get update
        apt-get install -y curl docker.io docker-compose
        ;;
    yum)
        yum install -y docker
        systemctl start docker
        systemctl enable docker
        ;;
    pacman)
        pacman -Sy docker --noconfirm
        systemctl start docker
        systemctl enable docker
        ;;
esac

# Create WAF user
echo "Creating waf user..."
useradd -m -s /bin/bash waf 2>/dev/null || true

# Create directories
echo "Creating directories..."
mkdir -p /opt/waf/{config,rules,logs}
mkdir -p /var/log/waf

# Set permissions
chown -R waf:waf /opt/waf
chown -R waf:waf /var/log/waf

# Download WAF (placeholder - would download actual release)
echo "Downloading WAF..."
# curl -L -o /usr/local/bin/waf https://github.com/username/waf/releases/latest/waf
echo "Note: Download actual release from https://github.com/username/waf/releases"
chmod +x /usr/local/bin/waf

# Copy default configuration
echo "Installing default configuration..."
# cp -r ./config /opt/waf/
# cp -r ./rules /opt/waf/

# Setup systemd service
echo "Installing systemd service..."
cat > /etc/systemd/system/waf.service << 'EOF'
[Unit]
Description=WAF - Web Application Firewall
After=network.target docker.service

[Service]
Type=simple
User=waf
ExecStart=/usr/local/bin/waf --config /opt/waf/config/waf.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Enable service
systemctl enable waf

echo ""
echo "======================================"
echo " Installation Complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "  1. Edit /opt/waf/config/waf.yaml with your settings"
echo "  2. Run: sudo systemctl start waf"
echo "  3. Check status: sudo systemctl status waf"
echo "  4. View logs: journalctl -u waf -f"
echo ""
echo "Access WAF at: http://localhost:8080"
echo "Admin API at: http://localhost:8081"
echo "Metrics at: http://localhost:9090/metrics"
echo ""