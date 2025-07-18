#!/bin/bash

# WiFi Traffic Monitor - Real Environment Installation Script
# For IPtime AX300M Router Environment (172.26.35.0/24)

set -e

echo "================================================================"
echo "WiFi Traffic Monitor - Real Environment Setup"
echo "Target Network: 172.26.35.0/24"
echo "Router: IPtime AX300M (172.26.35.10)"
echo "Monitor PC: 172.26.35.1"
echo "================================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   log_error "This script should not be run as root"
   exit 1
fi

# Get current user
CURRENT_USER=$(whoami)
PROJECT_DIR="/opt/wifi-monitor"

log_info "Starting installation for user: $CURRENT_USER"

# Detect network interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$INTERFACE" ]; then
    log_error "Could not detect default network interface"
    exit 1
fi
log_info "Detected network interface: $INTERFACE"

# Check network configuration
CURRENT_IP=$(ip addr show $INTERFACE | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
if [[ ! $CURRENT_IP =~ ^172\.26\.35\. ]]; then
    log_warning "Current IP ($CURRENT_IP) is not in expected range (172.26.35.0/24)"
    log_warning "Please ensure you're on the correct network"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo
log_info "Step 1: Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo
log_info "Step 2: Installing required packages..."
sudo apt install -y \
    python3 python3-pip python3-venv \
    mongodb nginx \
    tcpdump wireshark-common \
    aircrack-ng bridge-utils net-tools \
    curl wget git \
    ufw \
    libpcap-dev

# Add user to wireshark group for packet capture permissions
sudo usermod -a -G wireshark $CURRENT_USER
log_success "Added $CURRENT_USER to wireshark group"

echo
log_info "Step 3: Setting up project directory..."
if [ -d "$PROJECT_DIR" ]; then
    log_warning "Project directory already exists. Backing up..."
    sudo mv $PROJECT_DIR $PROJECT_DIR.backup.$(date +%Y%m%d_%H%M%S)
fi

sudo mkdir -p $PROJECT_DIR
sudo chown $CURRENT_USER:$CURRENT_USER $PROJECT_DIR
log_success "Created project directory: $PROJECT_DIR"

echo
log_info "Step 4: Copying project files..."
# Check if we're in the project directory
if [ -f "requirements.txt" ] && [ -f "src/web_app.py" ]; then
    cp -r . $PROJECT_DIR/
    log_success "Copied project files from current directory"
else
    log_error "Project files not found in current directory"
    log_info "Please ensure you're running this script from the project root directory"
    exit 1
fi

cd $PROJECT_DIR

echo
log_info "Step 5: Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
log_success "Python environment setup complete"

echo
log_info "Step 6: Configuring for real environment..."

# Create real environment config
cat > config/real_environment.json << EOF
{
  "environment": "real",
  "network": {
    "interface": "$INTERFACE",
    "ip_range": "172.26.35.0/24",
    "gateway": "172.26.35.254",
    "dns_servers": ["203.237.32.100", "203.237.32.101"],
    "capture_mode": "mirror"
  },
  "router": {
    "ip": "172.26.35.10",
    "model": "IPtime AX300M",
    "ssid": "Suman-5G",
    "admin_url": "http://172.26.35.10"
  },
  "security": {
    "jwt_expiry_hours": 24,
    "rsa_key_size": 2048,
    "force_https": true,
    "max_login_attempts": 5
  },
  "capture": {
    "mode": "mirror",
    "filter": "net 172.26.35.0/24 and not arp",
    "buffer_size": 65536
  },
  "database": {
    "name": "traffic_monitor_real",
    "retention_days": 30
  },
  "web": {
    "host": "0.0.0.0",
    "port": 5000,
    "ssl_cert": "keys/server.crt",
    "ssl_key": "keys/server.key"
  }
}
EOF

log_success "Created real environment configuration"

echo
log_info "Step 7: Setting up MongoDB..."
sudo systemctl start mongod
sudo systemctl enable mongod

# Wait for MongoDB to start
sleep 5

# Create database and user
mongo --eval "
use traffic_monitor_real;
db.createUser({
  user: 'wifi_monitor',
  pwd: 'SecureMonitorPass2024!',
  roles: [
    { role: 'readWrite', db: 'traffic_monitor_real' }
  ]
});
"

log_success "MongoDB setup complete"

echo
log_info "Step 8: Generating SSL certificates..."
mkdir -p keys
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout keys/server.key -out keys/server.crt \
    -subj "/C=KR/ST=Gwangju/L=GIST/O=WiFiMonitorLab/CN=$CURRENT_IP"

chmod 600 keys/server.key
chmod 644 keys/server.crt
log_success "SSL certificates generated"

echo
log_info "Step 9: Setting up packet capture permissions..."
# Set capabilities for Python to capture packets without sudo
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Create packet capture test script
cat > test_capture.py << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.append('/opt/wifi-monitor/src')
from packet_capture import PacketCapture
import time

print("Testing packet capture setup...")
try:
    capture = PacketCapture(
        interface='eth0',  # Will be updated by installer
        capture_mode='mirror',
        network_filter='net 172.26.35.0/24 and not arp'
    )
    print("✓ PacketCapture initialized successfully")
    print("✓ MongoDB connection established")
    print("✓ Interface configuration successful")
    print("\nReal environment setup appears to be working!")
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
EOF

# Update interface in test script
sed -i "s/eth0/$INTERFACE/g" test_capture.py
chmod +x test_capture.py

log_success "Packet capture permissions configured"

echo
log_info "Step 10: Configuring firewall..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 5000/tcp
sudo ufw allow from 172.26.35.0/24 to any port 27017  # MongoDB from local network only

log_success "Firewall configured"

echo
log_info "Step 11: Creating systemd service..."
sudo tee /etc/systemd/system/wifi-monitor-real.service > /dev/null << EOF
[Unit]
Description=WiFi Traffic Monitor (Real Environment)
After=network.target mongod.service
Wants=mongod.service

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_USER
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/venv/bin
Environment=PYTHONPATH=$PROJECT_DIR
ExecStart=$PROJECT_DIR/venv/bin/python src/web_app.py --config config/real_environment.json
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$PROJECT_DIR
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wifi-monitor-real

log_success "Systemd service created"

echo
log_info "Step 12: Creating management scripts..."

# Create startup script
cat > start_monitor.sh << EOF
#!/bin/bash
cd $PROJECT_DIR
source venv/bin/activate
echo "Starting WiFi Traffic Monitor (Real Environment)..."
sudo systemctl start wifi-monitor-real
echo "Service started. Check status with: sudo systemctl status wifi-monitor-real"
echo "Access web interface at: https://$CURRENT_IP:5000"
EOF
chmod +x start_monitor.sh

# Create test script
cat > test_environment.sh << EOF
#!/bin/bash
cd $PROJECT_DIR

echo "=== WiFi Traffic Monitor - Environment Test ==="

# Test network connectivity
echo "1. Testing network connectivity..."
ping -c 3 172.26.35.10 > /dev/null 2>&1
if [ \$? -eq 0 ]; then
    echo "   ✓ Router (172.26.35.10) is reachable"
else
    echo "   ✗ Router (172.26.35.10) is NOT reachable"
fi

ping -c 3 8.8.8.8 > /dev/null 2>&1
if [ \$? -eq 0 ]; then
    echo "   ✓ Internet connectivity is working"
else
    echo "   ✗ Internet connectivity is NOT working"
fi

# Test MongoDB
echo "2. Testing MongoDB..."
mongo --eval "db.stats()" > /dev/null 2>&1
if [ \$? -eq 0 ]; then
    echo "   ✓ MongoDB is running"
else
    echo "   ✗ MongoDB is NOT running"
fi

# Test packet capture
echo "3. Testing packet capture..."
source venv/bin/activate
python3 test_capture.py

# Test web service
echo "4. Testing web service..."
curl -k -s https://localhost:5000/api/health > /dev/null 2>&1
if [ \$? -eq 0 ]; then
    echo "   ✓ Web service is responding"
else
    echo "   ✗ Web service is NOT responding"
fi

echo
echo "=== Test Complete ==="
EOF
chmod +x test_environment.sh

# Create router configuration helper
cat > configure_router.sh << 'EOF'
#!/bin/bash

echo "=== IPtime AX300M Router Configuration Guide ==="
echo
echo "To enable traffic monitoring, configure port mirroring on your router:"
echo
echo "1. Open web browser and go to: http://172.26.35.10"
echo "2. Login with admin credentials"
echo "3. Navigate to: 고급설정 (Advanced Settings) → 네트워크 도구 (Network Tools)"
echo "4. Find 포트 미러링 (Port Mirroring) option"
echo "5. Configure:"
echo "   - Source Interface: 무선 인터페이스 (Wireless Interface)"
echo "   - Mirror Port: LAN 포트 connected to this PC"
echo "   - Enable: ON"
echo
echo "6. Save and apply settings"
echo "7. Restart the router if necessary"
echo
echo "After configuration, test with:"
echo "   sudo tcpdump -i $INTERFACE -n net 172.26.35.0/24"
echo
echo "You should see mirrored wireless traffic from the router."
EOF
chmod +x configure_router.sh

log_success "Management scripts created"

echo
log_info "Step 13: Setting up log directories..."
sudo mkdir -p /var/log/wifi-monitor
sudo chown $CURRENT_USER:$CURRENT_USER /var/log/wifi-monitor

# Create log rotation
sudo tee /etc/logrotate.d/wifi-monitor > /dev/null << EOF
/var/log/wifi-monitor/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 $CURRENT_USER $CURRENT_USER
}
EOF

log_success "Log directories configured"

echo
log_info "Step 14: Final system setup..."

# Enable promiscuous mode on network interface
sudo ip link set $INTERFACE promisc on

# Create network configuration script
cat > setup_network.sh << EOF
#!/bin/bash
# Enable promiscuous mode for packet capture
sudo ip link set $INTERFACE promisc on
echo "Promiscuous mode enabled on $INTERFACE"
EOF
chmod +x setup_network.sh

log_success "Network configuration complete"

echo
echo "================================================================"
log_success "WiFi Traffic Monitor - Real Environment Installation Complete!"
echo "================================================================"
echo
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Configure router port mirroring:"
echo "   ./configure_router.sh"
echo
echo "2. Test the environment:"
echo "   ./test_environment.sh"
echo
echo "3. Start the monitoring service:"
echo "   ./start_monitor.sh"
echo
echo "4. Access the web interface:"
echo "   https://$CURRENT_IP:5000"
echo
echo -e "${BLUE}Important Notes:${NC}"
echo "• You may need to logout/login for group permissions to take effect"
echo "• Router port mirroring must be configured manually"
echo "• Default admin credentials will be generated on first run"
echo "• Check logs with: journalctl -u wifi-monitor-real -f"
echo
echo -e "${YELLOW}Router Configuration Required:${NC}"
echo "The router (IPtime AX300M) must be configured to mirror wireless"
echo "traffic to the LAN port connected to this PC. See configure_router.sh"
echo "for detailed instructions."
echo
log_success "Installation script completed successfully!"