#!/bin/bash
"""
WiFi Traffic Monitoring System - Setup Script
This script sets up the complete WiFi traffic monitoring system
"""

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="/opt/wifi-monitor"
SERVICE_USER="wifi-monitor"
MONGODB_URI="mongodb://localhost:27017/"
DB_NAME="traffic_monitor"
INTERFACE="wlan0"

echo -e "${BLUE}WiFi Traffic Monitoring System Setup${NC}"
echo "===================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Update system packages
echo -e "${YELLOW}Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required system packages
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    mongodb \
    nginx \
    ufw \
    tcpdump \
    wireshark-common \
    hostapd \
    dnsmasq \
    iptables-persistent \
    git \
    curl \
    wget \
    supervisor \
    ssl-cert

# Create project directory
echo -e "${YELLOW}Creating project directory...${NC}"
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# Create service user
echo -e "${YELLOW}Creating service user...${NC}"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false -d $PROJECT_DIR $SERVICE_USER
fi

# Copy project files (assuming we're in the project directory)
echo -e "${YELLOW}Setting up project files...${NC}"
if [ -d "/tmp/lab2" ]; then
    cp -r /tmp/lab2/* $PROJECT_DIR/
else
    echo -e "${RED}Project files not found in /tmp/lab2${NC}"
    echo "Please copy your project files to /tmp/lab2 before running this script"
    exit 1
fi

# Create Python virtual environment
echo -e "${YELLOW}Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
cat > requirements.txt << EOF
flask==2.3.3
pymongo==4.5.0
scapy==2.5.0
cryptography==41.0.4
PyJWT==2.8.0
gunicorn==21.2.0
python-dotenv==1.0.0
requests==2.31.0
celery==5.3.1
redis==4.6.0
EOF

pip install -r requirements.txt

# Setup MongoDB
echo -e "${YELLOW}Configuring MongoDB...${NC}"
systemctl enable mongodb
systemctl start mongodb

# Create MongoDB user and database
mongo --eval "
use $DB_NAME;
db.createUser({
    user: 'wifi_monitor',
    pwd: '$(openssl rand -base64 32)',
    roles: [{role: 'readWrite', db: '$DB_NAME'}]
});
"

# Setup network interface for monitoring
echo -e "${YELLOW}Configuring network interface...${NC}"
# Enable monitor mode for the interface
if ip link show $INTERFACE > /dev/null 2>&1; then
    ip link set $INTERFACE down
    iw $INTERFACE set monitor control
    ip link set $INTERFACE up
    echo -e "${GREEN}Interface $INTERFACE configured for monitoring${NC}"
else
    echo -e "${YELLOW}Warning: Interface $INTERFACE not found${NC}"
fi

# Configure iptables for port forwarding
echo -e "${YELLOW}Configuring iptables...${NC}"
cat > /etc/iptables/rules.v4 << EOF
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
# Port forwarding rules
-A PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 8080
-A PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 8443
COMMIT

*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow loopback
-A INPUT -i lo -j ACCEPT
# Allow SSH (be careful!)
-A INPUT -p tcp --dport 22 -j ACCEPT
# Allow web interface
-A INPUT -p tcp --dport 5000 -j ACCEPT
# Allow MongoDB (local only)
-A INPUT -s 127.0.0.1 -p tcp --dport 27017 -j ACCEPT
# Drop other incoming
-A INPUT -j DROP
COMMIT
EOF

iptables-restore < /etc/iptables/rules.v4

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Create systemd service for packet capture
echo -e "${YELLOW}Creating systemd services...${NC}"
cat > /etc/systemd/system/wifi-monitor-capture.service << EOF
[Unit]
Description=WiFi Traffic Monitor - Packet Capture
After=network.target mongodb.service
Requires=mongodb.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/venv/bin
Environment=MONGODB_URI=$MONGODB_URI
Environment=DB_NAME=$DB_NAME
Environment=INTERFACE=$INTERFACE
ExecStart=$PROJECT_DIR/venv/bin/python src/packet_capture.py -i $INTERFACE
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for web interface
cat > /etc/systemd/system/wifi-monitor-web.service << EOF
[Unit]
Description=WiFi Traffic Monitor - Web Interface
After=network.target mongodb.service
Requires=mongodb.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/venv/bin
Environment=MONGODB_URI=$MONGODB_URI
Environment=DB_NAME=$DB_NAME
Environment=INTERFACE=$INTERFACE
Environment=SECRET_KEY=$(openssl rand -base64 32)
ExecStart=$PROJECT_DIR/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 4 src.web_app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx as reverse proxy with SSL
echo -e "${YELLOW}Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/wifi-monitor << EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static {
        alias $PROJECT_DIR/web/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Enable nginx site
ln -sf /etc/nginx/sites-available/wifi-monitor /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
nginx -t

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chown -R $SERVICE_USER:$SERVICE_USER $PROJECT_DIR
chmod -R 755 $PROJECT_DIR
chmod 600 $PROJECT_DIR/keys/* 2>/dev/null || true

# Add service user to necessary groups
usermod -a -G netdev $SERVICE_USER
usermod -a -G wireshark $SERVICE_USER

# Enable and start services
echo -e "${YELLOW}Starting services...${NC}"
systemctl daemon-reload
systemctl enable mongodb nginx wifi-monitor-capture wifi-monitor-web
systemctl start mongodb
systemctl start nginx
systemctl start wifi-monitor-capture
systemctl start wifi-monitor-web

# Configure firewall
echo -e "${YELLOW}Configuring firewall...${NC}"
ufw --force enable
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from 127.0.0.1 to any port 27017

# Generate initial admin credentials
echo -e "${YELLOW}Generating initial admin credentials...${NC}"
cd $PROJECT_DIR
sudo -u $SERVICE_USER $PROJECT_DIR/venv/bin/python src/key_manager.py generate
admin_password=$(sudo -u $SERVICE_USER $PROJECT_DIR/venv/bin/python -c "
import secrets
print(secrets.token_urlsafe(16))
")

sudo -u $SERVICE_USER $PROJECT_DIR/venv/bin/python src/key_manager.py create-user \
    --username admin \
    --password $admin_password \
    --role admin \
    --expires-days 365

# Create startup script
cat > $PROJECT_DIR/start.sh << EOF
#!/bin/bash
cd $PROJECT_DIR
source venv/bin/activate
python src/packet_capture.py -i $INTERFACE &
python src/web_app.py
EOF

chmod +x $PROJECT_DIR/start.sh

# Create status check script
cat > $PROJECT_DIR/status.sh << EOF
#!/bin/bash
echo "=== WiFi Traffic Monitor Status ==="
echo "Services:"
systemctl status wifi-monitor-capture --no-pager -l
systemctl status wifi-monitor-web --no-pager -l
systemctl status nginx --no-pager -l
systemctl status mongodb --no-pager -l

echo -e "\nNetwork Interface:"
ip link show $INTERFACE

echo -e "\nFirewall Status:"
ufw status

echo -e "\nActive Connections:"
netstat -tlnp | grep -E ":(5000|80|443|27017)"
EOF

chmod +x $PROJECT_DIR/status.sh

# Create backup script
cat > $PROJECT_DIR/backup.sh << EOF
#!/bin/bash
BACKUP_DIR="/var/backups/wifi-monitor"
DATE=\$(date +%Y%m%d_%H%M%S)

mkdir -p \$BACKUP_DIR

# Backup MongoDB
mongodump --db $DB_NAME --out \$BACKUP_DIR/mongodb_\$DATE

# Backup configuration
tar -czf \$BACKUP_DIR/config_\$DATE.tar.gz $PROJECT_DIR/keys $PROJECT_DIR/config

# Keep only last 7 days of backups
find \$BACKUP_DIR -name "mongodb_*" -mtime +7 -exec rm -rf {} \;
find \$BACKUP_DIR -name "config_*.tar.gz" -mtime +7 -delete

echo "Backup completed: \$BACKUP_DIR"
EOF

chmod +x $PROJECT_DIR/backup.sh

# Add backup to crontab
(crontab -l 2>/dev/null; echo "0 2 * * * $PROJECT_DIR/backup.sh") | crontab -

echo -e "${GREEN}Setup completed successfully!${NC}"
echo "======================================"
echo -e "${BLUE}System Information:${NC}"
echo "Project Directory: $PROJECT_DIR"
echo "Service User: $SERVICE_USER"
echo "MongoDB Database: $DB_NAME"
echo "Network Interface: $INTERFACE"
echo ""
echo -e "${BLUE}Access Information:${NC}"
echo "Web Interface: https://$(hostname -I | awk '{print $1}')"
echo "Admin Username: admin"
echo "Admin Password: $admin_password"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "Check Status: $PROJECT_DIR/status.sh"
echo "Create Backup: $PROJECT_DIR/backup.sh"
echo "View Logs: journalctl -u wifi-monitor-capture -f"
echo "           journalctl -u wifi-monitor-web -f"
echo ""
echo -e "${YELLOW}Important Notes:${NC}"
echo "1. Change the default admin password after first login"
echo "2. Configure your WiFi interface ($INTERFACE) for monitoring"
echo "3. Review firewall rules for your environment"
echo "4. Consider setting up SSL certificates for production use"
echo ""
echo -e "${GREEN}Installation completed! The system is now running.${NC}"
