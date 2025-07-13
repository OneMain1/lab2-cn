# WiFi Traffic Monitoring System - Setup Guide

## Overview

This system captures and monitors all WiFi traffic on a miniPC server, storing packet data in MongoDB and providing a secure HTTPS web interface for monitoring. The system implements port forwarding, packet capture, and includes RSA public/private key authentication with expiration mechanisms.

## System Architecture

### Components
- **Packet Capture Module** (`src/packet_capture.py`): Captures WiFi traffic using Scapy
- **Web Interface** (`src/web_app.py`): Flask-based HTTPS dashboard
- **Key Management** (`src/key_manager.py`): RSA key management and JWT authentication
- **Port Forwarding** (`scripts/configure_port_forwarding.sh`): iptables configuration
- **Database**: MongoDB for traffic storage

### Data Flow
1. WiFi clients connect to the miniPC's hotspot
2. iptables redirects traffic for inspection
3. Packet capture module extracts metadata
4. Data is stored in MongoDB with fields: src_ip, dest_ip, src_port, dest_port, timestamp, packet_length, protocol, URL
5. Web interface displays real-time monitoring dashboard

## Prerequisites

- Ubuntu/Debian Linux system
- Root access
- WiFi adapter capable of AP mode
- Internet connection for initial setup

## Installation

### 1. Quick Setup
```bash
# Clone/copy project files to the system
sudo cp -r /path/to/lab2 /tmp/lab2

# Run the automated setup script
cd /tmp/lab2
sudo ./scripts/setup.sh
```

### 2. Manual Setup Steps

#### System Dependencies
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip mongodb nginx hostapd dnsmasq iptables-persistent tcpdump
```

#### Python Environment
```bash
cd /opt/wifi-monitor
python3 -m venv venv
source venv/bin/activate
pip install flask pymongo scapy cryptography PyJWT gunicorn python-dotenv requests
```

#### Network Configuration
```bash
# Configure port forwarding
sudo ./scripts/configure_port_forwarding.sh wlan0

# This script will:
# - Set up iptables rules for traffic redirection
# - Configure hostapd for WiFi AP mode
# - Set up dnsmasq for DHCP
# - Enable IP forwarding
# - Create management scripts
```

## Configuration

### Network Settings (config/config.json)

```json
{
  "capture": {
    "interface": "wlan0",
    "protocols": ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
  },
  "security": {
    "rsa_key_size": 2048,
    "jwt_expiry_hours": 24,
    "password_min_length": 8
  },
  "web": {
    "host": "0.0.0.0",
    "port": 5000,
    "ssl_context": "adhoc"
  }
}
```

### WiFi Hotspot Settings

The system creates a WiFi hotspot with these default settings:
- **SSID**: WiFi-Monitor-Lab
- **Password**: MonitorLab2024
- **IP Range**: 192.168.100.10-100
- **Gateway**: 192.168.100.1

## Starting the System

### Option 1: Using Management Scripts
```bash
# Start all services
sudo wifi-monitor-start.sh

# Check status
sudo wifi-monitor-status.sh

# Stop services
sudo wifi-monitor-stop.sh
```

### Option 2: Using Systemd Services
```bash
# Start individual services
sudo systemctl start wifi-monitor-capture
sudo systemctl start wifi-monitor-web
sudo systemctl start hostapd
sudo systemctl start dnsmasq

# Enable auto-start on boot
sudo systemctl enable wifi-monitor-capture wifi-monitor-web hostapd dnsmasq
```

### Option 3: Manual Start
```bash
cd /opt/wifi-monitor
source venv/bin/activate
python src/packet_capture.py -i wlan0 &
python src/web_app.py
```

## Accessing the Web Interface

1. **URL**: https://YOUR_SERVER_IP (default port 443)
2. **Default Credentials**:
   - Username: `admin`
   - Password: Check `/opt/wifi-monitor/keys/admin_credentials.txt`

### Interface Features
- **Dashboard**: Real-time traffic statistics and recent packets
- **Traffic Monitor**: Detailed packet analysis with filtering
- **Admin Panel**: User management and system configuration

## Database Schema

### Packets Collection
```javascript
{
  "_id": ObjectId,
  "timestamp": "2024-01-01T12:00:00.000Z",
  "src_ip": "192.168.100.10",
  "dest_ip": "8.8.8.8", 
  "src_port": 12345,
  "dest_port": 80,
  "protocol": "TCP",
  "packet_length": 1024,
  "url": "http://example.com/path",
  "dns_query": "example.com",
  "packet_id": "abcd1234efgh5678"
}
```

## Security Features

### RSA Key Management
- 2048-bit RSA keys for encryption
- Automatic key generation on first setup
- Public/private key separation

### Authentication System
- JWT token-based authentication
- User role management (admin/user)
- Configurable token expiration (default 24 hours)
- Account expiration mechanism

### User Management
```bash
# Create new user
python src/key_manager.py create-user --username newuser --password mypass --role user --expires-days 30

# List users
python src/key_manager.py list-users

# Generate new keys
python src/key_manager.py generate
```

## Port Forwarding Details

### iptables Rules
The system configures these key rules:

```bash
# Redirect HTTP traffic for inspection
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirect HTTPS traffic for inspection  
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8443

# Enable NAT for internet access
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Log DNS queries
iptables -A FORWARD -i wlan0 -p udp --dport 53 -j LOG --log-prefix "DNS_QUERY: "
```

### Traffic Flow
1. Client connects to WiFi hotspot (192.168.100.x)
2. Traffic is forwarded through miniPC (192.168.100.1)
3. iptables redirects specific ports for inspection
4. Packet capture extracts metadata before forwarding
5. Original traffic continues to internet via NAT

## Monitoring and Maintenance

### Log Files
- Application logs: `/var/log/wifi-monitor/app.log`
- System logs: `journalctl -u wifi-monitor-capture`
- Nginx logs: `/var/log/nginx/access.log`

### Database Maintenance
```bash
# Check MongoDB status
mongo --eval "db.stats()"

# Clean old data (30+ days)
mongo traffic_monitor --eval "
db.packets.deleteMany({
  timestamp: {
    \$lt: new Date(new Date().getTime() - 30*24*60*60*1000).toISOString()
  }
})
"

# Create indexes for performance
mongo traffic_monitor --eval "
db.packets.createIndex({timestamp: -1});
db.packets.createIndex({src_ip: 1, dest_ip: 1});
"
```

### Backup System
```bash
# Manual backup
sudo /opt/wifi-monitor/backup.sh

# Automated backups (runs daily at 2 AM)
# Already configured in crontab during setup
```

## Troubleshooting

### Common Issues

#### WiFi Hotspot Not Starting
```bash
# Check interface status
ip link show wlan0

# Restart hostapd
sudo systemctl restart hostapd

# Check hostapd logs
journalctl -u hostapd -f
```

#### Packet Capture Not Working
```bash
# Check interface mode
iw wlan0 info

# Verify permissions
sudo usermod -a -G wireshark wifi-monitor

# Check process
ps aux | grep packet_capture
```

#### Web Interface Not Accessible
```bash
# Check nginx status
sudo systemctl status nginx

# Check Flask application
journalctl -u wifi-monitor-web -f

# Verify firewall
sudo ufw status
```

### Performance Optimization

#### High Traffic Environments
```bash
# Increase network buffers
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p

# Optimize MongoDB
mongo traffic_monitor --eval "db.packets.reIndex()"
```

## Security Considerations

### Production Deployment
1. **Change Default Passwords**: Update admin password immediately
2. **SSL Certificates**: Replace self-signed certificates with proper ones
3. **Firewall Rules**: Restrict access to management interfaces
4. **Regular Updates**: Keep system and dependencies updated
5. **Key Rotation**: Regularly generate new RSA keys

### Network Security
- Traffic inspection is performed at Layer 3/4 only
- No decryption of HTTPS content
- DNS queries logged for monitoring
- Port forwarding isolated to monitoring interface

## API Endpoints

### Authentication
- `POST /login` - User authentication
- `GET /logout` - Session termination

### Data Access
- `GET /api/stats` - Traffic statistics
- `GET /api/packets` - Filtered packet data
- `GET /api/realtime_stats` - Live dashboard updates

### Administration (Admin only)
- `POST /api/capture/start` - Start packet capture
- `POST /api/capture/stop` - Stop packet capture
- `POST /admin/create_user` - Create new user
- `POST /api/generate_keys` - Generate new RSA keys

## Support and Maintenance

### Health Monitoring
```bash
# Check system health
curl -k https://localhost/api/health

# Monitor resource usage
htop
df -h
free -h
```

### Updating the System
```bash
# Update application code
cd /opt/wifi-monitor
git pull  # if using git
sudo systemctl restart wifi-monitor-capture wifi-monitor-web

# Update system packages
sudo apt update && sudo apt upgrade
```

This system provides comprehensive WiFi traffic monitoring with secure access controls and is ready for deployment in your network environment.