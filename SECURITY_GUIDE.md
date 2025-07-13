# Security Guide - WiFi Traffic Monitoring System

## Overview

This document provides comprehensive security information for the WiFi traffic monitoring system, including key management, authentication mechanisms, access controls, and security best practices.

## Security Architecture

### Multi-Layer Security Model

1. **Network Layer**: iptables firewall rules and network isolation
2. **Application Layer**: RSA encryption and JWT authentication
3. **Data Layer**: MongoDB access controls and data encryption
4. **Transport Layer**: HTTPS/TLS encryption for web interface

## RSA Key Management System

### Key Generation and Storage

#### Automatic Key Generation
The system automatically generates 2048-bit RSA key pairs on first startup:

```bash
# Keys are stored in:
/opt/wifi-monitor/keys/
├── private_key.pem    # RSA private key (600 permissions)
├── public_key.pem     # RSA public key (644 permissions)
├── users.json         # User database
└── admin_credentials.txt  # Initial admin credentials
```

#### Manual Key Generation
```bash
# Generate new keys manually
cd /opt/wifi-monitor
python src/key_manager.py generate

# This will:
# 1. Generate new 2048-bit RSA key pair
# 2. Save keys with proper permissions
# 3. Invalidate all existing JWT tokens
```

### Key Rotation Policy

#### Recommended Schedule
- **RSA Keys**: Rotate every 6-12 months
- **JWT Secret**: Rotate every 30 days
- **User Passwords**: Force change every 90 days

#### Key Rotation Process
```bash
# 1. Generate new keys
python src/key_manager.py generate

# 2. Restart services to use new keys
sudo systemctl restart wifi-monitor-web

# 3. All users must re-authenticate
# 4. Update any automated systems using the API
```

## User Authentication and Authorization

### User Management

#### User Roles
- **admin**: Full system access, user management, configuration
- **user**: Read-only access to traffic data and statistics

#### Creating Users
```bash
# Create admin user
python src/key_manager.py create-user \
    --username admin_user \
    --password SecurePass123! \
    --role admin \
    --expires-days 365

# Create regular user
python src/key_manager.py create-user \
    --username monitor_user \
    --password ViewOnly456! \
    --role user \
    --expires-days 90
```

#### User Expiration Management
```bash
# List all users with expiration dates
python src/key_manager.py list-users

# Update user expiration
python -c "
from src.key_manager import KeyManager
km = KeyManager()
km.update_user_expiry('username', 60)  # Extend for 60 days
"
```

### JWT Token Security

#### Token Configuration
```json
{
  "security": {
    "jwt_expiry_hours": 24,
    "max_login_attempts": 5,
    "lockout_duration_minutes": 30
  }
}
```

#### Token Lifecycle
1. **Generation**: Upon successful authentication
2. **Validation**: On each API request
3. **Expiration**: Automatic after configured time
4. **Revocation**: Manual or automatic (user deactivation)

#### Token Security Features
- **Payload Encryption**: Contains user info and permissions
- **Expiration Enforcement**: Automatic token invalidation
- **Revocation Support**: Immediate token cancellation
- **Active Session Tracking**: Monitor concurrent sessions

## Access Control Configuration

### Web Interface Security

#### HTTPS Configuration
```nginx
# Nginx SSL configuration (automatically set up)
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
}
```

#### Session Management
- Session data stored server-side only
- Secure cookie flags enabled
- Session timeout after inactivity
- CSRF protection implemented

### API Security

#### Endpoint Protection
```python
# All API endpoints require authentication
@app.route('/api/stats')
@login_required
def api_stats():
    # Only authenticated users can access

@app.route('/api/admin/create_user', methods=['POST'])
@admin_required  
def create_user():
    # Only admin users can access
```

#### Rate Limiting (Recommended)
```bash
# Add to nginx configuration
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

location /api/ {
    limit_req zone=api burst=20 nodelay;
    limit_req_status 429;
}
```

## Network Security

### Firewall Configuration

#### iptables Rules
```bash
# Allow only necessary ports
iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH
iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP (redirects to HTTPS)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT  # Flask app (local)

# Block MongoDB from external access
iptables -A INPUT -p tcp --dport 27017 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 27017 -j DROP

# Default deny policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
```

#### UFW Configuration (Alternative)
```bash
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 127.0.0.1 to any port 27017
```

### Network Isolation

#### WiFi Interface Isolation
The monitoring WiFi interface is isolated from the main network:
- Separate subnet (192.168.100.0/24)
- NAT-based internet access only
- No access to internal networks

#### Traffic Inspection Boundaries
- Layer 3/4 packet metadata only
- No deep packet inspection of encrypted content
- DNS query logging for monitoring
- URL extraction from HTTP headers only

## Data Security

### Database Security

#### MongoDB Access Control
```javascript
// Create dedicated database user
use traffic_monitor;
db.createUser({
  user: "wifi_monitor",
  pwd: "STRONG_RANDOM_PASSWORD",
  roles: [
    { role: "readWrite", db: "traffic_monitor" }
  ]
});
```

#### Data Encryption at Rest
```bash
# Enable MongoDB encryption (if required)
mongod --enableEncryption \
       --encryptionKeyFile /path/to/keyfile \
       --encryptionCipherMode AES256-CBC
```

### Data Privacy

#### Data Collection Policy
The system collects only necessary metadata:
- IP addresses (source/destination)
- Port numbers
- Protocol information
- Packet sizes
- Timestamps
- HTTP URLs (headers only)
- DNS queries

#### Data Retention
```bash
# Automatic cleanup of old data (30 days default)
mongo traffic_monitor --eval "
db.packets.deleteMany({
  timestamp: {
    \$lt: new Date(new Date().getTime() - 30*24*60*60*1000).toISOString()
  }
})
"
```

## Security Monitoring

### Audit Logging

#### Application Logs
```python
# Key events logged:
# - Authentication attempts (success/failure)
# - Administrative actions
# - Configuration changes
# - System errors
# - Unauthorized access attempts
```

#### System Log Monitoring
```bash
# Monitor authentication logs
tail -f /var/log/auth.log

# Monitor application logs
journalctl -u wifi-monitor-web -f

# Monitor nginx access logs
tail -f /var/log/nginx/access.log
```

### Intrusion Detection

#### Failed Login Monitoring
```bash
# Monitor failed login attempts
grep "Invalid username or password" /var/log/wifi-monitor/app.log

# Monitor authentication failures
grep "authentication failed" /var/log/auth.log
```

#### Automated Alerting (Recommended)
```bash
# Example logwatch configuration
# Add to /etc/logwatch/conf/services/wifi-monitor.conf
Title = "WiFi Monitor Security Events"
LogFile = /var/log/wifi-monitor/app.log
*ApplyStdDate*
*RemoveHeaders*
```

## Security Best Practices

### Initial Setup

#### 1. Change Default Credentials
```bash
# Change default admin password immediately after setup
# Access web interface and change password in admin panel
```

#### 2. Generate Strong Passwords
- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- Use password manager for generation/storage

#### 3. Secure File Permissions
```bash
# Verify key file permissions
ls -la /opt/wifi-monitor/keys/
# private_key.pem should be 600 (read/write owner only)
# users.json should be 600 (contains password hashes)
```

### Operational Security

#### 1. Regular Updates
```bash
# System updates
sudo apt update && sudo apt upgrade

# Python package updates
cd /opt/wifi-monitor
source venv/bin/activate
pip list --outdated
pip install --upgrade package_name
```

#### 2. Certificate Management
```bash
# Replace self-signed certificates with proper SSL certs
# For Let's Encrypt:
sudo certbot --nginx -d your-domain.com

# Update nginx configuration to use new certificates
```

#### 3. Backup Security
```bash
# Encrypt backups
tar -czf backup.tar.gz /opt/wifi-monitor/keys
gpg --symmetric --cipher-algo AES256 backup.tar.gz

# Store encrypted backups securely
```

### Incident Response

#### Security Incident Checklist

1. **Immediate Response**
   - Identify affected systems
   - Isolate compromised components
   - Preserve evidence (logs, memory dumps)

2. **Assessment**
   - Determine scope of compromise
   - Identify data potentially accessed
   - Check for persistence mechanisms

3. **Containment**
   - Revoke all active tokens
   - Generate new RSA keys
   - Reset all user passwords
   - Update firewall rules

4. **Recovery**
   - Restore from clean backups
   - Apply security patches
   - Update monitoring rules
   - Test system functionality

#### Emergency Commands
```bash
# Immediately revoke all user sessions
sudo systemctl stop wifi-monitor-web

# Generate new keys (invalidates all tokens)
python src/key_manager.py generate

# Block all external access
sudo ufw deny 80
sudo ufw deny 443

# Create incident response backup
sudo tar -czf /tmp/incident_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    /var/log/wifi-monitor/ \
    /opt/wifi-monitor/keys/ \
    /etc/nginx/sites-available/
```

## Compliance and Privacy

### Data Protection Compliance

#### GDPR Considerations
- Data minimization: Collect only necessary packet metadata
- Data retention: Automatic deletion after retention period
- Right to erasure: Capability to delete specific user data
- Data portability: Export functionality for user data

#### Privacy Protection Measures
- No content inspection of encrypted traffic
- Anonymization of IP addresses (optional)
- Clear data retention policies
- Access logging and audit trails

### Security Documentation

#### Required Documentation
1. **Security Policy**: Define security requirements and procedures
2. **Access Control Matrix**: Document user roles and permissions
3. **Incident Response Plan**: Step-by-step incident handling
4. **Risk Assessment**: Identify and mitigate security risks
5. **Change Management**: Process for security-relevant changes

This security guide provides comprehensive protection for your WiFi traffic monitoring system. Regular review and updates of these security measures are essential for maintaining system integrity.