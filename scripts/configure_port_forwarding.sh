#!/bin/bash
"""
WiFi Traffic Monitoring - Port Forwarding Configuration Script
Configures iptables rules for capturing and forwarding network traffic
"""

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration variables
INTERFACE="${1:-wlan0}"
MONITOR_PORT="${2:-8080}"
CAPTURE_USER="${3:-wifi-monitor}"

echo -e "${BLUE}WiFi Traffic Port Forwarding Setup${NC}"
echo "=================================="
echo "Interface: $INTERFACE"
echo "Monitor Port: $MONITOR_PORT"
echo "Capture User: $CAPTURE_USER"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check if interface exists
if ! ip link show $INTERFACE > /dev/null 2>&1; then
    echo -e "${RED}Interface $INTERFACE not found${NC}"
    echo "Available interfaces:"
    ip link show
    exit 1
fi

# Function to backup current iptables rules
backup_iptables() {
    echo -e "${YELLOW}Backing up current iptables rules...${NC}"
    iptables-save > /etc/iptables/rules.backup.$(date +%Y%m%d_%H%M%S)
    echo -e "${GREEN}Backup saved${NC}"
}

# Function to configure iptables for traffic capture
configure_iptables() {
    echo -e "${YELLOW}Configuring iptables rules for traffic capture...${NC}"
    
    # Flush existing rules (be careful!)
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X
    iptables -t nat -X
    iptables -t mangle -X
    
    # Set default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH (important for remote access)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow web interface access
    iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # PREROUTING rules for capturing traffic
    # Redirect HTTP traffic for inspection
    iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port $MONITOR_PORT
    
    # Redirect HTTPS traffic for inspection
    iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 8443
    
    # Log DNS queries
    iptables -A FORWARD -i $INTERFACE -p udp --dport 53 -j LOG --log-prefix "DNS_QUERY: "
    iptables -A FORWARD -i $INTERFACE -p tcp --dport 53 -j LOG --log-prefix "DNS_QUERY: "
    
    # Forward all traffic through the interface
    iptables -A FORWARD -i $INTERFACE -j ACCEPT
    iptables -A FORWARD -o $INTERFACE -j ACCEPT
    
    # Enable NAT for internet access
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -t nat -A POSTROUTING -o wlan1 -j MASQUERADE  # fallback interface
    
    # Allow DHCP traffic
    iptables -A INPUT -i $INTERFACE -p udp --dport 67 -j ACCEPT
    iptables -A INPUT -i $INTERFACE -p udp --dport 68 -j ACCEPT
    
    # Mirror traffic to capture interface
    iptables -t mangle -A PREROUTING -i $INTERFACE -j TEE --gateway 127.0.0.1
    
    echo -e "${GREEN}iptables rules configured${NC}"
}

# Function to setup bridge interface
setup_bridge() {
    echo -e "${YELLOW}Setting up bridge interface...${NC}"
    
    # Install bridge utilities if not present
    if ! command -v brctl &> /dev/null; then
        apt-get update
        apt-get install -y bridge-utils
    fi
    
    # Create bridge interface
    brctl addbr br0
    brctl addif br0 $INTERFACE
    
    # Configure bridge
    ip link set dev br0 up
    ip addr add 192.168.100.1/24 dev br0
    
    echo -e "${GREEN}Bridge interface configured${NC}"
}

# Function to configure hostapd for AP mode
configure_hostapd() {
    echo -e "${YELLOW}Configuring hostapd for access point mode...${NC}"
    
    # Install hostapd if not present
    if ! command -v hostapd &> /dev/null; then
        apt-get update
        apt-get install -y hostapd
    fi
    
    # Create hostapd configuration
    cat > /etc/hostapd/hostapd.conf << EOF
# Interface configuration
interface=$INTERFACE
driver=nl80211

# Network configuration
ssid=WiFi-Monitor-Lab
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

# Security configuration
wpa=2
wpa_passphrase=MonitorLab2024
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
    
    # Enable hostapd service
    systemctl unmask hostapd
    systemctl enable hostapd
    
    echo -e "${GREEN}hostapd configured${NC}"
}

# Function to configure dnsmasq for DHCP
configure_dnsmasq() {
    echo -e "${YELLOW}Configuring dnsmasq for DHCP...${NC}"
    
    # Install dnsmasq if not present
    if ! command -v dnsmasq &> /dev/null; then
        apt-get update
        apt-get install -y dnsmasq
    fi
    
    # Backup original configuration
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
    
    # Create new dnsmasq configuration
    cat > /etc/dnsmasq.conf << EOF
# Interface configuration
interface=$INTERFACE
bind-interfaces

# DHCP configuration
dhcp-range=192.168.100.10,192.168.100.100,255.255.255.0,24h

# DNS configuration
server=8.8.8.8
server=8.8.4.4

# Logging
log-queries
log-dhcp

# Domain configuration
domain=monitor.lab
local=/monitor.lab/
EOF
    
    # Enable dnsmasq service
    systemctl enable dnsmasq
    
    echo -e "${GREEN}dnsmasq configured${NC}"
}

# Function to enable IP forwarding
enable_ip_forwarding() {
    echo -e "${YELLOW}Enabling IP forwarding...${NC}"
    
    # Enable IP forwarding temporarily
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Make IP forwarding permanent
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    # Apply sysctl settings
    sysctl -p
    
    echo -e "${GREEN}IP forwarding enabled${NC}"
}

# Function to setup traffic monitoring
setup_traffic_monitoring() {
    echo -e "${YELLOW}Setting up traffic monitoring...${NC}"
    
    # Create monitoring directory
    mkdir -p /var/log/wifi-monitor
    chown $CAPTURE_USER:$CAPTURE_USER /var/log/wifi-monitor
    
    # Create tcpdump capture script
    cat > /usr/local/bin/capture-traffic.sh << EOF
#!/bin/bash
INTERFACE="$INTERFACE"
LOG_DIR="/var/log/wifi-monitor"
DATE=\$(date +%Y%m%d_%H%M%S)

# Capture all traffic on the interface
tcpdump -i \$INTERFACE -w \$LOG_DIR/capture_\$DATE.pcap -s 0 &
TCPDUMP_PID=\$!

# Capture HTTP traffic separately
tcpdump -i \$INTERFACE -w \$LOG_DIR/http_\$DATE.pcap -s 0 port 80 &
HTTP_PID=\$!

# Capture HTTPS traffic separately
tcpdump -i \$INTERFACE -w \$LOG_DIR/https_\$DATE.pcap -s 0 port 443 &
HTTPS_PID=\$!

# Capture DNS traffic separately
tcpdump -i \$INTERFACE -w \$LOG_DIR/dns_\$DATE.pcap -s 0 port 53 &
DNS_PID=\$!

echo "Traffic capture started:"
echo "Main capture PID: \$TCPDUMP_PID"
echo "HTTP capture PID: \$HTTP_PID"
echo "HTTPS capture PID: \$HTTPS_PID"
echo "DNS capture PID: \$DNS_PID"

# Create PID file
echo \$TCPDUMP_PID > \$LOG_DIR/capture.pid
echo \$HTTP_PID >> \$LOG_DIR/capture.pid
echo \$HTTPS_PID >> \$LOG_DIR/capture.pid
echo \$DNS_PID >> \$LOG_DIR/capture.pid

wait
EOF
    
    chmod +x /usr/local/bin/capture-traffic.sh
    
    # Create systemd service for traffic capture
    cat > /etc/systemd/system/traffic-capture.service << EOF
[Unit]
Description=Traffic Capture Service
After=network.target

[Service]
Type=forking
User=$CAPTURE_USER
Group=$CAPTURE_USER
ExecStart=/usr/local/bin/capture-traffic.sh
ExecStop=/bin/kill -TERM \$MAINPID
PIDFile=/var/log/wifi-monitor/capture.pid
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable traffic-capture
    
    echo -e "${GREEN}Traffic monitoring configured${NC}"
}

# Function to save iptables rules permanently
save_iptables() {
    echo -e "${YELLOW}Saving iptables rules...${NC}"
    
    # Install iptables-persistent if not present
    if ! dpkg -l | grep -q iptables-persistent; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
    fi
    
    # Save current rules
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    
    echo -e "${GREEN}iptables rules saved${NC}"
}

# Function to create management scripts
create_management_scripts() {
    echo -e "${YELLOW}Creating management scripts...${NC}"
    
    # Create start script
    cat > /usr/local/bin/wifi-monitor-start.sh << EOF
#!/bin/bash
echo "Starting WiFi Traffic Monitor..."

# Start hostapd
systemctl start hostapd

# Start dnsmasq
systemctl start dnsmasq

# Start traffic capture
systemctl start traffic-capture

# Show status
systemctl status hostapd dnsmasq traffic-capture

echo "WiFi Traffic Monitor started"
echo "SSID: WiFi-Monitor-Lab"
echo "Password: MonitorLab2024"
echo "Gateway: 192.168.100.1"
EOF
    
    # Create stop script
    cat > /usr/local/bin/wifi-monitor-stop.sh << EOF
#!/bin/bash
echo "Stopping WiFi Traffic Monitor..."

# Stop services
systemctl stop traffic-capture
systemctl stop dnsmasq
systemctl stop hostapd

# Kill any remaining processes
pkill -f tcpdump
pkill -f hostapd
pkill -f dnsmasq

echo "WiFi Traffic Monitor stopped"
EOF
    
    # Create status script
    cat > /usr/local/bin/wifi-monitor-status.sh << EOF
#!/bin/bash
echo "=== WiFi Traffic Monitor Status ==="
echo ""

echo "Services:"
systemctl status hostapd --no-pager -l
echo ""
systemctl status dnsmasq --no-pager -l
echo ""
systemctl status traffic-capture --no-pager -l
echo ""

echo "Network Interface:"
ip addr show $INTERFACE
echo ""

echo "Active Connections:"
iw dev $INTERFACE station dump 2>/dev/null || echo "No stations connected"
echo ""

echo "iptables Rules:"
iptables -t nat -L -n
echo ""

echo "Capture Files:"
ls -la /var/log/wifi-monitor/
EOF
    
    # Make scripts executable
    chmod +x /usr/local/bin/wifi-monitor-*.sh
    
    echo -e "${GREEN}Management scripts created${NC}"
}

# Function to test configuration
test_configuration() {
    echo -e "${YELLOW}Testing configuration...${NC}"
    
    # Test interface
    if ip link show $INTERFACE | grep -q "UP"; then
        echo -e "${GREEN}✓ Interface $INTERFACE is UP${NC}"
    else
        echo -e "${RED}✗ Interface $INTERFACE is DOWN${NC}"
    fi
    
    # Test IP forwarding
    if cat /proc/sys/net/ipv4/ip_forward | grep -q "1"; then
        echo -e "${GREEN}✓ IP forwarding is enabled${NC}"
    else
        echo -e "${RED}✗ IP forwarding is disabled${NC}"
    fi
    
    # Test iptables rules
    if iptables -t nat -L | grep -q "REDIRECT"; then
        echo -e "${GREEN}✓ iptables redirect rules are active${NC}"
    else
        echo -e "${RED}✗ iptables redirect rules not found${NC}"
    fi
    
    # Test services
    services=("hostapd" "dnsmasq")
    for service in "${services[@]}"; do
        if systemctl is-enabled $service &>/dev/null; then
            echo -e "${GREEN}✓ $service is enabled${NC}"
        else
            echo -e "${YELLOW}! $service is not enabled${NC}"
        fi
    done
    
    echo -e "${GREEN}Configuration test completed${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}Starting port forwarding configuration...${NC}"
    
    # Backup current configuration
    backup_iptables
    
    # Configure components
    enable_ip_forwarding
    configure_iptables
    configure_hostapd
    configure_dnsmasq
    setup_traffic_monitoring
    save_iptables
    create_management_scripts
    
    # Test configuration
    test_configuration
    
    echo ""
    echo -e "${GREEN}Port forwarding configuration completed!${NC}"
    echo "======================================"
    echo -e "${BLUE}Usage:${NC}"
    echo "Start monitoring: wifi-monitor-start.sh"
    echo "Stop monitoring:  wifi-monitor-stop.sh"
    echo "Check status:     wifi-monitor-status.sh"
    echo ""
    echo -e "${BLUE}WiFi Network:${NC}"
    echo "SSID: WiFi-Monitor-Lab"
    echo "Password: MonitorLab2024"
    echo "Gateway: 192.168.100.1"
    echo ""
    echo -e "${YELLOW}Note: Reboot the system to ensure all changes take effect${NC}"
}

# Run main function
main "$@"
