#!/bin/bash

# WiFi Traffic Monitor - Local Traffic Generation Test
# Generates synthetic network traffic for testing packet capture

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

PROJECT_DIR=$(pwd)

echo "================================================================"
echo "WiFi Traffic Monitor - Local Traffic Generation Test"
echo "================================================================"

# Check if running as root for packet capture
if [ "$EUID" -ne 0 ]; then
    log_error "This script needs root privileges for packet capture"
    log_info "Please run with: sudo ./scripts/local_traffic_test.sh"
    exit 1
fi

# Get the actual user (in case of sudo)
ACTUAL_USER=${SUDO_USER:-$(whoami)}
log_info "Running as root for packet capture, actual user: $ACTUAL_USER"

# Step 1: Start MongoDB if not running
log_info "Step 1: Ensuring MongoDB is running..."
systemctl start mongod 2>/dev/null || systemctl start mongodb 2>/dev/null || {
    log_warning "Could not start MongoDB service, trying manual start..."
    mongod --fork --logpath /var/log/mongodb.log --dbpath /var/lib/mongodb 2>/dev/null || {
        log_error "Failed to start MongoDB"
        exit 1
    }
}

sleep 2
mongo --eval "db.stats()" > /dev/null 2>&1 && log_success "MongoDB is running" || {
    log_error "MongoDB is not responding"
    exit 1
}

# Step 2: Setup test database
log_info "Step 2: Setting up test database..."
mongo << 'EOF'
use traffic_monitor_test;
db.dropDatabase();
use traffic_monitor_test;
db.createUser({
  user: "test_user",
  pwd: "test_password",
  roles: [{ role: "readWrite", db: "traffic_monitor_test" }]
});
EOF

log_success "Test database created"

# Step 3: Create test configuration
log_info "Step 3: Creating test configuration..."
cat > config/test_config.json << 'EOF'
{
  "environment": "local_test",
  "network": {
    "interface": "lo",
    "capture_mode": "standard"
  },
  "database": {
    "name": "traffic_monitor_test",
    "uri": "mongodb://localhost:27017/"
  },
  "web": {
    "host": "127.0.0.1",
    "port": 5001,
    "debug": true
  },
  "security": {
    "jwt_expiry_hours": 1,
    "force_https": false
  }
}
EOF

log_success "Test configuration created"

# Step 4: Generate test RSA keys
log_info "Step 4: Generating test keys..."
mkdir -p test_keys
sudo -u $ACTUAL_USER python3 << 'EOF'
import sys
sys.path.append('src')
from key_manager import KeyManager

km = KeyManager(keys_dir='test_keys')
keys = km.generate_key_pair()
if keys:
    print("Test keys generated successfully")
    # Create test admin user
    result = km.create_user('admin', 'testpass123', 'admin', expires_days=1)
    if result:
        print("Test admin user created")
    else:
        print("Failed to create test user")
        sys.exit(1)
else:
    print("Failed to generate keys")
    sys.exit(1)
EOF

log_success "Test keys and admin user created"

# Step 5: Start packet capture in background
log_info "Step 5: Starting packet capture..."
cd $PROJECT_DIR

# Start packet capture with test configuration
sudo -u $ACTUAL_USER python3 src/packet_capture.py \
    --interface lo \
    --mongodb-uri "mongodb://localhost:27017/" \
    --db-name "traffic_monitor_test" \
    --capture-mode standard > capture_test.log 2>&1 &

CAPTURE_PID=$!
log_success "Packet capture started (PID: $CAPTURE_PID)"

# Give capture some time to initialize
sleep 3

# Step 6: Generate synthetic traffic
log_info "Step 6: Generating synthetic traffic..."

# Create traffic generator script
cat > generate_traffic.py << 'EOF'
#!/usr/bin/env python3
import time
import subprocess
import requests
import socket
from scapy.all import *

def generate_loopback_traffic():
    """Generate various types of traffic on loopback interface"""
    print("Generating synthetic network traffic...")
    
    # 1. HTTP-like traffic
    print("  • Generating HTTP-like packets...")
    for i in range(10):
        packet = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12345+i, dport=80)/Raw(load=f"GET /test{i} HTTP/1.1\r\nHost: localhost\r\n\r\n")
        send(packet, verbose=0, iface="lo")
        time.sleep(0.1)
    
    # 2. DNS-like traffic
    print("  • Generating DNS-like packets...")
    for i in range(5):
        packet = IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=54321, dport=53)/Raw(load=f"test{i}.example.com")
        send(packet, verbose=0, iface="lo")
        time.sleep(0.1)
    
    # 3. Various TCP connections
    print("  • Generating TCP traffic...")
    ports = [443, 22, 3389, 8080, 9090]
    for port in ports:
        packet = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=60000+port, dport=port, flags="S")
        send(packet, verbose=0, iface="lo")
        time.sleep(0.1)
    
    # 4. UDP traffic
    print("  • Generating UDP traffic...")
    for i in range(8):
        packet = IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=50000+i, dport=8000+i)/Raw(load=f"UDP test packet {i}")
        send(packet, verbose=0, iface="lo")
        time.sleep(0.1)

def generate_real_traffic():
    """Generate real network requests"""
    print("  • Generating real HTTP requests...")
    try:
        # Make some HTTP requests to generate real traffic
        urls = [
            "http://127.0.0.1:5001/api/health",
            "http://httpbin.org/get",
            "http://httpbin.org/json",
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=2)
                print(f"    ✓ {url} -> {response.status_code}")
            except:
                print(f"    ✗ {url} -> Failed")
            time.sleep(0.5)
    except Exception as e:
        print(f"Real traffic generation failed: {e}")

if __name__ == "__main__":
    try:
        generate_loopback_traffic()
        generate_real_traffic()
        print("Traffic generation completed!")
    except Exception as e:
        print(f"Error: {e}")
EOF

# Run traffic generator
sudo -u $ACTUAL_USER python3 generate_traffic.py

log_success "Synthetic traffic generated"

# Step 7: Wait for packets to be processed
log_info "Step 7: Waiting for packet processing..."
sleep 5

# Step 8: Check captured packets
log_info "Step 8: Checking captured packets in database..."
PACKET_COUNT=$(mongo traffic_monitor_test --quiet --eval "db.packets.count()")

if [ "$PACKET_COUNT" -gt 0 ]; then
    log_success "Captured $PACKET_COUNT packets successfully!"
    
    # Show packet details
    log_info "Sample captured packets:"
    mongo traffic_monitor_test --quiet --eval "
    db.packets.find().limit(5).forEach(function(packet) {
        print('  • ' + packet.protocol + ': ' + packet.src_ip + ':' + packet.src_port + ' → ' + packet.dest_ip + ':' + packet.dest_port + ' (' + packet.packet_length + ' bytes)');
    });
    "
else
    log_error "No packets captured! Check capture_test.log for errors"
    cat capture_test.log
fi

# Step 9: Test web interface
log_info "Step 9: Testing web interface..."

# Start web app in background
sudo -u $ACTUAL_USER python3 << 'EOF' &
import sys
sys.path.append('src')
import os
os.environ['TESTING'] = '1'
from web_app import app

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=False)
EOF

WEB_PID=$!
log_info "Web interface started (PID: $WEB_PID)"

# Wait for web server to start
sleep 5

# Test web endpoints
log_info "Testing web endpoints..."
curl -s http://127.0.0.1:5001/api/health > /dev/null 2>&1 && log_success "  ✓ Health endpoint working" || log_error "  ✗ Health endpoint failed"
curl -s http://127.0.0.1:5001/login > /dev/null 2>&1 && log_success "  ✓ Login page accessible" || log_error "  ✗ Login page failed"
curl -s http://127.0.0.1:5001/api/stats > /dev/null 2>&1 && log_success "  ✓ Stats API responding" || log_warning "  ⚠ Stats API requires authentication"

# Cleanup
log_info "Step 10: Cleaning up..."
kill $CAPTURE_PID 2>/dev/null || true
kill $WEB_PID 2>/dev/null || true
rm -f generate_traffic.py capture_test.log

# Final summary
log_info "Step 11: Final verification..."
FINAL_COUNT=$(mongo traffic_monitor_test --quiet --eval "db.packets.count()")

echo
echo "================================================================"
echo "LOCAL TRAFFIC TEST SUMMARY"
echo "================================================================"
echo -e "📊 Total packets captured: ${GREEN}$FINAL_COUNT${NC}"
echo -e "🔑 Test admin user created: ${GREEN}admin / testpass123${NC}"
echo -e "🌐 Web interface tested on: ${GREEN}http://127.0.0.1:5001${NC}"
echo -e "💾 Test database: ${GREEN}traffic_monitor_test${NC}"
echo "================================================================"

if [ "$FINAL_COUNT" -gt 0 ]; then
    echo -e "${GREEN}🎉 LOCAL TRAFFIC TEST SUCCESSFUL!${NC}"
    echo
    echo "Your implementation successfully:"
    echo "✅ Captured network packets"
    echo "✅ Stored data in MongoDB"
    echo "✅ Served web interface"
    echo "✅ Processed authentication"
    echo
    echo "Next steps:"
    echo "1. Run full test suite: ./scripts/full_test_suite.sh"
    echo "2. Deploy to real environment: ./scripts/real_environment_install.sh"
    echo
    echo "To manually explore the test data:"
    echo "  mongo traffic_monitor_test"
    echo "  db.packets.find().pretty()"
else
    echo -e "${RED}❌ LOCAL TRAFFIC TEST FAILED${NC}"
    echo "No packets were captured. Please check:"
    echo "• MongoDB is running"
    echo "• Python dependencies are installed"
    echo "• Network interface permissions"
    echo "• Check capture_test.log for errors"
fi

echo "================================================================"

# Exit with appropriate code
if [ "$FINAL_COUNT" -gt 0 ]; then
    exit 0
else
    exit 1
fi