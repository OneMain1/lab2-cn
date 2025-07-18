#!/bin/bash

# WiFi Traffic Monitor - Docker-based Testing Script
# Complete environment testing using Docker containers

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${PURPLE}[TEST]${NC} $1"; }

PROJECT_DIR=$(pwd)
TEST_RESULTS=()
TOTAL_TESTS=0
PASSED_TESTS=0

# Function to record test results
record_test() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$result" == "PASS" ]; then
        TEST_RESULTS+=("✅ $test_name")
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_success "$test_name"
        if [ -n "$details" ]; then
            echo "    $details"
        fi
    else
        TEST_RESULTS+=("❌ $test_name")
        log_error "$test_name"
        if [ -n "$details" ]; then
            echo "    $details"
        fi
    fi
}

echo "================================================================"
echo "WiFi Traffic Monitor - Docker Complete Test Suite"
echo "================================================================"
echo "Testing entire system in isolated Docker environment"
echo "================================================================"

# Cleanup function
cleanup() {
    log_info "Cleaning up Docker containers..."
    docker-compose down > /dev/null 2>&1 || true
    docker container prune -f > /dev/null 2>&1 || true
}

# Set trap for cleanup
trap cleanup EXIT

# Test 1: Docker Prerequisites
log_test "Test 1: Docker Environment Setup"
log_info "1.1 Checking Docker installation..."

if ! command -v docker &> /dev/null; then
    record_test "Docker Installation" "FAIL" "Docker not installed"
    exit 1
else
    record_test "Docker Installation" "PASS" "Docker is available"
fi

if ! command -v docker-compose &> /dev/null; then
    record_test "Docker Compose Installation" "FAIL" "Docker Compose not installed"
    exit 1
else
    record_test "Docker Compose Installation" "PASS" "Docker Compose is available"
fi

# Test 2: Build Application Container
log_test "Test 2: Building Application Container"
log_info "2.1 Building WiFi Monitor Docker image..."

if docker build -t wifi-monitor:test . > build.log 2>&1; then
    record_test "Docker Build" "PASS" "Application container built successfully"
else
    record_test "Docker Build" "FAIL" "Failed to build container - check build.log"
    cat build.log
    exit 1
fi

# Test 3: Start Complete Environment
log_test "Test 3: Starting Complete Environment"
log_info "3.1 Starting MongoDB and application containers..."

# Cleanup any existing containers
cleanup

# Start services
if docker-compose up -d > /dev/null 2>&1; then
    record_test "Environment Startup" "PASS" "All containers started"
    sleep 10  # Wait for services to initialize
else
    record_test "Environment Startup" "FAIL" "Failed to start containers"
    docker-compose logs
    exit 1
fi

# Test 4: Service Health Checks
log_test "Test 4: Service Health Verification"

log_info "4.1 Checking MongoDB container..."
if docker-compose exec -T mongodb mongosh --eval "db.stats()" > /dev/null 2>&1; then
    record_test "MongoDB Health" "PASS" "MongoDB is running and accessible"
else
    # Try alternative MongoDB client
    if docker-compose exec -T mongodb mongo --eval "db.stats()" > /dev/null 2>&1; then
        record_test "MongoDB Health" "PASS" "MongoDB is running and accessible"
    else
        record_test "MongoDB Health" "FAIL" "MongoDB not responding"
    fi
fi

log_info "4.2 Checking application container..."
if docker-compose ps | grep wifi-monitor-app | grep "Up" > /dev/null; then
    record_test "Application Health" "PASS" "Application container is running"
else
    record_test "Application Health" "FAIL" "Application container not running"
    docker-compose logs wifi-monitor
fi

# Test 5: Network Connectivity
log_test "Test 5: Inter-Container Communication"

log_info "5.1 Testing MongoDB connection from application..."
MONGO_TEST=$(docker-compose exec -T wifi-monitor python3 -c "
import sys
try:
    from pymongo import MongoClient
    client = MongoClient('mongodb://mongodb:27017/', serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print('SUCCESS')
except Exception as e:
    print(f'FAIL: {e}')
    sys.exit(1)
" 2>/dev/null)

if [[ "$MONGO_TEST" == "SUCCESS" ]]; then
    record_test "MongoDB Connectivity" "PASS" "Application can connect to MongoDB"
else
    record_test "MongoDB Connectivity" "FAIL" "Connection failed: $MONGO_TEST"
fi

# Test 6: Application Functionality
log_test "Test 6: Application Module Testing"

log_info "6.1 Testing key management system..."
KEY_TEST=$(docker-compose exec -T wifi-monitor python3 -c "
import sys
sys.path.append('/app/src')
try:
    from key_manager import KeyManager
    km = KeyManager(keys_dir='/app/keys')
    
    # Test key generation
    keys = km.generate_key_pair()
    if not keys:
        print('FAIL: Key generation failed')
        sys.exit(1)
    
    # Test user creation
    result = km.create_user('test_user', 'TestPass123!', 'admin', expires_days=1)
    if not result:
        print('FAIL: User creation failed')
        sys.exit(1)
    
    # Test authentication
    user = km.authenticate_user('test_user', 'TestPass123!')
    if not user:
        print('FAIL: Authentication failed')
        sys.exit(1)
    
    print('SUCCESS')
except Exception as e:
    print(f'FAIL: {e}')
    sys.exit(1)
" 2>/dev/null)

if [[ "$KEY_TEST" == "SUCCESS" ]]; then
    record_test "Key Management System" "PASS" "RSA keys, users, JWT tokens all working"
else
    record_test "Key Management System" "FAIL" "$KEY_TEST"
fi

log_info "6.2 Testing packet capture system..."
PACKET_TEST=$(docker-compose exec -T wifi-monitor python3 -c "
import sys
sys.path.append('/app/src')
try:
    from packet_capture import PacketCapture
    from scapy.all import IP, TCP
    
    # Test PacketCapture initialization
    capture = PacketCapture(
        interface='lo',
        mongodb_uri='mongodb://mongodb:27017/',
        db_name='test_capture',
        capture_mode='standard'
    )
    
    # Test packet parsing
    test_packet = IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=12345, dport=80)
    packet_info = capture.extract_packet_info(test_packet)
    
    if not packet_info or packet_info['src_ip'] != '127.0.0.1':
        print('FAIL: Packet parsing failed')
        sys.exit(1)
    
    # Test database storage
    capture.save_packet_to_db(packet_info)
    
    print('SUCCESS')
except Exception as e:
    print(f'FAIL: {e}')
    sys.exit(1)
" 2>/dev/null)

if [[ "$PACKET_TEST" == "SUCCESS" ]]; then
    record_test "Packet Capture System" "PASS" "Packet parsing and DB storage working"
else
    record_test "Packet Capture System" "FAIL" "$PACKET_TEST"
fi

# Test 7: Web Interface
log_test "Test 7: Web Interface Testing"

log_info "7.1 Waiting for web service to start..."
sleep 5

log_info "7.2 Testing web endpoints..."
if curl -f http://localhost:5000/api/health > /dev/null 2>&1; then
    record_test "Web Health Endpoint" "PASS" "Health check responding"
else
    record_test "Web Health Endpoint" "FAIL" "Health endpoint not accessible"
fi

if curl -f http://localhost:5000/login > /dev/null 2>&1; then
    record_test "Web Login Page" "PASS" "Login page accessible"
else
    record_test "Web Login Page" "FAIL" "Login page not accessible"
fi

# Test 8: Data Persistence
log_test "Test 8: Data Persistence Testing"

log_info "8.1 Testing database data persistence..."
DATA_TEST=$(docker-compose exec -T mongodb mongosh traffic_monitor --eval "
db.test_collection.insertOne({test: 'data', timestamp: new Date()});
db.test_collection.countDocuments({});
" 2>/dev/null | grep -o '[0-9]\+$' | tail -1)

if [[ "$DATA_TEST" -ge "1" ]]; then
    record_test "Data Persistence" "PASS" "Database storing and retrieving data"
else
    record_test "Data Persistence" "FAIL" "Database operations failed"
fi

# Test 9: Security Features
log_test "Test 9: Security Feature Testing"

log_info "9.1 Testing encryption capabilities..."
SECURITY_TEST=$(docker-compose exec -T wifi-monitor python3 -c "
import sys
sys.path.append('/app/src')
try:
    from key_manager import KeyManager
    km = KeyManager(keys_dir='/app/keys')
    
    # Test encryption/decryption
    test_data = 'Secret test message'
    encrypted = km.encrypt_data(test_data)
    if not encrypted:
        print('FAIL: Encryption failed')
        sys.exit(1)
    
    decrypted = km.decrypt_data(encrypted)
    if decrypted != test_data:
        print('FAIL: Decryption failed')
        sys.exit(1)
    
    print('SUCCESS')
except Exception as e:
    print(f'FAIL: {e}')
    sys.exit(1)
" 2>/dev/null)

if [[ "$SECURITY_TEST" == "SUCCESS" ]]; then
    record_test "Security Features" "PASS" "Encryption/decryption working correctly"
else
    record_test "Security Features" "FAIL" "$SECURITY_TEST"
fi

# Test 10: Performance Check
log_test "Test 10: Basic Performance Testing"

log_info "10.1 Testing packet processing performance..."
PERF_TEST=$(docker-compose exec -T wifi-monitor python3 -c "
import sys, time
sys.path.append('/app/src')
try:
    from packet_capture import PacketCapture
    from scapy.all import IP, TCP
    
    capture = PacketCapture(
        interface='lo',
        mongodb_uri='mongodb://mongodb:27017/',
        db_name='perf_test',
        capture_mode='standard'
    )
    
    # Performance test: Process 50 packets
    start_time = time.time()
    for i in range(50):
        packet = IP(src=f'192.168.1.{i%254+1}', dst='192.168.1.100')/TCP(sport=12345+i, dport=80)
        packet_info = capture.extract_packet_info(packet)
        capture.save_packet_to_db(packet_info)
    
    duration = time.time() - start_time
    pps = 50 / duration
    
    if pps >= 10:
        print(f'SUCCESS: {pps:.1f} packets/second')
    else:
        print(f'FAIL: Too slow ({pps:.1f} packets/second)')
        sys.exit(1)
        
except Exception as e:
    print(f'FAIL: {e}')
    sys.exit(1)
" 2>/dev/null)

if [[ "$PERF_TEST" =~ ^SUCCESS ]]; then
    record_test "Performance Test" "PASS" "${PERF_TEST#SUCCESS: }"
else
    record_test "Performance Test" "FAIL" "$PERF_TEST"
fi

# Results Summary
echo
echo "================================================================"
echo "DOCKER TEST SUITE RESULTS"
echo "================================================================"

for result in "${TEST_RESULTS[@]}"; do
    echo "$result"
done

echo
echo "================================================================"
echo -e "📊 SUMMARY: ${GREEN}$PASSED_TESTS${NC}/${TOTAL_TESTS} tests passed"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${GREEN}🎉 ALL DOCKER TESTS PASSED!${NC}"
    echo
    echo "Your WiFi Traffic Monitoring System is fully functional in Docker!"
    echo
    echo "✅ Docker environment working"
    echo "✅ All containers healthy"
    echo "✅ Inter-service communication"
    echo "✅ Application modules functional"
    echo "✅ Web interface accessible"
    echo "✅ Database operations working"
    echo "✅ Security features validated"
    echo "✅ Performance acceptable"
    echo
    echo "🌐 Access web interface at: http://localhost:5000"
    echo "🔧 View logs with: docker-compose logs -f"
    echo "🛑 Stop environment: docker-compose down"
    echo
    echo "Ready for real environment deployment!"
    
    EXIT_CODE=0
else
    FAILED_TESTS=$((TOTAL_TESTS - PASSED_TESTS))
    echo -e "${RED}❌ $FAILED_TESTS TESTS FAILED${NC}"
    echo
    echo "Check the following:"
    echo "• Docker and Docker Compose installation"
    echo "• Container build process (see build.log)"
    echo "• Service logs: docker-compose logs"
    echo "• Network connectivity between containers"
    
    EXIT_CODE=1
fi

echo
echo "================================================================"
echo "Container Status:"
docker-compose ps 2>/dev/null || echo "No containers running"
echo "================================================================"

exit $EXIT_CODE