#!/bin/bash

# WiFi Traffic Monitor - Full Test Suite
# Comprehensive testing of all system components

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
echo "WiFi Traffic Monitor - Full Test Suite"
echo "================================================================"
echo "This comprehensive test suite validates all system components"
echo "Expected duration: 10-15 minutes"
echo "================================================================"

# Test Suite 1: Environment and Dependencies
echo
log_test "Test Suite 1: Environment and Dependencies"
echo "----------------------------------------------------------------"

# Test 1.1: System Requirements
log_info "1.1 Checking system requirements..."
python3 --version > /dev/null 2>&1 && PYTHON_OK=1 || PYTHON_OK=0
which mongod > /dev/null 2>&1 && MONGO_OK=1 || MONGO_OK=0
which tcpdump > /dev/null 2>&1 && TCPDUMP_OK=1 || TCPDUMP_OK=0
which curl > /dev/null 2>&1 && CURL_OK=1 || CURL_OK=0

if [ $PYTHON_OK -eq 1 ] && [ $MONGO_OK -eq 1 ] && [ $TCPDUMP_OK -eq 1 ] && [ $CURL_OK -eq 1 ]; then
    record_test "System Requirements" "PASS" "Python3, MongoDB, tcpdump, curl available"
else
    missing=""
    [ $PYTHON_OK -eq 0 ] && missing="$missing Python3"
    [ $MONGO_OK -eq 0 ] && missing="$missing MongoDB"
    [ $TCPDUMP_OK -eq 0 ] && missing="$missing tcpdump"
    [ $CURL_OK -eq 0 ] && missing="$missing curl"
    record_test "System Requirements" "FAIL" "Missing:$missing"
fi

# Test 1.2: Python Dependencies
log_info "1.2 Checking Python dependencies..."
python3 << 'EOF'
import sys
required_modules = [
    'flask', 'pymongo', 'scapy', 'cryptography', 
    'jwt', 'werkzeug', 'bson', 'hashlib', 'threading'
]
missing = []
for module in required_modules:
    try:
        if module == 'jwt':
            import jwt as pyjwt  # PyJWT
        else:
            __import__(module)
    except ImportError:
        missing.append(module)

if missing:
    print(f"Missing modules: {', '.join(missing)}")
    sys.exit(1)
else:
    print("All required Python modules available")
EOF

if [ $? -eq 0 ]; then
    record_test "Python Dependencies" "PASS" "All required modules available"
else
    record_test "Python Dependencies" "FAIL" "Some modules missing - run: pip install -r requirements.txt"
fi

# Test 1.3: File Structure
log_info "1.3 Checking project file structure..."
REQUIRED_FILES=(
    "src/web_app.py"
    "src/packet_capture.py" 
    "src/key_manager.py"
    "requirements.txt"
    "config/config.json"
    "web/templates/base.html"
    "web/static/style.css"
)

missing_files=""
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        missing_files="$missing_files $file"
    fi
done

if [ -z "$missing_files" ]; then
    record_test "File Structure" "PASS" "All required files present"
else
    record_test "File Structure" "FAIL" "Missing files:$missing_files"
fi

# Test Suite 2: Database Operations
echo
log_test "Test Suite 2: Database Operations"
echo "----------------------------------------------------------------"

# Test 2.1: MongoDB Service
log_info "2.1 Testing MongoDB service..."
sudo systemctl start mongod 2>/dev/null || sudo systemctl start mongodb 2>/dev/null || true
sleep 2

mongo --eval "db.stats()" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    record_test "MongoDB Service" "PASS" "MongoDB is running and responsive"
else
    record_test "MongoDB Service" "FAIL" "MongoDB is not running or not accessible"
fi

# Test 2.2: Database Operations
log_info "2.2 Testing database operations..."
mongo << 'EOF' > /dev/null 2>&1
use test_suite_db;
db.dropDatabase();
use test_suite_db;
db.test_collection.insertOne({test: "data", timestamp: new Date()});
var count = db.test_collection.count();
if (count === 1) {
    print("Database operations successful");
} else {
    print("Database operations failed");
    quit(1);
}
db.dropDatabase();
EOF

if [ $? -eq 0 ]; then
    record_test "Database Operations" "PASS" "CRUD operations working correctly"
else
    record_test "Database Operations" "FAIL" "Database operations failed"
fi

# Test Suite 3: Core Modules
echo
log_test "Test Suite 3: Core Modules"
echo "----------------------------------------------------------------"

# Test 3.1: Key Manager Module
log_info "3.1 Testing key management system..."
python3 << 'EOF'
import sys
import os
import shutil
sys.path.append('src')

# Clean up any existing test keys
if os.path.exists('test_keys_suite'):
    shutil.rmtree('test_keys_suite')

try:
    from key_manager import KeyManager
    
    # Test 1: Key generation
    km = KeyManager(keys_dir='test_keys_suite')
    keys = km.generate_key_pair()
    
    if not (keys and 'private_key' in keys and 'public_key' in keys):
        print("Key generation failed")
        sys.exit(1)
    print("✓ RSA key pair generation successful")
    
    # Test 2: User creation
    user_result = km.create_user('test_admin', 'secure_pass_123', 'admin', expires_days=30)
    if not user_result:
        print("User creation failed")
        sys.exit(1)
    print("✓ User creation successful")
    
    # Test 3: Authentication
    user = km.authenticate_user('test_admin', 'secure_pass_123')
    if not user:
        print("User authentication failed")
        sys.exit(1)
    print("✓ User authentication successful")
    
    # Test 4: JWT token generation
    token = km.generate_token('test_admin', {'role': 'admin'})
    if not token:
        print("Token generation failed")
        sys.exit(1)
    print("✓ JWT token generation successful")
    
    # Test 5: JWT token validation
    payload = km.validate_token(token)
    if not payload or payload.get('username') != 'test_admin':
        print("Token validation failed")
        sys.exit(1)
    print("✓ JWT token validation successful")
    
    # Test 6: Encryption/Decryption
    test_data = "This is a test message for encryption"
    encrypted = km.encrypt_data(test_data)
    if not encrypted:
        print("Data encryption failed")
        sys.exit(1)
    print("✓ Data encryption successful")
    
    decrypted = km.decrypt_data(encrypted)
    if decrypted != test_data:
        print("Data decryption failed")
        sys.exit(1)
    print("✓ Data decryption successful")
    
    print("All key management tests passed")
    
except Exception as e:
    print(f"Key management test failed: {e}")
    sys.exit(1)
finally:
    # Cleanup
    if os.path.exists('test_keys_suite'):
        shutil.rmtree('test_keys_suite')
EOF

if [ $? -eq 0 ]; then
    record_test "Key Management System" "PASS" "RSA keys, users, JWT tokens, encryption all working"
else
    record_test "Key Management System" "FAIL" "One or more key management features failed"
fi

# Test 3.2: Packet Capture Module
log_info "3.2 Testing packet capture module..."
python3 << 'EOF'
import sys
import os
sys.path.append('src')

try:
    from packet_capture import PacketCapture
    from scapy.all import IP, TCP, UDP, DNS, DNSQR
    
    # Test 1: PacketCapture initialization
    capture = PacketCapture(
        interface='lo',
        mongodb_uri='mongodb://localhost:27017/',
        db_name='test_packet_capture',
        capture_mode='standard'
    )
    print("✓ PacketCapture initialization successful")
    
    # Test 2: MongoDB connection
    if capture.collection is None:
        print("MongoDB connection failed")
        sys.exit(1)
    print("✓ MongoDB connection established")
    
    # Test 3: Packet parsing - TCP
    tcp_packet = IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=12345, dport=80)
    packet_info = capture.extract_packet_info(tcp_packet)
    
    if not (packet_info and 
            packet_info['src_ip'] == '192.168.1.10' and
            packet_info['dest_ip'] == '192.168.1.20' and
            packet_info['protocol'] == 'TCP' and
            packet_info['src_port'] == 12345 and
            packet_info['dest_port'] == 80):
        print("TCP packet parsing failed")
        sys.exit(1)
    print("✓ TCP packet parsing successful")
    
    # Test 4: Packet parsing - UDP
    udp_packet = IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=53, dport=54321)
    packet_info = capture.extract_packet_info(udp_packet)
    
    if not (packet_info and 
            packet_info['protocol'] == 'UDP' and
            packet_info['src_port'] == 53):
        print("UDP packet parsing failed")
        sys.exit(1)
    print("✓ UDP packet parsing successful")
    
    # Test 5: DNS packet parsing
    dns_packet = IP(src="1.1.1.1", dst="192.168.1.1")/UDP(sport=53, dport=12345)/DNS(qd=DNSQR(qname="example.com"))
    packet_info = capture.extract_packet_info(dns_packet)
    
    if not (packet_info and 'dns_query' in packet_info):
        print("DNS packet parsing failed")
        sys.exit(1)
    print("✓ DNS packet parsing successful")
    
    # Test 6: Database storage
    capture.save_packet_to_db(packet_info)
    print("✓ Packet database storage successful")
    
    # Test 7: Statistics
    stats = capture.get_capture_stats()
    if not isinstance(stats, dict):
        print("Statistics generation failed")
        sys.exit(1)
    print("✓ Statistics generation successful")
    
    print("All packet capture tests passed")
    
except Exception as e:
    print(f"Packet capture test failed: {e}")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    record_test "Packet Capture Module" "PASS" "Packet parsing, DB storage, statistics all working"
else
    record_test "Packet Capture Module" "FAIL" "Packet capture functionality failed"
fi

# Test 3.3: Web Application Module
log_info "3.3 Testing web application module..."
python3 << 'EOF'
import sys
import os
sys.path.append('src')

try:
    from web_app import app
    
    # Test 1: Flask app creation
    if not app:
        print("Flask app creation failed")
        sys.exit(1)
    print("✓ Flask app creation successful")
    
    # Test 2: Test client
    with app.test_client() as client:
        app.config['TESTING'] = True
        
        # Test 3: Health endpoint
        response = client.get('/api/health')
        if response.status_code != 200:
            print(f"Health endpoint failed: {response.status_code}")
            sys.exit(1)
        print("✓ Health endpoint working")
        
        # Test 4: Login page
        response = client.get('/login')
        if response.status_code != 200:
            print(f"Login page failed: {response.status_code}")
            sys.exit(1)
        print("✓ Login page accessible")
        
        # Test 5: Dashboard (should redirect to login)
        response = client.get('/dashboard')
        if response.status_code not in [200, 302]:
            print(f"Dashboard endpoint failed: {response.status_code}")
            sys.exit(1)
        print("✓ Dashboard endpoint responding")
        
        # Test 6: API stats (should require auth)
        response = client.get('/api/stats')
        if response.status_code not in [200, 401, 403]:
            print(f"Stats API unexpected response: {response.status_code}")
            sys.exit(1)
        print("✓ Stats API responding correctly")
        
        # Test 7: Static files
        response = client.get('/static/style.css')
        if response.status_code != 200:
            print(f"Static file serving failed: {response.status_code}")
            sys.exit(1)
        print("✓ Static file serving working")
    
    print("All web application tests passed")
    
except Exception as e:
    print(f"Web application test failed: {e}")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    record_test "Web Application Module" "PASS" "Flask app, endpoints, static files all working"
else
    record_test "Web Application Module" "FAIL" "Web application functionality failed"
fi

# Test Suite 4: Integration Tests
echo
log_test "Test Suite 4: Integration Tests"
echo "----------------------------------------------------------------"

# Test 4.1: End-to-End Flow
log_info "4.1 Testing end-to-end system flow..."

# Create a comprehensive integration test
python3 << 'EOF'
import sys
import os
import time
import threading
import shutil
sys.path.append('src')

try:
    # Clean up
    if os.path.exists('integration_test_keys'):
        shutil.rmtree('integration_test_keys')
    
    from key_manager import KeyManager
    from packet_capture import PacketCapture
    from web_app import app
    from scapy.all import IP, TCP
    
    # Step 1: Setup key manager
    km = KeyManager(keys_dir='integration_test_keys')
    keys = km.generate_key_pair()
    if not keys:
        print("Integration test: Key generation failed")
        sys.exit(1)
    
    admin_created = km.create_user('integration_admin', 'test_pass_123', 'admin', expires_days=1)
    if not admin_created:
        print("Integration test: Admin user creation failed")
        sys.exit(1)
    print("✓ Key management setup complete")
    
    # Step 2: Setup packet capture
    capture = PacketCapture(
        interface='lo',
        mongodb_uri='mongodb://localhost:27017/',
        db_name='integration_test_db',
        capture_mode='standard'
    )
    print("✓ Packet capture setup complete")
    
    # Step 3: Generate and process test packets
    test_packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=12345, dport=80),
        IP(src="192.168.1.11", dst="192.168.1.21")/TCP(sport=12346, dport=443),
        IP(src="192.168.1.12", dst="192.168.1.22")/TCP(sport=12347, dport=22),
    ]
    
    for packet in test_packets:
        packet_info = capture.extract_packet_info(packet)
        capture.save_packet_to_db(packet_info)
    print("✓ Test packets processed and stored")
    
    # Step 4: Verify data in database
    stats = capture.get_capture_stats()
    if stats.get('total_packets', 0) < 3:
        print("Integration test: Insufficient packets in database")
        sys.exit(1)
    print("✓ Database verification complete")
    
    # Step 5: Test web app with data
    with app.test_client() as client:
        app.config['TESTING'] = True
        
        # Test health endpoint
        response = client.get('/api/health')
        if response.status_code != 200:
            print("Integration test: Health endpoint failed")
            sys.exit(1)
        
        # Test stats endpoint (even if auth required, should respond)
        response = client.get('/api/stats')
        if response.status_code not in [200, 401, 403]:
            print("Integration test: Stats endpoint failed")
            sys.exit(1)
    
    print("✓ Web application integration complete")
    print("End-to-end integration test successful")
    
except Exception as e:
    print(f"Integration test failed: {e}")
    sys.exit(1)
finally:
    # Cleanup
    if os.path.exists('integration_test_keys'):
        shutil.rmtree('integration_test_keys')
EOF

if [ $? -eq 0 ]; then
    record_test "End-to-End Integration" "PASS" "Full system flow working correctly"
else
    record_test "End-to-End Integration" "FAIL" "Integration test failed"
fi

# Test 4.2: Performance Test
log_info "4.2 Running basic performance test..."
python3 << 'EOF'
import sys
import time
sys.path.append('src')

try:
    from packet_capture import PacketCapture
    from scapy.all import IP, TCP
    
    capture = PacketCapture(
        interface='lo',
        mongodb_uri='mongodb://localhost:27017/',
        db_name='performance_test_db',
        capture_mode='standard'
    )
    
    # Performance test: Process 100 packets
    start_time = time.time()
    
    for i in range(100):
        packet = IP(src=f"192.168.1.{i%254+1}", dst="192.168.1.100")/TCP(sport=12345+i, dport=80)
        packet_info = capture.extract_packet_info(packet)
        capture.save_packet_to_db(packet_info)
    
    end_time = time.time()
    duration = end_time - start_time
    packets_per_second = 100 / duration
    
    print(f"Processed 100 packets in {duration:.2f} seconds")
    print(f"Performance: {packets_per_second:.1f} packets/second")
    
    if packets_per_second < 10:
        print("Performance test failed: Too slow")
        sys.exit(1)
    
    print("Performance test passed")
    
except Exception as e:
    print(f"Performance test failed: {e}")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    record_test "Performance Test" "PASS" "System performance acceptable"
else
    record_test "Performance Test" "FAIL" "Performance below acceptable threshold"
fi

# Test Suite 5: Security Tests
echo
log_test "Test Suite 5: Security Tests"
echo "----------------------------------------------------------------"

# Test 5.1: Authentication Security
log_info "5.1 Testing authentication security..."
python3 << 'EOF'
import sys
import os
import shutil
sys.path.append('src')

try:
    if os.path.exists('security_test_keys'):
        shutil.rmtree('security_test_keys')
    
    from key_manager import KeyManager
    
    km = KeyManager(keys_dir='security_test_keys')
    keys = km.generate_key_pair()
    
    # Test 1: Strong password enforcement
    weak_passwords = ['123', 'password', 'abc']
    for pwd in weak_passwords:
        result = km.create_user('test_user', pwd, 'user', expires_days=1)
        if result:
            print(f"Security test failed: Weak password '{pwd}' was accepted")
            sys.exit(1)
    print("✓ Weak password rejection working")
    
    # Test 2: Invalid authentication
    km.create_user('security_user', 'SecurePass123!', 'user', expires_days=1)
    
    invalid_auth = km.authenticate_user('security_user', 'WrongPassword')
    if invalid_auth:
        print("Security test failed: Invalid password was accepted")
        sys.exit(1)
    print("✓ Invalid authentication rejection working")
    
    # Test 3: JWT token tampering
    valid_token = km.generate_token('security_user', {'role': 'user'})
    
    # Try to validate a tampered token
    tampered_token = valid_token[:-10] + "tampered123"
    tampered_payload = km.validate_token(tampered_token)
    if tampered_payload:
        print("Security test failed: Tampered token was accepted")
        sys.exit(1)
    print("✓ Token tampering detection working")
    
    # Test 4: Expired user handling
    km.create_user('expired_user', 'SecurePass123!', 'user', expires_days=-1)  # Already expired
    expired_auth = km.authenticate_user('expired_user', 'SecurePass123!')
    if expired_auth:
        print("Security test failed: Expired user was authenticated")
        sys.exit(1)
    print("✓ Expired user handling working")
    
    print("All security tests passed")
    
except Exception as e:
    print(f"Security test failed: {e}")
    sys.exit(1)
finally:
    if os.path.exists('security_test_keys'):
        shutil.rmtree('security_test_keys')
EOF

if [ $? -eq 0 ]; then
    record_test "Authentication Security" "PASS" "Password enforcement, token security, expiration all working"
else
    record_test "Authentication Security" "FAIL" "Security vulnerabilities detected"
fi

# Test 5.2: Data Security
log_info "5.2 Testing data encryption security..."
python3 << 'EOF'
import sys
import os
import shutil
sys.path.append('src')

try:
    if os.path.exists('encryption_test_keys'):
        shutil.rmtree('encryption_test_keys')
    
    from key_manager import KeyManager
    
    km = KeyManager(keys_dir='encryption_test_keys')
    keys = km.generate_key_pair()
    
    # Test 1: Encryption/Decryption integrity
    test_messages = [
        "Simple message",
        "Complex message with !@#$%^&*() symbols and 123 numbers",
        "Very long message that exceeds normal limits and includes unicode characters: ñáéíóú",
        ""  # Empty string
    ]
    
    for msg in test_messages:
        encrypted = km.encrypt_data(msg)
        if not encrypted:
            print(f"Encryption failed for message: '{msg[:20]}...'")
            sys.exit(1)
        
        decrypted = km.decrypt_data(encrypted)
        if decrypted != msg:
            print(f"Decryption integrity failed for message: '{msg[:20]}...'")
            sys.exit(1)
    
    print("✓ Encryption/decryption integrity verified")
    
    # Test 2: Key file security
    private_key_path = os.path.join('encryption_test_keys', 'private_key.pem')
    if os.path.exists(private_key_path):
        file_stat = os.stat(private_key_path)
        file_permissions = oct(file_stat.st_mode)[-3:]
        
        if file_permissions != '600':
            print(f"Private key file permissions insecure: {file_permissions}")
            sys.exit(1)
        print("✓ Private key file permissions secure")
    
    print("All data security tests passed")
    
except Exception as e:
    print(f"Data security test failed: {e}")
    sys.exit(1)
finally:
    if os.path.exists('encryption_test_keys'):
        shutil.rmtree('encryption_test_keys')
EOF

if [ $? -eq 0 ]; then
    record_test "Data Encryption Security" "PASS" "Encryption integrity and key security verified"
else
    record_test "Data Encryption Security" "FAIL" "Data security issues detected"
fi

# Final cleanup
log_info "Cleaning up test artifacts..."
mongo << 'EOF' > /dev/null 2>&1
use test_suite_db; db.dropDatabase();
use test_packet_capture; db.dropDatabase();
use integration_test_db; db.dropDatabase();
use performance_test_db; db.dropDatabase();
EOF

rm -rf test_keys_* 2>/dev/null || true

# Test Results Summary
echo
echo "================================================================"
echo "FULL TEST SUITE RESULTS"
echo "================================================================"

for result in "${TEST_RESULTS[@]}"; do
    echo "$result"
done

echo
echo "================================================================"
echo -e "📊 SUMMARY: ${GREEN}$PASSED_TESTS${NC}/${TOTAL_TESTS} tests passed"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo
    echo "Your WiFi Traffic Monitoring System is fully functional and ready for deployment!"
    echo
    echo "✅ Environment and dependencies verified"
    echo "✅ Database operations working"
    echo "✅ All core modules functional"
    echo "✅ Integration tests successful"
    echo "✅ Security tests passed"
    echo
    echo "Next steps:"
    echo "1. Test with real traffic: sudo ./scripts/local_traffic_test.sh"
    echo "2. Deploy to real environment: ./scripts/real_environment_install.sh"
    echo "3. Configure router port mirroring as per documentation"
    
    EXIT_CODE=0
else
    FAILED_TESTS=$((TOTAL_TESTS - PASSED_TESTS))
    echo -e "${RED}❌ $FAILED_TESTS TESTS FAILED${NC}"
    echo
    echo "Please address the failing tests before proceeding to deployment."
    echo
    echo "Common fixes:"
    echo "• Install missing dependencies: pip install -r requirements.txt"
    echo "• Start MongoDB: sudo systemctl start mongod"
    echo "• Check file permissions and paths"
    echo "• Verify network interface availability"
    
    EXIT_CODE=1
fi

echo "================================================================"

exit $EXIT_CODE