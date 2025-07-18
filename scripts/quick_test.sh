#!/bin/bash

# WiFi Traffic Monitor - Quick Local Test Script
# Tests basic functionality on local machine

set -e

# Colors for output
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
TEST_RESULTS=()

echo "================================================================"
echo "WiFi Traffic Monitor - Quick Local Test"
echo "================================================================"

# Function to record test results
record_result() {
    local test_name="$1"
    local result="$2"
    if [ "$result" == "PASS" ]; then
        TEST_RESULTS+=("✅ $test_name")
        log_success "$test_name"
    else
        TEST_RESULTS+=("❌ $test_name")
        log_error "$test_name"
    fi
}

# Test 1: Check Prerequisites
log_info "Test 1: Checking prerequisites..."
python3 --version > /dev/null 2>&1 && PYTHON_OK=1 || PYTHON_OK=0
which tcpdump > /dev/null 2>&1 && TCPDUMP_OK=1 || TCPDUMP_OK=0

# Check MongoDB (either local installation or Docker)
if which mongod > /dev/null 2>&1; then
    MONGO_OK=1
elif sudo docker ps | grep mongo > /dev/null 2>&1; then
    MONGO_OK=1
    log_info "MongoDB found running in Docker"
else
    MONGO_OK=0
fi

if [ $PYTHON_OK -eq 1 ] && [ $MONGO_OK -eq 1 ] && [ $TCPDUMP_OK -eq 1 ]; then
    record_result "Prerequisites Check" "PASS"
else
    record_result "Prerequisites Check" "FAIL"
    if [ $PYTHON_OK -eq 0 ]; then log_error "Python3 not found"; fi
    if [ $MONGO_OK -eq 0 ]; then log_error "MongoDB not found (neither local nor Docker)"; fi
    if [ $TCPDUMP_OK -eq 0 ]; then log_error "tcpdump not found"; fi
fi

# Test 2: Python Dependencies
log_info "Test 2: Checking Python dependencies..."
if [ -f "requirements.txt" ]; then
    python3 -c "
import sys
required_modules = ['flask', 'pymongo', 'scapy', 'cryptography']
missing = []
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing.append(module)
if missing:
    print('Missing modules:', ', '.join(missing))
    sys.exit(1)
else:
    print('All required modules available')
" 2>/dev/null && record_result "Python Dependencies" "PASS" || record_result "Python Dependencies" "FAIL"
else
    record_result "Python Dependencies" "FAIL"
    log_error "requirements.txt not found"
fi

# Test 3: MongoDB Connection
log_info "Test 3: Testing MongoDB connection..."

# Test MongoDB connection using Python pymongo (works with Docker)
python3 << 'EOF'
import sys
try:
    from pymongo import MongoClient
    client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("MongoDB connection successful")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    record_result "MongoDB Connection" "PASS"
else
    record_result "MongoDB Connection" "FAIL"
fi

# Test 4: Key Manager Module
log_info "Test 4: Testing key management system..."
python3 << 'EOF'
import sys
import os
sys.path.append('src')

try:
    from key_manager import KeyManager
    
    # Test key generation
    km = KeyManager(keys_dir='test_keys')
    keys = km.generate_key_pair()
    
    if keys and 'private_key' in keys and 'public_key' in keys:
        print("✓ Key generation successful")
        
        # Test user creation
        result = km.create_user('test_user', 'test_password', 'admin', expires_days=1)
        if result:
            print("✓ User creation successful")
            
            # Test authentication
            user = km.authenticate_user('test_user', 'test_password')
            if user:
                print("✓ User authentication successful")
            else:
                print("✗ User authentication failed")
                sys.exit(1)
        else:
            print("✗ User creation failed")
            sys.exit(1)
    else:
        print("✗ Key generation failed")
        sys.exit(1)
        
except Exception as e:
    print(f"✗ Key manager test failed: {e}")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    record_result "Key Management System" "PASS"
else
    record_result "Key Management System" "FAIL"
fi

# Test 5: Packet Capture Module (Mock Test)
log_info "Test 5: Testing packet capture module..."
python3 << 'EOF'
import sys
import os
sys.path.append('src')

try:
    # Test without actually capturing packets
    from packet_capture import PacketCapture
    
    # Create instance with loopback interface
    capture = PacketCapture(
        interface='lo',
        mongodb_uri='mongodb://localhost:27017/',
        db_name='test_traffic_monitor',
        capture_mode='standard'
    )
    
    # Test MongoDB connection
    if capture.collection is not None:
        print("✓ PacketCapture initialized successfully")
        print("✓ MongoDB connection established")
        
        # Test packet info extraction (mock packet)
        from scapy.all import IP, TCP
        test_packet = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12345, dport=80)
        packet_info = capture.extract_packet_info(test_packet)
        
        if packet_info and packet_info['src_ip'] == '127.0.0.1':
            print("✓ Packet parsing working correctly")
        else:
            print("✗ Packet parsing failed")
            sys.exit(1)
    else:
        print("✗ MongoDB connection failed")
        sys.exit(1)
        
except Exception as e:
    print(f"✗ Packet capture test failed: {e}")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    record_result "Packet Capture Module" "PASS"
else
    record_result "Packet Capture Module" "FAIL"
fi

# Test 6: Web Application (Basic)
log_info "Test 6: Testing web application basics..."
python3 << 'EOF'
import sys
import os
sys.path.append('src')

try:
    from web_app import app
    
    # Test app creation
    if app:
        print("✓ Flask app created successfully")
        
        # Test app configuration
        with app.test_client() as client:
            # Test health endpoint
            response = client.get('/api/health')
            if response.status_code == 200:
                print("✓ Health endpoint working")
            else:
                print("✗ Health endpoint failed")
                sys.exit(1)
                
            # Test login page
            response = client.get('/login')
            if response.status_code == 200:
                print("✓ Login page accessible")
            else:
                print("✗ Login page failed")
                sys.exit(1)
    else:
        print("✗ Flask app creation failed")
        sys.exit(1)
        
except Exception as e:
    print(f"✗ Web application test failed: {e}")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    record_result "Web Application Basics" "PASS"
else
    record_result "Web Application Basics" "FAIL"
fi

# Test 7: File Structure and Permissions
log_info "Test 7: Checking file structure and permissions..."
REQUIRED_FILES=(
    "src/web_app.py"
    "src/packet_capture.py" 
    "src/key_manager.py"
    "requirements.txt"
    "config/config.json"
)

FILE_CHECK_PASS=1
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        log_error "Missing file: $file"
        FILE_CHECK_PASS=0
    fi
done

if [ $FILE_CHECK_PASS -eq 1 ]; then
    record_result "File Structure Check" "PASS"
else
    record_result "File Structure Check" "FAIL"
fi

# Clean up test artifacts
rm -rf test_keys/ 2>/dev/null || true

# Test Results Summary
echo
echo "================================================================"
echo "TEST RESULTS SUMMARY"
echo "================================================================"

PASS_COUNT=0
TOTAL_COUNT=${#TEST_RESULTS[@]}

for result in "${TEST_RESULTS[@]}"; do
    echo "$result"
    if [[ $result == ✅* ]]; then
        ((PASS_COUNT++))
    fi
done

echo
echo "================================================================"
if [ $PASS_COUNT -eq $TOTAL_COUNT ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED ($PASS_COUNT/$TOTAL_COUNT)${NC}"
    echo "Your implementation is ready for real environment testing!"
    echo
    echo "Next steps:"
    echo "1. Run full test suite: ./scripts/full_test_suite.sh"
    echo "2. Test with real traffic: ./scripts/local_traffic_test.sh"
    echo "3. Deploy to real environment using: ./scripts/real_environment_install.sh"
else
    echo -e "${RED}❌ SOME TESTS FAILED ($PASS_COUNT/$TOTAL_COUNT passed)${NC}"
    echo "Please fix the failing tests before proceeding to real environment."
    echo
    echo "Common fixes:"
    echo "• Install missing dependencies: pip install -r requirements.txt"
    echo "• Start MongoDB: sudo systemctl start mongod"
    echo "• Check file permissions and paths"
fi
echo "================================================================"

# Exit with appropriate code
if [ $PASS_COUNT -eq $TOTAL_COUNT ]; then
    exit 0
else
    exit 1
fi