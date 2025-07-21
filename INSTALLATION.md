# Installation Guide - WiFi Traffic Monitoring System

## Quick Start Guide

This guide will help you install and run the WiFi traffic monitoring system on Ubuntu/Debian systems.

## Prerequisites

- Ubuntu 20.04+ or Debian 11+
- Python 3.8+
- Root/sudo access
- Network interface for monitoring

## Step-by-Step Installation

### 1. System Dependencies

First, update your system and install basic dependencies:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install basic tools
sudo apt install -y wget curl gnupg2 software-properties-common apt-transport-https ca-certificates lsb-release
```

### 2. Install MongoDB

MongoDB is required for storing packet data. Install from the official repository:

```bash
# Import MongoDB public GPG key
curl -fsSL https://pgp.mongodb.com/server-7.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

# Add MongoDB repository
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

# Update package database
sudo apt update

# Install MongoDB
sudo apt install -y mongodb-org

# Start and enable MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Verify MongoDB is running
sudo systemctl status mongod
```

**Alternative: MongoDB with Docker (if above fails)**

```bash
# Install Docker
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker

# Run MongoDB container
sudo docker run -d --name mongodb -p 27017:27017 mongo:latest

# Verify container is running
sudo docker ps
```

### 3. Install Network Tools

```bash
# Install packet capture tools
sudo apt install -y tcpdump wireshark-common

# Add current user to wireshark group (optional)
sudo usermod -a -G wireshark $USER
```

### 4. Python Environment Setup

```bash
# Navigate to project directory
cd /path/to/lab2-cn

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 5. Configuration

#### Update Network Interface

Check your network interfaces:
```bash
ip link show
```

Update the configuration file with your WiFi interface name:
```bash
# Edit config/config.json
# Change "interface": "wlan0" to your actual interface (e.g., "wlp0s20f3")
```

#### Generate Security Keys

```bash
# Generate RSA keys and initial admin user
python3 src/key_manager.py generate
```

### 6. Run the Application

#### Basic Test Run

```bash
# Make sure you're in the project directory with venv activated
cd /path/to/lab2-cn
source venv/bin/activate

# Test MongoDB connection
python3 -c "from pymongo import MongoClient; print('MongoDB:', 'OK' if MongoClient().admin.command('ping') else 'Failed')"

# Run the web application
python3 src/web_app.py
```

The application will be available at:
- https://127.0.0.1:5000
- https://[your-ip]:5000

#### Default Credentials

- **Username**: admin
- **Password**: Check `/path/to/lab2-cn/keys/admin_credentials.txt`

## Troubleshooting

### MongoDB Connection Issues

```bash
# Check MongoDB status
sudo systemctl status mongod

# Check MongoDB logs
sudo journalctl -u mongod

# Restart MongoDB
sudo systemctl restart mongod
```

### Network Interface Issues

```bash
# List all network interfaces
ip link show

# Check interface status
ip addr show [interface-name]

# Enable interface if needed
sudo ip link set [interface-name] up
```

### Permission Issues

```bash
# Add user to necessary groups
sudo usermod -a -G netdev $USER
sudo usermod -a -G wireshark $USER

# Log out and log back in for group changes to take effect
```

### Python Dependencies

```bash
# If pip install fails, try updating pip
python3 -m pip install --upgrade pip

# Install dependencies one by one if needed
pip install flask==2.3.3
pip install pymongo==4.5.0
pip install scapy==2.5.0
# ... etc
```

## Advanced Installation (Production)

For production deployment, see:
- [SETUP_GUIDE.md](SETUP_GUIDE.md) - Full system setup with services
- [SECURITY_GUIDE.md](SECURITY_GUIDE.md) - Security configuration

## Verification

After installation, verify everything works:

```bash
# Check MongoDB
python3 -c "from pymongo import MongoClient; print(MongoClient().admin.command('ping'))"

# Check web app imports
python3 -c "from src.web_app import app; print('Web app OK')"

# Check packet capture (requires root/sudo)
sudo python3 -c "from src.packet_capture import PacketCapture; print('Packet capture OK')"
```

## Quick Commands Reference

```bash
# Start application
cd /path/to/lab2-cn
source venv/bin/activate
python3 src/web_app.py

# Check MongoDB
sudo systemctl status mongod

# View logs
journalctl -f

# Stop application
# Press Ctrl+C in the terminal running the app
```

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review system logs: `journalctl -f`
3. Verify all dependencies are installed
4. Ensure MongoDB is running and accessible

---

**Note**: This is an educational project for learning network security concepts. Use responsibly and in compliance with applicable laws and regulations.