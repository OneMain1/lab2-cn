# API Documentation - WiFi Traffic Monitoring System

## Overview

This document provides comprehensive API documentation for the WiFi Traffic Monitoring System. The API provides RESTful endpoints for accessing traffic data, managing users, and controlling system operations.

## Base URL and Authentication

### Base URL
```
https://your-server-ip/api/
```

### Authentication

All API endpoints require authentication using JWT tokens obtained through the login process.

#### Login Process
```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=your_username&password=your_password
```

**Response:**
```json
{
  "status": "success",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```

#### Using Authentication Token
Include the JWT token in the session cookie or Authorization header:

```http
Cookie: session=your_session_token
# OR
Authorization: Bearer your_jwt_token
```

## Data Endpoints

### Get Traffic Statistics

Retrieve comprehensive traffic statistics including protocol distribution, hourly activity, and top source IPs.

```http
GET /api/stats
```

**Response:**
```json
{
  "total_packets": 15420,
  "protocol_stats": [
    {"_id": "TCP", "count": 8932},
    {"_id": "UDP", "count": 4021},
    {"_id": "ICMP", "count": 467}
  ],
  "hourly_stats": [
    {"_id": "2024-01-01 10:00", "count": 234},
    {"_id": "2024-01-01 11:00", "count": 456}
  ],
  "top_sources": [
    {"_id": "192.168.100.10", "count": 1234},
    {"_id": "192.168.100.11", "count": 987}
  ]
}
```

### Get Packet Data

Retrieve filtered packet data with pagination support.

```http
GET /api/packets?page=1&limit=50&protocol=TCP&src_ip=192.168.100.10
```

**Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Results per page (default: 50, max: 1000)
- `protocol` (optional): Filter by protocol (TCP, UDP, ICMP, etc.)
- `src_ip` (optional): Filter by source IP address
- `dest_ip` (optional): Filter by destination IP address

**Response:**
```json
{
  "packets": [
    {
      "timestamp": "2024-01-01T12:30:45.123Z",
      "src_ip": "192.168.100.10",
      "dest_ip": "8.8.8.8",
      "src_port": 12345,
      "dest_port": 80,
      "protocol": "TCP",
      "packet_length": 1024,
      "url": "http://example.com/path",
      "packet_id": "abcd1234efgh5678"
    }
  ],
  "total": 1500,
  "page": 1,
  "pages": 30
}
```

### Get Real-time Statistics

Retrieve real-time statistics for dashboard updates (last 5 minutes).

```http
GET /api/realtime_stats
```

**Response:**
```json
{
  "recent_activity": [
    {"_id": "TCP", "count": 45, "total_bytes": 23456},
    {"_id": "UDP", "count": 12, "total_bytes": 3456}
  ],
  "top_sources": [
    {"_id": "192.168.100.10", "packet_count": 23},
    {"_id": "192.168.100.11", "packet_count": 15}
  ],
  "capture_running": true,
  "timestamp": "2024-01-01T12:35:00.000Z"
}
```

## System Control Endpoints (Admin Only)

### Start Packet Capture

Start the packet capture process.

```http
POST /api/capture/start
```

**Response:**
```json
{
  "status": "started",
  "message": "Packet capture started successfully"
}
```

**Error Response:**
```json
{
  "error": "Capture already running or not initialized"
}
```

### Stop Packet Capture

Stop the packet capture process.

```http
POST /api/capture/stop
```

**Response:**
```json
{
  "status": "stopped",
  "message": "Packet capture stopped successfully"
}
```

## User Management Endpoints (Admin Only)

### Create User

Create a new user account.

```http
POST /admin/create_user
Content-Type: application/x-www-form-urlencoded

username=newuser&password=securepass&role=user&expires_days=30
```

**Parameters:**
- `username`: Username for the new account
- `password`: Password for the new account
- `role`: User role (user or admin)
- `expires_days`: Account expiration in days

**Response:**
```json
{
  "status": "success",
  "message": "User created successfully"
}
```

### Deactivate User

Deactivate an existing user account.

```http
POST /admin/deactivate_user/username
```

**Response:**
```json
{
  "status": "success",
  "message": "User deactivated successfully"
}
```

### Update User Expiry

Update user account expiration date.

```http
POST /api/update_user_expiry
Content-Type: application/json

{
  "username": "existing_user",
  "expires_days": 60
}
```

**Response:**
```json
{
  "success": true
}
```

## Security Endpoints

### Get Public Key

Retrieve the RSA public key for encryption.

```http
GET /api/public_key
```

**Response:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
}
```

### Generate New Keys (Admin Only)

Generate new RSA key pair (invalidates all existing tokens).

```http
POST /api/generate_keys
```

**Response:**
```json
{
  "success": true,
  "message": "New RSA keys generated successfully"
}
```

## Administrative Endpoints

### Get Admin Statistics

Retrieve administrative statistics and system health information.

```http
GET /api/admin/stats
```

**Response:**
```json
{
  "active_sessions": 3,
  "total_logins": 45,
  "failed_logins": 2,
  "packets_today": 5420,
  "data_volume": 2048576
}
```

### Health Check

Check system health and component status.

```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "capture": "running",
  "timestamp": "2024-01-01T12:35:00.000Z"
}
```

**Error Response:**
```json
{
  "status": "unhealthy",
  "error": "Database connection failed",
  "timestamp": "2024-01-01T12:35:00.000Z"
}
```

## Error Handling

### Standard Error Responses

All API endpoints return consistent error responses:

#### Authentication Error (401)
```json
{
  "error": "Authentication required",
  "code": 401
}
```

#### Authorization Error (403)
```json
{
  "error": "Admin access required",
  "code": 403
}
```

#### Validation Error (400)
```json
{
  "error": "Invalid parameters",
  "details": "Username and password required",
  "code": 400
}
```

#### Server Error (500)
```json
{
  "error": "Internal server error",
  "details": "Database connection failed",
  "code": 500
}
```

### HTTP Status Codes

- `200` - Success
- `400` - Bad Request (invalid parameters)
- `401` - Unauthorized (authentication required)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `429` - Too Many Requests (rate limited)
- `500` - Internal Server Error

## Rate Limiting

API endpoints are rate-limited to prevent abuse:

- **General API**: 100 requests per minute per IP
- **Authentication**: 10 login attempts per minute per IP
- **Admin Operations**: 50 requests per minute per user

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## Data Models

### Packet Object
```json
{
  "timestamp": "ISO 8601 datetime string",
  "src_ip": "Source IP address",
  "dest_ip": "Destination IP address", 
  "src_port": "Source port number (integer)",
  "dest_port": "Destination port number (integer)",
  "protocol": "Protocol name (TCP/UDP/ICMP/etc)",
  "packet_length": "Packet size in bytes (integer)",
  "url": "HTTP URL if available (string or null)",
  "dns_query": "DNS query if applicable (string or null)",
  "packet_id": "Unique packet identifier"
}
```

### User Object
```json
{
  "username": "User login name",
  "role": "User role (user or admin)",
  "created_at": "ISO 8601 creation timestamp",
  "expires_at": "ISO 8601 expiration timestamp",
  "active": "Boolean active status"
}
```

## Usage Examples

### Python Client Example

```python
import requests
import json

class WiFiMonitorAPI:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.session = requests.Session()
        self.login(username, password)
    
    def login(self, username, password):
        """Authenticate and establish session"""
        response = self.session.post(
            f"{self.base_url}/login",
            data={'username': username, 'password': password},
            verify=False  # For self-signed certificates
        )
        if response.status_code != 200:
            raise Exception("Login failed")
    
    def get_stats(self):
        """Get traffic statistics"""
        response = self.session.get(f"{self.base_url}/api/stats")
        return response.json()
    
    def get_packets(self, **filters):
        """Get packets with optional filters"""
        response = self.session.get(
            f"{self.base_url}/api/packets",
            params=filters
        )
        return response.json()
    
    def start_capture(self):
        """Start packet capture (admin only)"""
        response = self.session.post(f"{self.base_url}/api/capture/start")
        return response.json()

# Usage
api = WiFiMonitorAPI("https://192.168.1.100", "admin", "password")
stats = api.get_stats()
packets = api.get_packets(protocol="TCP", limit=100)
```

### JavaScript Client Example

```javascript
class WiFiMonitorAPI {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    
    async login(username, password) {
        const response = await fetch(`${this.baseUrl}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${username}&password=${password}`,
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Login failed');
        }
    }
    
    async getStats() {
        const response = await fetch(`${this.baseUrl}/api/stats`, {
            credentials: 'include'
        });
        return await response.json();
    }
    
    async getPackets(filters = {}) {
        const params = new URLSearchParams(filters);
        const response = await fetch(`${this.baseUrl}/api/packets?${params}`, {
            credentials: 'include'
        });
        return await response.json();
    }
}

// Usage
const api = new WiFiMonitorAPI('https://192.168.1.100');
await api.login('admin', 'password');
const stats = await api.getStats();
const packets = await api.getPackets({protocol: 'TCP', limit: 100});
```

### cURL Examples

```bash
# Login and save cookies
curl -k -c cookies.txt -X POST \
  "https://192.168.1.100/login" \
  -d "username=admin&password=yourpassword"

# Get statistics
curl -k -b cookies.txt \
  "https://192.168.1.100/api/stats"

# Get packets with filters
curl -k -b cookies.txt \
  "https://192.168.1.100/api/packets?protocol=TCP&limit=10"

# Start capture (admin only)
curl -k -b cookies.txt -X POST \
  "https://192.168.1.100/api/capture/start"
```

This API documentation provides complete information for integrating with the WiFi Traffic Monitoring System programmatically.