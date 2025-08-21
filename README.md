# WiFi Traffic Monitoring System / WiFi 트래픽 모니터링 시스템

[English](#english) | [한국어](#korean)

---

<a name="english"></a>
## WiFi Traffic Monitoring System

A comprehensive network traffic monitoring solution designed for educational purposes and network management. This system provides real-time packet capture, analysis, and visualization capabilities for WiFi networks.

### Features

- **Real-time Traffic Monitoring**: Capture and analyze network packets in real-time
- **Web-based Dashboard**: Modern, responsive web interface with data visualization
- **Security Features**: RSA encryption, JWT authentication, and role-based access control
- **Multiple Capture Modes**: Standard, mirror, and monitor mode support
- **RESTful API**: Comprehensive API for programmatic access
- **Docker Support**: Easy deployment with containerization

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/wifi-monitor.git
cd wifi-monitor

# Run with Docker
docker-compose up -d

# Or install locally
./scripts/setup.sh
```

Default credentials:
- Username: `admin`
- Password: `admin123`

### Technology Stack

- **Backend**: Python 3, Flask, MongoDB, Scapy
- **Frontend**: HTML5, Bootstrap 5, Chart.js
- **Security**: JWT, RSA 2048-bit encryption, PBKDF2
- **Deployment**: Docker, Gunicorn, Nginx

### Documentation

- [Installation Guide](INSTALLATION.md)
- [Setup Guide](SETUP_GUIDE.md)
- [API Documentation](API_DOCUMENTATION.md)
- [Security Guide](SECURITY_GUIDE.md)
- [Development Guide](docs/README.md)

### License

This project is licensed under the MIT License.

---

<a name="korean"></a>
## WiFi 트래픽 모니터링 시스템

교육 목적과 네트워크 관리를 위해 설계된 종합적인 네트워크 트래픽 모니터링 솔루션입니다. 이 시스템은 WiFi 네트워크에 대한 실시간 패킷 캡처, 분석 및 시각화 기능을 제공합니다.

### 주요 기능

- **실시간 트래픽 모니터링**: 네트워크 패킷을 실시간으로 캡처하고 분석
- **웹 기반 대시보드**: 데이터 시각화가 포함된 현대적이고 반응형 웹 인터페이스
- **보안 기능**: RSA 암호화, JWT 인증 및 역할 기반 접근 제어
- **다중 캡처 모드**: 표준, 미러 및 모니터 모드 지원
- **RESTful API**: 프로그래밍 방식 접근을 위한 포괄적인 API
- **Docker 지원**: 컨테이너화를 통한 쉬운 배포

### 빠른 시작

```bash
# 저장소 복제
git clone https://github.com/yourusername/wifi-monitor.git
cd wifi-monitor

# Docker로 실행
docker-compose up -d

# 또는 로컬 설치
./scripts/setup.sh
```

기본 인증 정보:
- 사용자명: `admin`
- 비밀번호: `admin123`

### 기술 스택

- **백엔드**: Python 3, Flask, MongoDB, Scapy
- **프론트엔드**: HTML5, Bootstrap 5, Chart.js
- **보안**: JWT, RSA 2048비트 암호화, PBKDF2
- **배포**: Docker, Gunicorn, Nginx

### 문서

- [설치 가이드](INSTALLATION.md)
- [설정 가이드](SETUP_GUIDE.md)
- [API 문서](API_DOCUMENTATION.md)
- [보안 가이드](SECURITY_GUIDE.md)
- [개발 가이드](docs/README.md)

### 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.