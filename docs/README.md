# 리소스 사용량 확인
htop
df -h
free -h
```

### 데이터베이스 유지보수
```bash
# MongoDB 상태 확인
mongo --eval "db.stats()"

# 인덱스 재구성
mongo traffic_monitor --eval "db.packets.reIndex()"

# 오래된 데이터 정리 (30일 이상)
mongo traffic_monitor --eval "
db.packets.deleteMany({
  timestamp: {
    \$lt: new Date(new Date().getTime() - 30*24*60*60*1000).toISOString()
  }
})
"
```

## 개발 정보

### 프로젝트 구조
```
wifi-monitor/
├── src/                    # 소스 코드
│   ├── packet_capture.py   # 패킷 캡처 모듈
│   ├── key_manager.py      # 키 관리 시스템
│   └── web_app.py          # 웹 애플리케이션
├── web/                    # 웹 인터페이스
│   ├── templates/          # HTML 템플릿
│   └── static/             # CSS, JS 파일
├── scripts/                # 설치/설정 스크립트
│   ├── setup.sh           # 전체 시스템 설치
│   └── configure_port_forwarding.sh
├── config/                 # 설정 파일
│   ├── .env               # 환경 변수
│   └── config.json        # JSON 설정
├── keys/                   # RSA 키 저장소
├── docs/                   # 문서
└── requirements.txt        # Python 종속성
```

### 코딩 스타일
- PEP 8 Python 코딩 스타일
- 타입 힌트 사용 권장
- Docstring 필수
- 에러 핸들링 철저히

### 테스트
```bash
# 단위 테스트 실행
python -m pytest tests/

# 코드 커버리지 확인
python -m pytest --cov=src tests/
```

## 확장 가능성

### 추가 기능 구현
1. **심화 분석**: 
   - DPI (Deep Packet Inspection)
   - 악성 트래픽 탐지
   - 대역폭 사용량 분석

2. **알림 시스템**:
   - 이메일/SMS 알림
   - 임계값 기반 경고
   - 슬랙 연동

3. **고급 시각화**:
   - 지리적 IP 매핑
   - 실시간 네트워크 토폴로지
   - 트래픽 흐름 다이어그램

4. **API 확장**:
   - REST API 완성
   - GraphQL 지원
   - 웹훅 지원

### 성능 최적화
1. **데이터베이스**: 
   - 샤딩 구현
   - 읽기 전용 복제본
   - 인덱스 최적화

2. **캐싱**:
   - Redis 캐시 레이어
   - CDN 사용
   - 브라우저 캐시 최적화

3. **비동기 처리**:
   - Celery 작업 큐
   - 웹소켓 실시간 업데이트
   - 백그라운드 분석

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 기여 방법

1. 이슈 리포트
2. 기능 요청
3. 코드 기여
4. 문서 개선

## 연락처

- 프로젝트 관리자: [이메일]
- 이슈 트래커: [GitHub Issues]
- 문서: [프로젝트 위키]

---

## 부록

### A. 네트워크 구성 상세

#### iptables 규칙 상세
```bash
# NAT 테이블 규칙 확인
sudo iptables -t nat -L -n -v

# 필터 테이블 규칙 확인  
sudo iptables -L -n -v

# 트래픽 통계 확인
sudo iptables -L -n -v --line-numbers
```

#### hostapd 구성 옵션
```
# /etc/hostapd/hostapd.conf
interface=wlan0
driver=nl80211
ssid=WiFi-Monitor-Lab
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=MonitorLab2024
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP

# 고급 옵션
country_code=KR
ieee80211d=1
ieee80211h=1
```

#### dnsmasq 구성 옵션
```
# /etc/dnsmasq.conf
interface=wlan0
bind-interfaces
dhcp-range=192.168.100.10,192.168.100.100,255.255.255.0,24h
dhcp-option=3,192.168.100.1
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
domain=monitor.lab
local=/monitor.lab/
```

### B. 데이터베이스 스키마

#### 패킷 컬렉션 (packets)
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

#### 사용자 컬렉션 (users)
```javascript
{
  "_id": ObjectId,
  "username": "admin",
  "password_hash": "pbkdf2_sha256$...",
  "role": "admin",
  "created_at": "2024-01-01T12:00:00.000Z",
  "expires_at": "2025-01-01T12:00:00.000Z",
  "active": true,
  "last_login": "2024-01-01T12:00:00.000Z"
}
```

### C. 보안 체크리스트

#### 설치 후 보안 검증
- [ ] 기본 비밀번호 변경
- [ ] 불필요한 서비스 비활성화
- [ ] 방화벽 규칙 검증
- [ ] SSL 인증서 설정
- [ ] 로그 모니터링 설정
- [ ] 백업 시스템 테스트
- [ ] 사용자 권한 검토
- [ ] 네트워크 격리 확인

#### 주기적 보안 점검
- [ ] 패치 업데이트 (월간)
- [ ] 로그 검토 (주간)
- [ ] 백업 테스트 (월간)
- [ ] 비밀번호 정책 검토 (분기)
- [ ] 접근 권한 감사 (분기)

### D. 성능 튜닝 가이드

#### MongoDB 최적화
```javascript
// 인덱스 생성
db.packets.createIndex({ "timestamp": -1 })
db.packets.createIndex({ "src_ip": 1, "dest_ip": 1 })
db.packets.createIndex({ "protocol": 1 })

// 복합 인덱스
db.packets.createIndex({ 
  "timestamp": -1, 
  "protocol": 1, 
  "src_ip": 1 
})
```

#### 시스템 설정 최적화
```bash
# 네트워크 버퍼 증가
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf

# 파일 핸들 제한 증가
echo 'wifi-monitor soft nofile 65536' >> /etc/security/limits.conf
echo 'wifi-monitor hard nofile 65536' >> /etc/security/limits.conf
```

### E. 문제 해결 FAQ

#### Q: 패킷 캡처가 느려요
A: 다음을 확인하세요:
- 시스템 리소스 상태 (CPU, 메모리)
- 네트워크 인터페이스 설정
- MongoDB 성능
- 필터 설정 최적화

#### Q: 웹 인터페이스에 접속할 수 없어요
A: 다음을 확인하세요:
- Nginx 서비스 상태
- 방화벽 설정
- SSL 인증서
- Flask 애플리케이션 상태

#### Q: 데이터가 저장되지 않아요
A: 다음을 확인하세요:
- MongoDB 서비스 상태
- 데이터베이스 권한
- 디스크 공간
- 네트워크 연결

#### Q: WiFi 클라이언트가 연결되지 않아요
A: 다음을 확인하세요:
- hostapd 설정
- 인터페이스 상태
- DHCP 서버 (dnsmasq)
- 라우팅 테이블

이 문서는 WiFi 트래픽 모니터링 시스템의 완전한 구현 및 운영 가이드입니다. 추가 질문이나 지원이 필요한 경우 프로젝트 관리팀에 문의하세요.
