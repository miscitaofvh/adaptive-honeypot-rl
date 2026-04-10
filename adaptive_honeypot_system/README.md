# Adaptive Honeypot System - Log Analysis Edition

Hệ thống honeypot tích hợp với **Advanced Logging** và **SIEM Stack (ELK)** để phân tích hành vi tấn công theo thời gian thực.

**Phiên bản hiện tại**: Logging + SIEM focus (LLM & RL sẽ sớm được thêm)

## Kiến trúc hệ thống

```
adaptive_honeypot_system/
├── gateway/                    # HAProxy - Advanced logging & routing
├── real_service/              # Services bait (Backend Flask + Frontend React)
├── honeypots/                 # Honeypot API detection
└── observability/             # ELK Stack (Elasticsearch + Kibana + Filebeat)
    ├── elasticsearch/         # Log storage & analysis
    ├── kibana/                # Real-time visualization
    └── filebeat/              # Log collection
```

## Quick Start

```bash
cd adaptive_honeypot_system

# (Optional) Cấu hình
cp .env .env.local
# Chỉnh sửa nếu cần

# Khởi động hệ thống
docker-compose up -d

# Kiểm tra services
docker-compose ps

# Xem logs real-time
docker-compose logs -f gateway
```

## Truy cập dịch vụ

| Dịch vụ | URL | Tài khoản |
|---------|-----|----------|
| Frontend | http://localhost | admin / admin123 |
| HAProxy Stats | http://localhost:8404 | admin / admin |
| Kibana | http://localhost:5601 | - |
| Elasticsearch API | http://localhost:9200 | - |

## Logging Mechanisms

### 1. HAProxy Gateway Logging

**Chi tiết được ghi lại**:
- Client IP:Port
- Request method, path, HTTP version
- Response status code & bytes sent
- Response time (Tr), processing time (Ta)
- Request/Response headers (User-Agent, Cookie, Host, Content-Type)
- Backend server used + health status
- Session ID tracking

**Log format**:
```
192.168.1.100:54321 [10/Apr/2026:14:23:45.123] web_in normal_api/backend 0/0/1/2/3 200 1024 - - ---- 1/1/0/1/0 0/0 {admin|Mozilla/5.0}
```

### 2. Service Logs

**Backend (Flask)**:
- Request routing
- Authentication events
- Database operations
- Tool execution (ping, fetch, markdown)

**Honeypots**:
- Attack pattern detection
- SQL injection attempts
- Command injection attempts
- SSTI detection
- SSRF attempts

### 3. Filebeat Collection

**Thu thập từ**:
- HAProxy stdout/stderr
- Container logs (Docker)
- Application logs
- System logs

## SIEM Analysis (Elasticsearch + Kibana)

### Key Features

✅ **Real-time monitoring**: Logs xuất hiện trong Kibana trong vòng 1-5 giây
✅ **Full-text search**: Tìm kiếm trong tất cả logs bằng Kibana Query Language (KQL)
✅ **Visualization**: Biểu đồ,  timelines, heatmaps
✅ **Alerting** (có thể bật): Cảnh báo khi phát hiện attack patterns
✅ **Log retention**: 30 ngày (cấu hình trong .env)

### Kibana Dashboards

1. **Gateway Overview**
   - Request volume (requests/min)
   - Error rates
   - Response times
   - Top client IPs
   - Top paths/endpoints

2. **Attack Detection**
   - SQL Injection attempts
   - Command + injection attempts
   - SSTI payloads
   - SSRF requests
   - Authentication failures

3. **Service Health**
   - Backend uptime
   - Honeypot responses
   - Failed requests
   - Slow queries

## Data Types Indexed

Elasticsearch indexes logs với các fields:

```json
{
  "@timestamp": "2026-04-10T14:23:45.123Z",
  "client_ip": "192.168.1.100",
  "request_method": "POST",
  "request_path": "/api/auth/login",
  "http_status": 401,
  "response_time_ms": 45,
  "user_agent": "Mozilla/5.0...",
  "host": "localhost",
  "backend_server": "backend:5000",
  "message": "[Full HAProxy log line]",
  "tags": ["haproxy", "gateway"],
  "source": "haproxy-gateway"
}
```

## Common Queries

### Tìm kiếm tất cả SQL injection attempts:
```
message : "union" OR message : "select" OR message : "drop" OR message : "insert"
```

### Lọc requests từ IP cụ thể:
```
client_ip : "192.168.1.100"
```

### Tìm failed logins:
```
request_path : "/api/auth/login" AND http_status : 401
```

### Response time chậm (>500ms):
```
response_time_ms > 500
```

### Thống kê theo endpoint:
```
request_path : * | stats count() by request_path
```

## Performance Considerations

- **Filebeat latency**: ~1-2 giây
- **Elasticsearch indexing**: Realtime (sub-second)
- **Kibana query**: 100K+ logs < 100ms
- **Retention**: 30 ngày (tự động xóa logs cũ)

## Troubleshooting

### Elasticsearch không khởi động
```bash
# Kiểm tra logs
docker-compose logs elasticsearch

# Reset
docker-compose down -v
docker-compose up -d elasticsearch
docker-compose logs -f elasticsearch
```

### Kibana không kết nối Elasticsearch
```bash
# Kiểm tra health
curl http://localhost:9200/_cluster/health

# Restart Kibana
docker-compose restart kibana
```

### Filebeat không gửi logs
```bash
# Kiểm tra config
docker exec adaptive-filebeat filebeat test config

# Kiểm tra connection
docker exec adaptive-filebeat filebeat test output
```

## Next Steps (Tương lai)

1. **Thêm RL Agent**: Adaptive routing dựa trên attack patterns
2. **LLM Integration**: Semantic analysis của attack vectors
3. **Alert Rules**: Automatic notifications
4. **Custom Dashboards**: Business logic visualization
5. **Log Retention Policies**: Archive old logs

---

**Tập trung hiện tại**: Logging infrastructure & SIEM analysis

