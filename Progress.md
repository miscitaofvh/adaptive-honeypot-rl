# Báo cáo tiến độ

Cập nhật: 2026-04-15

## 1) Tiến độ hiện tại

Tổng quan hiện tại: Data plane đã chạy ổn cho demo web honeypot. Control plane và RL tạm xem như chưa triển khai end-to-end.

### Đã hoàn thành (ngoại trừ control plane và RL)

- [x] Gateway (HAProxy) đã route được 2 mode:
  - normal mode -> API vào real backend
  - honeypot mode -> API vào honeypot theo endpoint
- [x] Routing honeypot theo endpoint trong honeypot mode:
  - /api/tools/ping -> CMDI
  - /api/tools/preview -> SSTI
  - /api/tools/fetch -> SSRF
  - /api/articles/search -> SQLI
- [x] Đã tách riêng route /api/health trong honeypot mode để không rơi vào mặc định CMDI:
  - /api/health -> health_api -> real backend
- [x] Session map steering hoạt động runtime:
  - add/remove sid -> backend route qua script routing_update.sh
  - đã fix runtime command add map + set map
- [x] Real service (backend + frontend) chạy ổn qua gateway port 8080
- [x] 4 web honeypot chạy được và phản hồi đúng mục tiêu quan sát hành vi tấn công
- [x] Smoke tests đã pass:
  - make test-routes
  - python test_honeypots.py -> ALL TESTS PASSED

### Cập nhật phần observability

- [x] Đã sửa healthcheck Filebeat để tương thích strict permissions:
  - dùng filebeat test config -strict.perms=false
- [x] Đã chuyển input sang filestream + ndjson parser để đọc Docker JSON log ổn định
- [x] Đã parse json.log thành field chuẩn app.* để query trên Kibana:
  - app.service
  - app.path
  - app.pot_type
  - app.status_code
- [x] Đã thêm lọc log theo container.name và fallback theo container.id/log.file.path để loại log không cần thiết (elasticsearch, kibana, frontend, filebeat)

### Cơ bản đã sẵn sàng

- Gateway URL: http://localhost:8080
- HAProxy stats: http://localhost:8404/stats
- Direct honeypots:
  - CMDI: http://localhost:5002
  - SQLI: http://localhost:5003
  - SSTI: http://localhost:5004
  - SSRF: http://localhost:5005
- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200

---

## 2) Cách chuyển qua lại giữa normal service và honeypot

Thực hiện trong thư mục adaptive_honeypot_system.

### Cách nhanh (khuyến nghị)

```bash
cd adaptive_honeypot_system
make mode-normal
make mode-honeypot
make mode-show
```

- mode-normal: set TEST_HONEYPOT=false và restart gateway
- mode-honeypot: set TEST_HONEYPOT=true và restart gateway

### Cách bằng tay

1. Sửa file .env

```env
TEST_HONEYPOT=false
# hoặc
TEST_HONEYPOT=true
```

2. Apply config mới cho gateway

```bash
cd adaptive_honeypot_system
docker compose up -d --no-deps --build gateway
```

3. Kiểm tra nhanh

```bash
curl -s http://localhost:8080/api/health
```

Lưu ý:
- Sau cập nhật mới, /api/health được route riêng về real backend trong honeypot mode.
- Các endpoint tấn công vẫn route vào honeypot theo mapping endpoint.

---

## 3) Cách test honeypot bằng tay

### 3.1 Test bằng trình duyệt

1. Chạy hệ thống:

```bash
cd adaptive_honeypot_system
docker compose up -d --build
make mode-honeypot
```

2. Mở giao diện:
- http://localhost:8080

3. Vào các trang có gọi API tools/search, thử payload như sau:
- CMDI: 8.8.8.8;id
- SSTI: {{7*7}}
- SSRF: http://169.254.169.254/latest/meta-data/
- SQLI: union select password from users

4. Mở DevTools -> Network để xem request/response.

### 3.2 Test bằng curl

#### CMDI

```bash
curl -s -X POST http://localhost:8080/api/tools/ping \
  -H 'Content-Type: application/json' \
  -d '{"host":"8.8.8.8;id"}'
```

Dấu hiệu mong đợi (honeypot mode): response có output giả lập command execution.

#### SSTI

```bash
curl -s -X POST http://localhost:8080/api/tools/preview \
  -H 'Content-Type: application/json' \
  -d '{"content":"{{7*7}}"}'
```

Dấu hiệu mong đợi: rendered có giá trị tính toán (ví dụ 49).

#### SSRF

```bash
curl -s -X POST http://localhost:8080/api/tools/fetch \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

Dấu hiệu mong đợi: response trả về fake metadata.

#### SQLI

```bash
curl -s -X POST http://localhost:8080/api/articles/search \
  -H 'Content-Type: application/json' \
  -d '{"query":"union select password from users"}'
```

Dấu hiệu mong đợi: lỗi SQL giả lập (status 500 với payload tấn công đặc trưng).

#### Theo dõi log route

```bash
cd adaptive_honeypot_system
docker compose logs -f gateway
```

Bạn sẽ thấy backend được chọn (cmdi/ssti/ssrf/sqli hoặc health_api/backend).

### 3.3 Test bằng Burp Suite

Lưu ý quan trọng: app đang dùng port 8080, Burp default cũng 8080; để tránh xung đột, dùng Burp listener 8081.

1. Burp Proxy Listener:
- 127.0.0.1:8081

2. Trình duyệt proxy:
- HTTP proxy -> 127.0.0.1:8081

3. Truy cập URL đích:
- http://localhost:8080

4. Intercept request API, chỉnh payload và Forward.

5. Gợi ý payload để thử nhanh:
- POST /api/tools/ping body {"host":"8.8.8.8;id"}
- POST /api/tools/preview body {"content":"{{7*7}}"}
- POST /api/tools/fetch body {"url":"http://169.254.169.254/latest/meta-data/"}
- POST /api/articles/search body {"query":"union select password from users"}

6. Dùng Repeater để lặp lại và so sánh response theo mode normal/honeypot.

---

## 4) TODO (tạm coi control plane và RL chưa làm)

Mặc định trong plan hiện tại: control_plane và RL chưa có implementation hoàn chỉnh chạy thực tế end-to-end.

### Control Plane TODO

- [ ] Định nghĩa workflow đọc logs từ Elasticsearch theo cửa sổ thời gian
- [ ] Hoàn thiện llm_analyzer (prompting, parsing output, confidence handling)
- [ ] Hoàn thiện state_builder để tạo state vector nhất quán
- [ ] Xây dựng routing_controller API đầy đủ:
  - nhận decision
  - ghi map route
  - audit log route history
- [ ] Nối control_plane vào docker-compose để run chung stack

### RL TODO

- [ ] Chốt state/action/reward schema cho web scope
- [ ] Tạo dữ liệu offline (trajectories) từ logs + labels
- [ ] Train và evaluate model offline
- [ ] Lưu/nạp model weights cho inference
- [ ] Nối RL inference vào routing_controller
- [ ] Thêm guardrails để tránh false positive cao

### Validation TODO

- [ ] Viết integration test cho control-plane loop:
  - log ingest -> LLM/state -> RL action -> route update
- [ ] Viết benchmark cơ bản:
  - route accuracy
  - false reroute rate
  - engagement after reroute
- [ ] Chốt báo cáo so sánh baseline rule-based vs adaptive policy

### Observability TODO nhỏ (phần còn lại)

- [ ] Tự động hóa danh sách container loại trừ theo tên thay vì phụ thuộc fallback id/path tĩnh khi container được recreate
- [ ] Tạo dashboard Kibana chuẩn cho các field app.service, app.path, app.pot_type, app.status_code

---

## 5) Ghi chú nhanh

- Scope hiện tại đang ưu tiên data plane demo và manual validation.
- Nếu bắt đầu phase control plane + RL, nên tách milestone nhỏ và chốt contract JSON giữa các module trước.
