# Adaptive Honeypot System

## 1) Tổng quan
Đây là bộ lab local để nghiên cứu adaptive honeypot routing, gồm đầy đủ data plane + control plane.

Kiến trúc hiện tại:
- Data plane: HAProxy gateway với 2 mode normal/honeypot.
- Real service: Flask backend + React frontend.
- Lớp honeypot web: CMDI, SQLI, SSTI, SSRF.
- Control plane: FastAPI routing controller + RL model loading/inference.
- Observability: Filebeat -> Elasticsearch -> Kibana.

Nguyên tắc quan trọng: control plane chạy bất đồng bộ với luồng request, không chen đường đồng bộ vào request path.

## 2) Trạng thái hiện tại
- Đã có route theo mode qua `TEST_HONEYPOT=true|false`.
- Đã có map endpoint -> honeypot trong honeypot mode.
- Đã có route riêng `/api/health` về real backend ở cả 2 mode.
- Đã có dynamic routing theo session và source IP qua HAProxy map.
- Đã có API routing controller (`/health`, `/model/reload`, `/decide`, add/remove route).
- Đã có bộ RL offline + dummy model để test route có tính lặp lại.
- Đã có script test honeypot độc lập (`test_honeypots.py`) + Make target.
- Đã có test split-IP end-to-end (1 IP vào honeypot, 1 IP vào backend thật).

## 3) Chính sách PyTorch (bắt buộc)
- PyTorch chỉ dùng để train RL offline trên máy local.
- Không cài PyTorch trong bất kỳ Docker image runtime nào.
- Không thêm `torch` vào requirements của `routing_controller` hay service runtime.
- File local-only cho train: `adaptive_honeypot_system/control_plane/rl_agent/requirements-local.txt`.

## 4) Cấu trúc thư mục

```text
adaptive_honeypot_system/
|-- Makefile
|-- docker-compose.yml
|-- gateway/
|-- honeypots/
|-- real_service/
|-- observability/
`-- control_plane/
    |-- llm_analyzer/
    |-- rl_agent/
    `-- routing_controller/

test_honeypots.py  (ở root repo)
```

## 5) Hành vi routing

### Chọn mode
- Gateway đọc `TEST_HONEYPOT` trong `.env`:
  - `false` -> `haproxy.normal.cfg`
  - `true` -> `haproxy.honeypot.cfg`

### Normal mode
- Mặc định request vào real backend.
- Session/IP map có thể override backend.

### Honeypot mode
- Mặc định request vào endpoint honeypot.
- Mapping endpoint:
  - `/api/tools/ping` -> CMDI
  - `/api/tools/preview` -> SSTI
  - `/api/tools/fetch` -> SSRF
  - `/api/articles/search` -> SQLI
- `/api/health` luôn vào `health_api` (real backend).

### Dynamic map update
- Session map: `/etc/haproxy/maps/session_routes.map`
- IP map: `/etc/haproxy/maps/ip_honeypot.map`
- Script cập nhật: `gateway/routing_update.sh`

## 6) API control plane
- `GET /health`
- `POST /model/reload`
- `POST /decide`
- `POST /route/session/{session_id}`
- `DELETE /route/session/{session_id}`
- `POST /route/ip/{source_ip}`
- `DELETE /route/ip/{source_ip}`

URL dịch vụ: `http://localhost:8001`

## 7) Chạy nhanh

Lưu ý: toàn bộ lệnh vận hành chạy trong `adaptive_honeypot_system/`.

```bash
cd adaptive_honeypot_system
cp .env.example .env
make up
```

## 8) Lệnh kiểm thử nhanh

```bash
cd adaptive_honeypot_system
docker compose ps -a
curl -s http://localhost:8001/health
curl -s http://localhost:8080/api/health
make test-routes
make test-honeypots
make test-rl-split-ip
```

## 9) Kiểm tra ràng buộc "không torch trong container"

```bash
cd adaptive_honeypot_system
docker compose exec routing_controller python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec backend python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec cmdi_pot python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
```

Kết quả mong đợi: tất cả đều `False`.

## 10) Kết quả xác nhận gần nhất
Lần chạy hợp nhất gần nhất (2026-04-19):
- Container status: PASS
- Routing controller health: PASS
- Gateway `/api/health`: PASS
- `make test-routes`: PASS
- `make test-honeypots`: PASS
- `make test-rl-split-ip`: PASS
  - Client A -> `ssti-honeypot`
  - Client B -> `real-backend`

## 11) Service URLs
- Gateway: `http://localhost:8080`
- Routing controller: `http://localhost:8001`
- HAProxy stats: `http://localhost:8404/stats`
- Kibana: `http://localhost:5601`
- Elasticsearch: `http://localhost:9200`
- Honeypot direct ports:
  - CMDI: `http://localhost:5002`
  - SQLI: `http://localhost:5003`
  - SSTI: `http://localhost:5004`
  - SSRF: `http://localhost:5005`

## 12) Giới hạn hiện tại
- `llm_analyzer` chưa nối đầy đủ vào loop adaptive end-to-end.
- Policy dùng trong split-IP demo là dummy model để test tính ổn định, chưa phải policy production.
- Routing controller hiện vẫn có warning Pydantic namespace (`model_path`) nhưng không ảnh hưởng chức năng.
