# Adaptive Honeypot System

## 1) Tổng quan
Đây là bộ lab local để nghiên cứu adaptive honeypot routing, gồm đầy đủ data plane + control plane.

Kiến trúc hiện tại:
- Data plane: HAProxy gateway với 2 mode normal/honeypot.
- Exposure mode: debug/operator surface hoặc attacker-facing surface.
- Real service: Flask backend + React frontend.
- Lớp honeypot web: CMDI, SQLI, SSTI, SSRF.
- Control plane: FastAPI routing controller + RL model loading/inference + Torch RL agent service để export model artifact.
- AI loop: LLM analyzer đọc log từ Elasticsearch, gọi Groq khi có API key, dựng state runtime hiện tại và gọi controller.
- Observability: Filebeat -> Elasticsearch -> Kibana.

Nguyên tắc quan trọng: control plane chạy bất đồng bộ với luồng request, không chen đường đồng bộ vào request path.

## 2) Trạng thái hiện tại
- Đã có route theo mode qua `TEST_HONEYPOT=true|false`.
- Đã có exposure mode qua `EXPOSURE_MODE=debug|attack`.
- Đã có map endpoint -> honeypot trong honeypot mode.
- Đã có route riêng `/api/health` về real backend ở cả 2 mode.
- Đã có dynamic routing theo session và source IP qua HAProxy map.
- Đã có API routing controller (`/health`, `/decide`, và debug-only `/model/reload`, add/remove route).
- Đã có API inspect route map trong debug mode (`/routes`, `GET /route/session/{sid}`, `GET /route/ip/{ip}`).
- Đã có API/target dọn route map (`DELETE /routes`, `make clear-routes`) để test không để lại trạng thái bẩn.
- Adaptive session/IP routing đã được scope theo đúng API surface: SQLi chỉ ảnh hưởng search, CMDI chỉ ping, SSTI chỉ markdown preview, SSRF chỉ fetch.
- Đã có structured JSON logging cho real backend và honeypots.
- Đã có `POST /api/articles/search` ở real backend để khớp SQLI honeypot contract.
- Đã có `llm_analyzer` service chạy flow bất đồng bộ `log -> state -> decide -> route`.
- Analyzer hiện có Groq integration (`GROQ_API_KEY`, mặc định model `llama-3.3-70b-versatile`) và rule-based fallback khi thiếu key/provider lỗi để Web flow vẫn route được các attack rõ ràng.
- Đã có dummy heuristic RL mode (`RL_POLICY_MODE=heuristic`) để route theo subtype score.
- Đã có bộ RL offline + dummy model để test route có tính lặp lại.
- Đã có `rl_agent` service dùng Torch, chạy debug/attack mode, hỗ trợ predict/debug, export artifact JSON và one-epoch proxy train rất nhỏ. Service này không nằm trên request path và không full train.
- Runtime code đã dùng `rl_state_v2_16` (`STATE_DIM = 16`) trong analyzer, routing controller, RL agent, dummy model và synthetic data generator.
- Đã có script test honeypot độc lập (`test_honeypots.py`) + Make target.
- Đã có test split-IP end-to-end (1 IP vào honeypot, 1 IP vào backend thật).

## 3) Chính sách PyTorch (bắt buộc)
- PyTorch chỉ được dùng ở 2 nơi: train RL offline local và service tách riêng `rl_agent`.
- `routing_controller`, real backend, frontend, honeypots, gateway, analyzer và request path không phụ thuộc Torch.
- Không thêm `torch` vào requirements của `routing_controller`, real service hoặc honeypots.
- `rl_agent` container có Torch một cách chủ động để phục vụ demo RL service/debug/export, nhưng không chặn luồng request attacker.
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
- Các service đọc `EXPOSURE_MODE` trong `.env`:
  - `debug` -> hiện operator endpoints, docs/OpenAPI, detailed health metadata.
  - `attack` -> ẩn service identity, tắt `/routes`, docs/OpenAPI, và HAProxy Stats UI. Endpoint analyzer debug `/analyze` đã bị loại khỏi source hiện tại.

### Normal mode
- Mặc định request vào real backend.
- Session/IP map có thể override backend theo đúng endpoint tương ứng, không override toàn bộ `/api/*`.

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
- Map lưu `sid/source_ip -> backend`, nhưng gateway chỉ áp dụng backend đó trên API surface tương ứng:
  - `sqli_api` -> `/api/articles/search`
  - `cmdi_api` -> `/api/tools/ping`
  - `ssti_api` -> `/api/tools/preview`
  - `ssrf_api` -> `/api/tools/fetch`

## 6) API control plane
- `POST /decide`
- `GET /health`: detailed trong debug mode, generic `{"status":"ok"}` trong attack mode.
- Debug-only: `POST /model/reload`
- Debug-only: `POST|DELETE|GET /route/session/{session_id}`
- Debug-only: `POST|DELETE|GET /route/ip/{source_ip}`
- Debug-only: `GET|DELETE /routes`

URL dịch vụ: `http://localhost:8001`

## 6.1) LLM analyzer
- `GET /health`: detailed trong debug mode, generic trong attack mode.

URL dịch vụ: `http://localhost:8002`

Analyzer hiện poll Elasticsearch (`honeypot-logs-*`), gom session theo `sid`, enrich payload/body từ service logs, gọi Groq để trích xuất semantic features, rồi gọi routing controller bất đồng bộ. Endpoint debug `POST /analyze` đã không còn trong source hiện tại; test/manual injection nên đi qua log pipeline thật.

## 6.2) Torch RL agent
- `GET /health`: detailed trong debug mode, generic trong attack mode.
- Debug-only: `GET /model/info`, `POST /predict`, `POST /export`, `POST /train/one-epoch`.
- Output artifact tương thích controller: `control_plane/rl_agent/artifacts/rl_agent_linear.json`.
- `RL_AGENT_INIT_MODE=web_policy` tạo policy Torch deterministic theo subtype score để giữ flow demo ổn định.
- `POST /train/one-epoch` chỉ chạy một epoch proxy rất nhỏ để chứng minh đường Torch hoạt động; đây không phải full train.

URL dịch vụ: `http://localhost:8003`

## 6.3) RL state schema
Schema runtime hiện tại:
- `rl_state_v2_16`, 16 chiều.
- `protocol` là metadata bắt buộc của `/decide`, không nằm trong tensor; controller dùng nó cho action masking và normalizer profile.
- State chỉ chứa tín hiệu hành vi/semantic đã normalize, đủ mở rộng sang SSH/FTP/SMTP mà không tăng chiều chỉ vì thêm protocol.

```text
0  session_age_norm
1  interaction_rate_norm
2  failed_attempts_norm
3  payload_complexity_norm
4  target_diversity_norm
5  current_route
6  engagement_depth_norm
7  target_sqli_score
8  target_cmdi_score
9  target_ssti_score
10 target_ssrf_score
11 target_credential_attack_score
12 target_enumeration_score
13 evasion_score
14 attack_progression_stage
15 intent_stability_score
```

Metadata `/decide` đi kèm state:

```json
{
  "state_schema": "rl_state_v2_16",
  "protocol": "http",
  "session_id": "sid_demo_001",
  "source_ip": "172.22.0.10",
  "apply_route": true
}
```

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
make mode-debug
curl -s http://localhost:8001/health
curl -s http://localhost:8003/health
curl -s http://localhost:18080/api/health
make test-routes
make test-honeypots
make test-rl-split-ip
make test-adaptive-web
make test-adaptive-attacks
make validate
```

## 9) Kiểm tra ràng buộc Torch trong runtime

```bash
cd adaptive_honeypot_system
docker compose exec routing_controller python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec backend python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec cmdi_pot python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec rl_agent python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
```

Kết quả mong đợi: 3 service request-path đầu là `False`; riêng `rl_agent` là `True`.

## 10) Kết quả xác nhận gần nhất
Lần quét/sanity gần nhất (2026-05-07):
- Python syntax: PASS.
- `docker compose config --quiet`: PASS.
- `git diff --check`: PASS.
- `rl_agent` Docker build/start: PASS (`torch 2.5.1+cpu`).
- RL agent debug endpoints: PASS (`/health`, `/predict`, `/export`, `/train/one-epoch`).
- RL agent attack mode hiding: PASS (`/health` generic, `/predict` và `/docs` trả `404`).
- Controller `RL_POLICY_MODE=model` smoke với artifact do `rl_agent` export: PASS (`ROUTE_SQLI -> sqli_api`).
- Gateway `/api/health`: PASS.
- `make validate`: PASS.
- `make test-rl-split-ip`: PASS.
  - Client A -> `ssti-honeypot`
  - Client B -> `real-backend`
- `make test-adaptive-web`: PASS (`log -> analyzer -> heuristic RL/controller -> HAProxy session route -> SQLI honeypot`).
- `make test-adaptive-attacks`: PASS (`SQLi`, `CMDi`, `SSTI`, `SSRF` route đúng endpoint-scoped honeypot; không tạo route giả `sid="-"`).
- Route maps sau E2E: sạch (`session_routes={}`, `ip_routes={}`).

Frontend local Vite build chưa chạy riêng; frontend Docker container đã start được trong Compose stack.

## 11) Service URLs
- Gateway: `http://localhost:18080`
- Routing controller: `http://localhost:8001` (debug/operator)
- LLM analyzer: `http://localhost:8002` (debug/operator health)
- Torch RL agent: `http://localhost:8003` (debug/operator)
- HAProxy stats: `http://localhost:8404/stats` (debug only)
- Kibana: `http://localhost:5601`
- Elasticsearch: `http://localhost:9200`
- Honeypot direct ports:
  - CMDI: `http://localhost:5002`
  - SQLI: `http://localhost:5003`
  - SSTI: `http://localhost:5004`
  - SSRF: `http://localhost:5005`

## 12) Giới hạn hiện tại
- `llm_analyzer` đã có Groq API integration và rule-based fallback. Phần cần polish tiếp là provider abstraction, retry/backoff, và memory decay.
- Runtime state đã là `rl_state_v2_16`; model artifacts/dataset cũ 24D cần regenerate trước khi dùng `RL_POLICY_MODE=model`.
- `RL_POLICY_MODE=heuristic` và `RL_AGENT_INIT_MODE=web_policy` vẫn là dummy/deterministic cho Web MVP. Train/evaluate RL đầy đủ trên replay buffer thật vẫn là bước nghiên cứu tiếp theo.
- L4 SSH/FTP/SMTP Drop-and-Catch vẫn chưa implement; controller sẽ reject non-HTTP route khi `L4_ROUTING_ENABLED=false`.
- Benchmark nghiên cứu đầy đủ vẫn cần bổ sung sau khi thu được replay buffer/log thật.
