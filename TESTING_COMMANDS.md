# Testing Commands

Tài liệu này gồm các command hay dùng để test service trong lab:

- Frontend qua HAProxy gateway.
- Real backend trong normal mode.
- Honeypots qua direct ports.
- Honeypots qua gateway honeypot mode.
- Adaptive flow: real backend log -> analyzer -> routing controller -> HAProxy route map -> honeypot.

Mặc định chạy command trong thư mục:

```bash
cd adaptive_honeypot_system
```

## 1) Start stack

Copy env nếu chưa có:

```bash
cp .env.example .env
```

Start full stack:

```bash
make up
```

Hoặc start normal-first mode cho adaptive flow:

```bash
TEST_HONEYPOT=false EXPOSURE_MODE=debug RL_POLICY_MODE=heuristic ANALYZER_ENABLED=true docker compose up -d --build
```

Kiểm tra containers:

```bash
docker compose ps
```

Clear route maps trước mỗi lần test:

```bash
make clear-routes
curl -s http://localhost:8001/routes
```

Expected:

```json
{"status":"ok","session_routes":{},"ip_routes":{}}
```

## 2) Traffic mode vs exposure mode

Project hiện có 2 loại mode độc lập:

- `TEST_HONEYPOT=false|true`: traffic mode, quyết định API đi normal-first hay ép qua honeypot theo endpoint.
- `EXPOSURE_MODE=debug|attack`: exposure mode, quyết định có lộ endpoint/metadata phục vụ debug hay không.

Debug mode dùng khi test:

```bash
make mode-debug
curl -s http://localhost:18080/api/health
curl -s http://localhost:8001/routes
curl -s http://localhost:8002/health
curl -s http://localhost:8003/health
```

Attack-facing mode dùng khi demo dưới góc nhìn user/attacker:

```bash
make mode-attack
curl -s http://localhost:18080/api/health
curl -i http://localhost:8001/routes
curl -i http://localhost:8002/docs
```

Expected trong attack mode:

- `/api/health` chỉ trả `{"status":"ok"}`.
- `/routes`, `/route/...`, `/model/reload`, `/docs`, `/openapi.json` trả `404`.
- RL agent debug endpoints như `/predict`, `/export`, `/model/info`, `/train/one-epoch` cũng trả `404`.
- Analyzer debug injection endpoint `/analyze` đã không còn trong source hiện tại; manual test nên đi qua request thật và log pipeline.
- HAProxy Stats UI trên `:8404/stats` bị tắt ở runtime.
- `/decide` vẫn được giữ cho analyzer nội bộ, không dùng như endpoint demo public.

Quay lại debug mode trước khi chạy các test target:

```bash
make mode-debug
```

## 3) Service URLs

- Frontend/Gateway: `http://localhost:18080`
- HAProxy stats: `http://localhost:8404/stats`
- Routing controller: `http://localhost:8001`
- LLM analyzer: `http://localhost:8002`
- Torch RL agent: `http://localhost:8003`
- Elasticsearch: `http://localhost:9200`
- Kibana: `http://localhost:5601`
- CMDI honeypot direct: `http://localhost:5002`
- SQLI honeypot direct: `http://localhost:5003`
- SSTI honeypot direct: `http://localhost:5004`
- SSRF honeypot direct: `http://localhost:5005`

## 4) Quick validation targets

Chạy syntax check + controller health + honeypots + core real routes:

```bash
make mode-debug
make validate
```

Chỉ chạy direct honeypot tests:

```bash
make test-honeypots
```

Chạy adaptive Web MVP flow:

```bash
make test-adaptive-web
```

Chạy split-IP routing test:

```bash
make test-rl-split-ip
```

Export Torch RL artifact dùng cho controller model mode:

```bash
make rl-agent-export
```

Chạy một proxy epoch nhỏ rồi export artifact:

```bash
make rl-agent-one-epoch
```

## 5) Torch RL agent tests

RL agent là service debug/operator riêng, không nằm trên request path.

Health:

```bash
curl -s http://localhost:8003/health
```

Predict HTTP SQLi-like state trong debug mode:

```bash
curl -s -X POST http://localhost:8003/predict \
  -H "Content-Type: application/json" \
  -d '{
    "state_schema": "rl_state_v2_16",
    "protocol": "http",
    "state": [0,0,0,0,0,0,0,0.9,0.05,0.05,0.05,0,0,0.2,0.4,0.8]
  }'
```

Expected:

- `action_name` là `ROUTE_SQLI`.
- `backend` là `sqli_api`.

Export model JSON artifact:

```bash
curl -s -X POST http://localhost:8003/export
ls -l control_plane/rl_agent/artifacts/rl_agent_linear.json
curl -s -X POST http://localhost:8001/model/reload
```

One tiny proxy epoch, không phải full train:

```bash
curl -s -X POST http://localhost:8003/train/one-epoch \
  -H "Content-Type: application/json" \
  -d '{"learning_rate":0.01,"export_after":true}'
```

Attack mode hiding:

```bash
make mode-attack
curl -s http://localhost:8003/health
curl -i -X POST http://localhost:8003/predict \
  -H "Content-Type: application/json" \
  -d '{"state_schema":"rl_state_v2_16","protocol":"http","state":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}'
make mode-debug
```

Expected:

- `/health` chỉ trả `{"status":"ok"}`.
- `/predict` trả `404`.

## 6) Frontend smoke tests

Frontend được phục vụ qua gateway trên port `18080`.

```bash
curl -i http://localhost:18080/
curl -i http://localhost:18080/articles
curl -i http://localhost:18080/tools
curl -i http://localhost:18080/login
```

Expected:

- HTTP `200`.
- `Content-Type: text/html`.

## 7) Real backend tests through gateway

Chuyển gateway sang normal mode:

```bash
make mode-normal
make clear-routes
```

Health:

```bash
curl -s http://localhost:18080/api/health
```

Kết quả mong đợi trong `EXPOSURE_MODE=debug`:

```json
{"service":"real-backend","status":"ok"}
```

Trong `EXPOSURE_MODE=attack`, endpoint này chỉ nên trả:

```json
{"status":"ok"}
```

List articles:

```bash
curl -s "http://localhost:18080/api/articles?page=1&limit=2"
```

Search articles:

```bash
curl -s -X POST "http://localhost:18080/api/articles/search" \
  -H "Content-Type: application/json" \
  -d '{"query":"tcp","page":1,"limit":10}'
```

Article detail:

```bash
curl -s http://localhost:18080/api/articles/1
```

Markdown preview:

```bash
curl -s -X POST "http://localhost:18080/api/tools/preview" \
  -H "Content-Type: application/json" \
  -d '{"content":"# Hello\n\nThis is **Markdown**."}'
```

Ping benign host:

```bash
curl -s -X POST "http://localhost:18080/api/tools/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1","count":2}'
```

Fetch public URL:

```bash
curl -s -X POST "http://localhost:18080/api/tools/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Fetch private URL should be rejected by real service:

```bash
curl -i -X POST "http://localhost:18080/api/tools/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

Expected:

- HTTP `400`.
- Message says private/internal URLs are not supported by real service.

Đăng nhập:

```bash
curl -s -X POST "http://localhost:18080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

Tạo article có bảo vệ:

```bash
TOKEN=$(curl -s -X POST "http://localhost:18080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -s -X POST "http://localhost:18080/api/articles" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Manual Smoke Article","summary":"Smoke summary","content":"Smoke content","category":"General","tags":["smoke"],"read_time":1}'
```

Lưu ý: command trên tạo data trong SQLite volume. Nếu chỉ test nhanh, nên xóa record bằng shell DB riêng hoặc reset volume khi cần.

## 8) Honeypot direct-port tests

Direct ports bỏ qua HAProxy, dùng để test từng honeypot riêng.

Health:

```bash
curl -s http://localhost:5002/api/health
curl -s http://localhost:5003/api/health
curl -s http://localhost:5004/api/health
curl -s http://localhost:5005/api/health
```

Service mong đợi trong `EXPOSURE_MODE=debug`:

- Port `5002` -> `cmdi-honeypot`
- Port `5003` -> `sqli-honeypot`
- Port `5004` -> `ssti-honeypot`
- Port `5005` -> `ssrf-honeypot`

Trong `EXPOSURE_MODE=attack`, các health endpoint direct-port cũng chỉ trả `{"status":"ok"}`.

CMDI:

```bash
curl -i -X POST "http://localhost:5002/api/tools/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"8.8.8.8;id"}'
```

Kết quả mong đợi:

- HTTP `200`.
- Body `output` contains `uid=33` or `www-data`.

SQLI:

```bash
curl -i -X POST "http://localhost:5003/api/articles/search" \
  -H "Content-Type: application/json" \
  -d '{"query":"union select password from users"}'
```

Expected:

- HTTP `500`.
- Body contains `"error":"DatabaseError"`.

SSTI:

```bash
curl -i -X POST "http://localhost:5004/api/tools/preview" \
  -H "Content-Type: application/json" \
  -d '{"content":"{{7*7}}"}'
```

Expected:

- HTTP `200`.
- Body contains `"rendered":"49"`.

SSRF:

```bash
curl -i -X POST "http://localhost:5005/api/tools/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

Expected:

- HTTP `200`.
- Body `content` contains fake cloud metadata such as `instanceId`.

## 9) Honeypot mode through gateway

Honeypot mode route API traffic qua HAProxy endpoint mapping:

- `/api/tools/ping` -> CMDI honeypot.
- `/api/articles/search` -> SQLI honeypot.
- `/api/tools/preview` -> SSTI honeypot.
- `/api/tools/fetch` -> SSRF honeypot.
- `/api/health` vẫn đi real backend; response chi tiết hay generic phụ thuộc `EXPOSURE_MODE`.

Chuyển sang honeypot mode:

```bash
make mode-honeypot
make clear-routes
```

Health vẫn là real backend:

```bash
curl -s http://localhost:18080/api/health
```

Expected trong `EXPOSURE_MODE=debug`:

```json
{"service":"real-backend","status":"ok"}
```

CMDI via gateway:

```bash
curl -i -X POST "http://localhost:18080/api/tools/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"8.8.8.8;id"}'
```

SQLI via gateway:

```bash
curl -i -X POST "http://localhost:18080/api/articles/search" \
  -H "Content-Type: application/json" \
  -d '{"query":"union select password from users"}'
```

SSTI via gateway:

```bash
curl -i -X POST "http://localhost:18080/api/tools/preview" \
  -H "Content-Type: application/json" \
  -d '{"content":"{{7*7}}"}'
```

SSRF via gateway:

```bash
curl -i -X POST "http://localhost:18080/api/tools/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

Quay lại normal mode sau phần này:

```bash
make mode-normal
make clear-routes
```

## 10) Adaptive flow manual test

Phần này kiểm tra main project flow:

```text
real backend -> structured log -> Filebeat/Elasticsearch -> LLM analyzer
-> routing controller -> HAProxy session map -> honeypot
```

Khởi động normal-first stack:

```bash
TEST_HONEYPOT=false EXPOSURE_MODE=debug RL_POLICY_MODE=heuristic ANALYZER_ENABLED=true docker compose up -d --build
make clear-routes
```

Kiểm tra control plane trong debug mode:

```bash
curl -s http://localhost:8001/health
curl -s http://localhost:8002/health
curl -s http://localhost:8001/routes
```

Tạo session ID:

```bash
SID=manual_$(date +%s)
echo "$SID"
```

Gửi request SQLi đầu tiên tới real backend path:

```bash
curl -s -X POST "http://localhost:18080/api/articles/search" \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=$SID" \
  -d '{"query":"union select password from users"}'
```

Request đầu tiên dự kiến sẽ đi tới real backend. Analyzer chạy bất đồng bộ.

Lưu ý: code hiện tại gọi Groq khi có `GROQ_API_KEY`. Nếu thiếu key hoặc provider timeout, analyzer dùng rule-based fallback để các SQLi/CMDI/SSTI/SSRF rõ ràng vẫn có thể route.

Kiểm tra session route:

```bash
curl -s "http://localhost:8001/route/session/$SID"
```

Lặp lại cho đến khi hiển thị:

```json
{"backend":"sqli_api","found":true}
```

Gửi request thứ hai với cùng `sid`:

```bash
curl -i -X POST "http://localhost:18080/api/articles/search" \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=$SID" \
  -d '{"query":"union select password from users"}'
```

Kết quả mong đợi:

- HTTP `500`.
- Body contains `"DatabaseError"`.
- Điều này có nghĩa request thứ hai đã được route tới SQLI honeypot.
- Cùng `sid`, các API không phải search như markdown preview, ping, fetch vẫn đi real service trong normal-first mode.

Cleanup:

```bash
make clear-routes
curl -s http://localhost:8001/routes
```

## 11) Logs while testing

All logs:

```bash
docker compose logs -f
```

Gateway:

```bash
docker compose logs -f gateway
```

Real backend:

```bash
docker compose logs -f backend
```

All honeypots:

```bash
docker compose logs -f cmdi_pot sqli_pot ssti_pot ssrf_pot
```

Analyzer + routing controller:

```bash
make logs-analyzer
```

Torch RL agent:

```bash
make logs-rl-agent
```

SIEM stack:

```bash
make logs-siem
```

Log gần đây không follow:

```bash
docker compose logs --tail=80 backend
docker compose logs --tail=80 gateway
docker compose logs --tail=80 llm_analyzer routing_controller
docker compose logs --tail=80 cmdi_pot sqli_pot ssti_pot ssrf_pot
```

## 12) Elasticsearch checks

List indices:

```bash
curl -s "http://localhost:9200/_cat/indices/honeypot-logs-*?v"
```

Tìm docs gần đây:

```bash
curl -s -X POST "http://localhost:9200/honeypot-logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 5,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {"match_all": {}}
  }'
```

Tìm route decisions:

```bash
curl -s -X POST "http://localhost:9200/honeypot-logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 10,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {
      "query_string": {
        "query": "route_decision OR llm_route_decision"
      }
    }
  }'
```

## 13) Common cleanup

Clear adaptive routes:

```bash
make clear-routes
```

Đưa gateway về normal mode:

```bash
make mode-normal
```

Dừng stack:

```bash
make down
```

Stop và xóa volumes khi bạn chủ động muốn trạng thái database/log mới:

```bash
docker compose down -v
```

Cảnh báo: `down -v` xóa Docker volumes, bao gồm dữ liệu SQLite của backend và dữ liệu Elasticsearch.

## 14) Expected demo sequence

Để demo thủ công sạch:

```bash
cd adaptive_honeypot_system
TEST_HONEYPOT=false EXPOSURE_MODE=debug RL_POLICY_MODE=heuristic ANALYZER_ENABLED=true docker compose up -d --build
make clear-routes
curl -s http://localhost:18080/api/health
make validate
make test-adaptive-web
curl -s http://localhost:8001/routes
```

Route map cuối cùng mong đợi:

```json
{"status":"ok","session_routes":{},"ip_routes":{}}
```

Khi chuyen sang demo attacker-facing:

```bash
make mode-normal
make mode-attack
curl -s http://localhost:18080/api/health
curl -i http://localhost:8001/routes
```
