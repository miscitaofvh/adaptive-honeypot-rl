# Command Reference

Chạy các lệnh trong thư mục:

```bash
cd adaptive_honeypot_system
```

## Start And Health

```bash
cp .env.example .env
make up
docker compose ps
make health
```

URLs chính:

```text
Gateway/frontend:    http://localhost:18080
Routing controller:  http://localhost:8001
LLM analyzer:        http://localhost:8002
Elasticsearch:       http://localhost:9200
Kibana debug UI:     http://localhost:5601
```

## Modes

```bash
make mode-debug     # operator endpoints/metadata visible
make mode-attack    # attacker-facing demo, debug endpoints hidden
make mode-normal    # normal-first adaptive flow
make mode-honeypot  # direct endpoint-to-honeypot test mode
make mode-show
```

Important:

- Adaptive demo chính dùng `make mode-normal`.
- `make mode-honeypot` chỉ dùng để test honeypot contract nhanh.
- Debug endpoints như `/routes`, `/model/reload`, OpenAPI docs chỉ dùng trong debug mode.

## Logs

Container logs:

```bash
make logs-gateway
make logs-analyzer
make logs-honeypots
make logs-ingest
```

Host-mounted logs:

```bash
tail -f logs/llm_analyzer/llm_fields.jsonl
tail -f logs/real_backend/service_requests.jsonl
tail -f logs/honeypots/sqli/service_requests.jsonl
tail -f logs/honeypots/cmdi/service_requests.jsonl
tail -f logs/honeypots/ssti/service_requests.jsonl
tail -f logs/honeypots/ssrf/service_requests.jsonl
```

## Route Maps

```bash
make clear-routes
curl -s http://localhost:8001/routes | python -m json.tool
```

Manually route one session:

```bash
curl -s -X POST "http://localhost:8001/route/session/demo_sqli?backend=sqli_api" | python -m json.tool
curl -s -X POST "http://localhost:8001/route/session/demo_ssti?backend=ssti_api" | python -m json.tool
curl -s -X POST "http://localhost:8001/route/session/demo_cmdi?backend=cmdi_api" | python -m json.tool
curl -s -X POST "http://localhost:8001/route/session/demo_ssrf?backend=ssrf_api" | python -m json.tool
```

## Smoke Tests

```bash
make mode-debug
make mode-normal
make clear-routes
make validate PYTHON=../.venv/bin/python
make test-adaptive-web
make test-adaptive-attacks
make test-rl-split-ip
```

Expected:

- `make validate`: syntax + direct honeypots + core real routes pass.
- `make test-adaptive-attacks`: SQLi/CMDi/SSTI/SSRF route đúng honeypot, API surface khác không bị hỏng.
- Route maps cuối test rỗng.

## Manual Adaptive Test

SQLi:

```bash
make mode-debug
make mode-normal
make clear-routes

SID="manual_sqli_$(date +%s)"

curl -s -X POST http://localhost:18080/api/articles/search \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"query":"union select password from users"}'

sleep 8

curl -s "http://localhost:8001/route/session/${SID}" | python -m json.tool

curl -i -s -X POST http://localhost:18080/api/articles/search \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"query":"union select password from users"}'
```

SSTI markdown contract:

```bash
SID="manual_ssti_$(date +%s)"

curl -s -X POST http://localhost:18080/api/tools/preview \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"content":"# Hello\n\nType some **Markdown** here.\n\n```python\nprint(\"hello\")\n```\n\n{{7*7}}"}'

sleep 8

curl -s "http://localhost:8001/route/session/${SID}" | python -m json.tool

curl -s -X POST http://localhost:18080/api/tools/preview \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"content":"# Hello\n\nType some **Markdown** here.\n\n```python\nprint(\"hello\")\n```\n\n{{7*7}}"}' | python -m json.tool
```

Expected SSTI output vẫn có markdown HTML và `49`.

## Direct `/decide` Test

```bash
curl -s -X POST http://localhost:8001/decide \
  -H "Content-Type: application/json" \
  -d '{
    "state_schema": "web_state",
    "protocol": "http",
    "session_id": "direct_sqli",
    "apply_route": false,
    "state": [0.0,0.2,0.0,0.67,1.0,0.0,0.0,0.9,0.05,0.05,0.05,0,0,0.15,0.35,0.39]
  }' | python -m json.tool
```

Expected: `ROUTE_SQLI -> sqli_api`.

## Replay Buffer

Generate Web traffic and export replay buffer:

```bash
make generate-replay-buffer PYTHON=../.venv/bin/python
RL_REPLAY_SESSIONS=80 make generate-replay-buffer PYTHON=../.venv/bin/python
```

Export from existing runtime logs:

```bash
make export-replay-buffer PYTHON=../.venv/bin/python
```

Inspect:

```bash
wc -l control_plane/rl_agent/data/replay_buffer.jsonl
head -1 control_plane/rl_agent/data/replay_buffer.jsonl | python -m json.tool
```

## RL Training

PyTorch chỉ cần trong local/VM venv:

```bash
../.venv/bin/python -c "import torch; print(torch.__version__)"
```

Generate synthetic data:

```bash
make gen-fake-data PYTHON=../.venv/bin/python
```

Short smoke train:

```bash
make gen-fake-data PYTHON=../.venv/bin/python RL_SYNTHETIC_SESSIONS=200 RL_SYNTHETIC_MIN_STEPS=3 RL_SYNTHETIC_MAX_STEPS=5
make train-rl PYTHON=../.venv/bin/python RL_EPOCHS=5 RL_LOG_EVERY=1
```

Train from replay buffer:

```bash
make train-rl-replay PYTHON=../.venv/bin/python
```

Reload model:

```bash
docker compose up -d --force-recreate routing_controller llm_analyzer
curl -s -X POST http://localhost:8001/model/reload | python -m json.tool
```

## Metrics

```bash
make evaluate-metrics PYTHON=../.venv/bin/python
cat logs/metrics_report.json | python -m json.tool
```

Metrics:

- Honeypot engagement rate.
- Avg requests after adaptive rerouting.
- Session length.
- Correct honeypot routing rate.
- False rerouting rate on benign sessions.
- Normal-service continuity rate.

Nếu muốn report sạch, archive hoặc xóa `logs/**/*.jsonl`, chạy lại test/demo, rồi evaluate lại.

## Cleanup

```bash
make clear-routes
make down
```
