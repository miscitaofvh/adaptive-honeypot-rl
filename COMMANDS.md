# Command Reference

Các lệnh dưới đây chạy trong thư mục:

```bash
cd adaptive_honeypot_system
```

## Deploy

```bash
cp .env.example .env
make up
docker compose ps
make health
```

URLs:

```text
Web app / gateway:   http://localhost:18080
Routing controller:  http://localhost:8001
LLM analyzer:        http://localhost:8002
Kibana debug UI:     http://localhost:5601
```

## Demo Modes

```bash
make mode-normal   # adaptive flow: first request real service, later requests may be routed
make mode-attack   # attacker-facing mode: hide debug endpoints/metadata
make mode-debug    # operator mode: enable /routes, /model/reload, detailed health
make clear-routes  # clear old session routes before demo/test
```

Recommended demo setup:

```bash
make mode-debug
make mode-normal
make clear-routes
```

Before attacker-facing presentation:

```bash
make mode-attack
```

## Attacker-View Manual Test

SQLi adaptive route:

```bash
SID="demo_sqli_$(date +%s)"

curl -s -X POST http://localhost:18080/api/articles/search \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"query":"union select password from users"}'

sleep 8

curl -i -s -X POST http://localhost:18080/api/articles/search \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"query":"union select password from users"}'
```

Expected second response: fake SQL error from SQLi honeypot.

SSTI adaptive route:

```bash
SID="demo_ssti_$(date +%s)"

curl -s -X POST http://localhost:18080/api/tools/preview \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"content":"# Hello\n\nType some **Markdown** here.\n\n```python\nprint(\"hello\")\n```\n\n{{7*7}}"}'

sleep 8

curl -s -X POST http://localhost:18080/api/tools/preview \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"content":"# Hello\n\nType some **Markdown** here.\n\n```python\nprint(\"hello\")\n```\n\n{{7*7}}"}' | python -m json.tool
```

Expected second response: markdown HTML is still rendered and `{{7*7}}` becomes `49`.

Normal-service continuity check in same browser/session:

```bash
curl -s -X POST http://localhost:18080/api/tools/ping \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=${SID}" \
  -d '{"host":"8.8.8.8; id"}' | python -m json.tool
```

Expected: non-target API surface does not break because routing is endpoint-scoped.

## Automated Tests

```bash
make mode-debug
make mode-normal
make clear-routes
make validate PYTHON=../.venv/bin/python
make test-adaptive-attacks PYTHON=../.venv/bin/python
make test-adaptive-web PYTHON=../.venv/bin/python
```

Expected:

- `make validate`: syntax, direct honeypots, and core real routes pass.
- `make test-adaptive-attacks`: SQLi/CMDi/SSTI/SSRF route to matching honeypots.
- `make test-adaptive-web`: route is endpoint-scoped; unrelated APIs stay on real service.

## Operator Debug

Route maps are debug-only:

```bash
make mode-debug
curl -s http://localhost:8001/routes | python -m json.tool
curl -s "http://localhost:8001/route/session/${SID}" | python -m json.tool
```

Reload tracked RL model:

```bash
curl -s -X POST http://localhost:8001/model/reload | python -m json.tool
```

Direct model decision smoke test:

```bash
curl -s -X POST http://localhost:8001/decide \
  -H "Content-Type: application/json" \
  -d '{"state_schema":"web_state","protocol":"http","apply_route":false,"state":[0.0003,0.6,0.0,0.449,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.035,0.175]}' \
  | python -m json.tool
```

Expected: `KEEP_NORMAL`.

## Logs

Routing controller + analyzer container logs:

```bash
make logs-analyzer
```

Gateway logs:

```bash
make logs-gateway
```

Host-mounted analyzer decisions:

```bash
tail -f logs/llm_analyzer/llm_fields.jsonl
```

Host-mounted service/honeypot request logs:

```bash
tail -f logs/real_backend/service_requests.jsonl
tail -f logs/honeypots/sqli/service_requests.jsonl
tail -f logs/honeypots/cmdi/service_requests.jsonl
tail -f logs/honeypots/ssti/service_requests.jsonl
tail -f logs/honeypots/ssrf/service_requests.jsonl
```

Useful fields in `logs/llm_analyzer/llm_fields.jsonl`:

```text
session_id
attack_type
target_scores
state
action_name
backend
route_applied
route_correct_by_semantic_label
controller_roundtrip_ms
event_to_decision_latency_ms
```

## Metrics Report

```bash
make evaluate-metrics PYTHON=../.venv/bin/python
cat logs/metrics_report.json | python -m json.tool
```

Metrics covered:

```text
honeypot_engagement_rate
avg_requests_after_adaptive_rerouting
session_length_seconds
correct_honeypot_routing_rate
false_rerouting_rate_on_benign_sessions
normal_service_continuity_rate
```

For a clean report, archive or remove `logs/**/*.jsonl`, rerun the demo/tests, then run `make evaluate-metrics`.

## RL Training Reference

The trained runtime model is already tracked:

```text
control_plane/rl_agent/artifacts/rl_agent_linear.json
control_plane/rl_agent/artifacts/rl_agent_linear.metrics.json
```

Training commands, parameters, and validation report fields are in:

```text
control_plane/RL_TRAINING_SUMMARY.md
```

## Shutdown

```bash
make clear-routes
make down
```
