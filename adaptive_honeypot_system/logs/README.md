# Host-Mounted Debug Logs

Thư mục này nhận JSONL logs được ghi trực tiếp từ service container ra host.
Nguồn này độc lập với Filebeat/Elasticsearch/HAProxy proxy logs.

Các file chính sau khi chạy Docker Compose:

```text
logs/real_backend/service_requests.jsonl
logs/honeypots/cmdi/service_requests.jsonl
logs/honeypots/sqli/service_requests.jsonl
logs/honeypots/ssti/service_requests.jsonl
logs/honeypots/ssrf/service_requests.jsonl
logs/llm_analyzer/llm_fields.jsonl
```

Ý nghĩa:

- `service_requests.jsonl`: structured request logs từ real backend hoặc honeypot service, gồm method/path/session/body preview/status/duration.
- `llm_fields.jsonl`: các event/field do LLM analyzer xuất ra, gồm LLM fallback/response, state vector, target scores, selected action/backend và controller response.

Các field phục vụ evaluation metric:

```text
session_id
ts
service_role
is_honeypot
observed_backend
api_surface
expected_honeypot_backend
route_matches_api_surface
status_code
status_class
duration_ms
```

`route_matches_api_surface` chỉ có ý nghĩa với `service_role=honeypot`; real service ghi `null` để tránh trộn nhầm vào metric correct-routing.

Các field riêng của `llm_fields.jsonl`:

```text
decision_id
attack_type
target_scores
expected_backend_by_semantic_label
backend
route_correct_by_semantic_label
route_applied
analysis_duration_ms
controller_roundtrip_ms
event_to_decision_latency_ms
```

Mapping metric trong proposal:

- Honeypot engagement rate: đếm session/request có `is_honeypot=true` sau `route_applied=true`.
- Avg requests after adaptive rerouting: đếm `service_requests.jsonl` theo `session_id` sau decision timestamp.
- Session length: max/min `ts` theo `session_id`.
- Correct honeypot routing rate: `route_correct_by_semantic_label` ở analyzer kết hợp `route_matches_api_surface` ở honeypot logs.
- False rerouting rate trên benign sessions: analyzer `is_attack_window=false` nhưng service log sau đó có `is_honeypot=true`.
- Normal-service continuity rate: mọi follow-up API surface không phải target của honeypot route tiếp tục có `service_role=real_service`, kể cả các API bình thường không có `expected_honeypot_backend`.

Bật/tắt bằng `.env`:

```text
HOST_DEBUG_LOG_ENABLED=true
```

Ví dụ xem nhanh:

```bash
tail -f logs/real_backend/service_requests.jsonl
tail -f logs/llm_analyzer/llm_fields.jsonl
```

Sinh report metric:

```bash
make evaluate-metrics
cat logs/metrics_report.json | python -m json.tool
```
