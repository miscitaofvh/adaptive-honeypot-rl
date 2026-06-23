# Adaptive Honeypot Web Routing

Đồ án này là lab Web-only để tăng attacker engagement bằng adaptive honeypot routing. Hệ thống quan sát request, suy luận intent bằng LLM analyzer hoặc rule fallback, dùng RL policy chọn honeypot phù hợp, rồi route các request tiếp theo trong cùng session sang honeypot đúng loại.

Lệnh vận hành/test/train nằm trong [COMMANDS.md](COMMANDS.md). Tóm tắt train RL nằm trong [RL_TRAINING_SUMMARY.md](adaptive_honeypot_system/control_plane/RL_TRAINING_SUMMARY.md). Proposal học thuật nằm trong [proposal.md](proposal.md). Plan còn lại nằm trong [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Scope

Đang làm:

- Real Web service: React frontend + Flask backend.
- Web honeypots: SQLi, SSTI, CMDi, SSRF.
- HAProxy gateway route theo cookie `sid`.
- LLM analyzer đọc logs, enrich body, build state.
- Routing controller gọi RL model JSON và cập nhật HAProxy maps.
- Offline RL training bằng torch/CQL; runtime dùng model JSON đã export.
- Replay buffer exporter và metric evaluator từ host-mounted logs.

Không làm trong phạm vi hiện tại:

- SSH/FTP/SMTP.
- L4 Drop-and-Catch.
- Xây dashboard monitoring mới như một deliverable. Kibana vẫn có trong stack để debug Elasticsearch logs khi cần.
- Bảo vệ/chặn real service. Mục tiêu là route đúng honeypot và kéo dài engagement.

## Runtime Flow

```text
Browser/request with sid cookie
  -> HAProxy gateway
  -> real backend first, or endpoint-scoped honeypot if route exists
  -> service/honeypot logs + Elasticsearch
  -> llm_analyzer builds session context and web_state
  -> routing_controller /decide
  -> RL model selects action/backend
  -> gateway/routing_update.sh updates HAProxy session route map
  -> follow-up requests with same sid use adaptive route
```

Routing được scope theo API surface, không route toàn bộ session vào một honeypot:

```text
/api/articles/search -> sqli_api
/api/tools/preview   -> ssti_api
/api/tools/ping      -> cmdi_api
/api/tools/fetch     -> ssrf_api
```

Ví dụ session bị route `ssti_api` thì chỉ markdown preview đi SSTI honeypot; search/ping/fetch không liên quan vẫn đi real backend.

## Components

```text
adaptive_honeypot_system/
  gateway/                         HAProxy config + runtime map update script
  real_service/                    React frontend + Flask backend
  honeypots/                       SQLi/SSTI/CMDi/SSRF Flask honeypots
  observability/                   Filebeat + Elasticsearch + optional Kibana debug UI
  logs/                            host-mounted debug/evaluation logs
  control_plane/
    llm_analyzer/analyzer.py       log polling, body enrichment, semantic extraction
    routing_controller/main.py     /decide, model load, HAProxy map updates
    state_builder/state_schema.py  runtime state definition
    rl_agent/                      JSON runtime agent + torch offline training
    replay_buffer/                 replay export, Web traffic generation, metrics
```

## State And Actions

Runtime state schema:

```text
STATE_SCHEMA_VERSION = web_state
STATE_DIM = 16
```

Field order:

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

Action space:

```text
0 KEEP_NORMAL -> normal_api
1 ROUTE_SQLI  -> sqli_api
2 ROUTE_SSTI  -> ssti_api
3 ROUTE_CMDI  -> cmdi_api
4 ROUTE_SSRF  -> ssrf_api
```

`protocol` là metadata của `/decide`, không nằm trong tensor. Runtime hiện chỉ chấp nhận `http`.

## Logs And Metrics

Host-mounted logs:

```text
adaptive_honeypot_system/logs/llm_analyzer/llm_fields.jsonl
adaptive_honeypot_system/logs/real_backend/service_requests.jsonl
adaptive_honeypot_system/logs/honeypots/*/service_requests.jsonl
```

Các metric trong proposal hiện có đủ field để tính:

- Honeypot engagement rate.
- Avg requests after adaptive rerouting.
- Session length.
- Correct honeypot routing rate.
- False rerouting rate on benign sessions.
- Normal-service continuity rate.

`evaluate_metrics.py` đọc host logs, không cần đưa các field evaluation này vào RL state.

## Current Status

Đã hoàn thành:

- Full Web stack chạy qua Docker Compose.
- Debug/attack exposure mode.
- Endpoint-scoped adaptive routing.
- Real backend và honeypots có API contract tương thích.
- LLM analyzer có Groq path và deterministic rule fallback.
- Routing controller dùng trained JSON model, runtime không phụ thuộc torch.
- Offline RL model CQL được train/tune từ một training dataset thống nhất, được build từ generated transitions và replay transitions.
- Replay buffer generator/exporter.
- Metric evaluator từ host logs.
- Current model artifact đã được track tại `adaptive_honeypot_system/control_plane/rl_agent/artifacts/rl_agent_linear.json`.

Còn lại:

- Viết báo cáo kết quả dựa trên `logs/metrics_report.json`.
- Nếu cần cải thiện kết quả báo cáo, chạy thêm batch replay sạch rồi evaluate lại.
- Nếu dùng Groq thật khi demo dài, polish retry/backoff và memory decay.

## Important Notes

- Adaptive demo nên chạy `TEST_HONEYPOT=false`: request đầu tiên đi real backend, analyzer quyết định route cho request sau.
- `EXPOSURE_MODE=attack` ẩn debug endpoints và health metadata.
- `make clear-routes` trước demo/test để tránh route cũ làm nhiễu kết quả.
- PyTorch chỉ dùng trong local/VM training. Request path Docker runtime không cần torch.
- `.env` local không nên commit secret thật.
