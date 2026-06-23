# Control Plane Architecture

Tài liệu này là contract tập trung cho control plane. Các lệnh vận hành ngắn gọn nằm ở root `COMMANDS.md`; thuật toán và report train nằm ở `RL_TRAINING_SUMMARY.md`.

## Scope

Control plane hiện tại là Web-only:

- `protocol=http` là protocol runtime duy nhất.
- Action space chỉ gồm `KEEP_NORMAL`, `ROUTE_SQLI`, `ROUTE_SSTI`, `ROUTE_CMDI`, `ROUTE_SSRF`.
- Không triển khai SSH/FTP/SMTP, L4 Drop-and-Catch, hoặc monitoring dashboard.
- Elasticsearch/Filebeat chỉ dùng làm log ingest cho analyzer/replay export; host-mounted logs dùng để debug và đánh giá metric.

Mục tiêu là tăng attacker engagement bằng adaptive routing, không phải block/bảo vệ service thật.

## Runtime Flow

```text
Request with sid cookie
  -> HAProxy gateway
  -> real backend or route-matched honeypot
  -> service/honeypot logs + Elasticsearch
  -> llm_analyzer builds session context and web_state
  -> routing_controller /decide
  -> trained RL model chooses action
  -> gateway/routing_update.sh updates HAProxy maps
  -> follow-up requests with same sid use adaptive route
```

Gateway vẫn giữ normal-service continuity: nếu session bị route vào `sqli_api`, chỉ article-search surface đi SQLi honeypot; preview/ping/fetch không liên quan vẫn về real backend.

## Component Map

```text
control_plane/
  llm_analyzer/analyzer.py
  routing_controller/main.py
  rl_agent/agent.py
  rl_agent/train_offline.py
  rl_agent/generate_fake_data.py
  rl_agent/build_training_dataset.py
  replay_buffer/export_replay_buffer.py
  replay_buffer/generate_web_replay_buffer.py
  replay_buffer/evaluate_metrics.py
  rule_based_baseline/evaluate_rule_based_baseline.py
  state_builder/state_schema.py
```

## State Schema

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
11 target_credential_attack_score   # semantic side signal, no dedicated Web action
12 target_enumeration_score         # semantic side signal, no dedicated Web action
13 evasion_score
14 attack_progression_stage
15 intent_stability_score
```

Important files:

- `state_builder/state_schema.py`: schema definition and validation.
- `llm_analyzer/analyzer.py`: runtime state builder.
- `rl_agent/agent.py`: action constants, model loader, inference.
- `routing_controller/main.py`: `/decide` request validation.

## Action Space

```text
0 KEEP_NORMAL -> normal_api
1 ROUTE_SQLI  -> sqli_api
2 ROUTE_SSTI  -> ssti_api
3 ROUTE_CMDI  -> cmdi_api
4 ROUTE_SSRF  -> ssrf_api
```

The routing controller rejects non-HTTP protocols and unsupported backends. Model artifacts must match both `STATE_DIM=16` and this 5-action runtime action list.

## LLM Analyzer Contract

`llm_analyzer/analyzer.py`:

- Polls Elasticsearch index `honeypot-logs-*`.
- Groups events by `session_id`.
- Enriches gateway events with service-log `body_preview`.
- Calls Groq when `GROQ_API_KEY` is configured.
- Falls back to rule-based semantic extraction when LLM is unavailable or invalid.
- Builds `web_state`.
- Calls `routing_controller /decide`.
- Writes host debug log `logs/llm_analyzer/llm_fields.jsonl`.

Important analyzer output fields:

```text
event_type = rl_state_decision
session_id
decision_id
state
state_fields
attack_type
target_scores
expected_backend_by_semantic_label
backend
route_applied
route_correct_by_semantic_label
is_attack_window
analysis_duration_ms
controller_roundtrip_ms
event_to_decision_latency_ms
```

## Routing Controller Contract

`routing_controller/main.py`:

- Accepts `POST /decide`.
- Validates `state_schema`, `protocol=http`, and state dimension.
- Loads trained JSON artifact from `RL_MODEL_PATH`.
- Selects action using `LinearQAgent`.
- Updates HAProxy maps through `gateway/routing_update.sh`.
- Exposes route/debug endpoints only when `EXPOSURE_MODE=debug`.

Main runtime endpoint:

```text
POST /decide
GET /health
```

Debug-only endpoints:

```text
POST /model/reload
GET /routes
DELETE /routes
POST /route/session/{sid}?backend=...
GET /route/session/{sid}
DELETE /route/session/{sid}
```

## Replay Buffer Contract

`replay_buffer/export_replay_buffer.py` creates offline transitions:

```json
{
  "session_id": "sid",
  "decision_id": "id",
  "protocol": "http",
  "state_schema": "web_state",
  "state": [0.0],
  "action": 1,
  "action_name": "ROUTE_SQLI",
  "backend": "sqli_api",
  "reward": 1.4,
  "reward_components": {},
  "next_state": [0.0],
  "done": false,
  "optimal_action": 1
}
```

Reward rewards correct Web honeypot engagement and penalizes wrong honeypot, false reroute on benign sessions, and broken non-target API surfaces.

## Metric Evaluation

`replay_buffer/evaluate_metrics.py` reads only host-mounted debug logs:

```text
logs/llm_analyzer/llm_fields.jsonl
logs/real_backend/service_requests.jsonl
logs/honeypots/*/service_requests.jsonl
```

It reports:

- Honeypot engagement rate.
- Average requests after adaptive rerouting.
- Session length.
- Correct honeypot routing rate.
- False rerouting rate on benign sessions.
- Normal-service continuity rate.

Continuity is evaluated against the active route at each service event timestamp, so a session that later changes route is not judged forever by its first route.

These evaluation fields are intentionally richer than the RL state; they exist for debugging/report metrics, not for direct model input.

`rl_agent/build_training_dataset.py` builds one unified training dataset from generated and replay transitions, while still keeping source labels inside rows for validation/reporting. `train_offline.py` validates with a session-grouped split stratified by source and dominant attack type, then writes detailed classification/leakage metrics beside the exported model. The tracked runtime artifact is `rl_agent/artifacts/rl_agent_linear.json`; historical local model archives are intentionally not tracked.

## Rule-Based Baseline For RQ1

`rule_based_baseline/evaluate_rule_based_baseline.py` is an offline baseline only:

- Reads the replay traffic manifest.
- Uses simple regex/pattern matching over request `method`, `path`, and `body`.
- Simulates endpoint-scoped routing without calling Docker services or HAProxy.
- Writes RQ1 comparison artifacts under `logs/rule_based_baseline/`.

Command:

```bash
make evaluate-rule-baseline
```

This baseline is intentionally isolated from runtime LLM + RL. It exists to answer whether the adaptive pipeline gives a better tradeoff than a simple rule-based analyzer/router, not to replace the production flow.
