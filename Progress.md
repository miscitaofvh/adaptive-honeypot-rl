# Báo cáo tiến độ

Cập nhật: 2026-05-20

## 1) Tổng quan hiện tại

Dự án đã hoạt động đủ cho data plane + control plane trong web scope:
- Data plane: gateway HAProxy + real backend/frontend + 4 web honeypot.
- Exposure mode: `debug` cho operator/test, `attack` cho demo attacker-facing.
- Control plane: routing controller FastAPI chạy runtime, cập nhật route map theo session/IP.
- RL: đã tách rõ controller inference không Torch, train offline local/container, và `rl_agent` Torch service riêng cho debug/export/one-epoch proxy train. Web MVP có dummy heuristic RL mode. Runtime code đã migrate sang `rl_state_v2_16`. Đã có replay-buffer exporter từ runtime logs và `train_offline.py` mặc định dùng Discrete CQL cho offline RL.
- LLM analyzer: service poll Elasticsearch, gọi Groq API (Llama 3.3 70B) hoặc rule fallback để trích xuất semantic features, dựng state v2 16D và gọi routing controller bất đồng bộ.
- Observability: Filebeat -> Elasticsearch -> Kibana hoạt động. Service-level syslog forwarding thu thập HTTP request body từ backend/honeypot.
- State hiện tại: `rl_state_v2_16`, giảm từ 24D xuống 16D, giữ `protocol` ngoài tensor làm metadata của `/decide` để mở rộng SSH/FTP/SMTP bằng action masking.

Control plane tiếp tục được giữ theo nguyên tắc bất đồng bộ, không chặn request path.

## 2) Hạng mục đã hoàn thành

### Data plane
- [x] Route theo 2 mode (`TEST_HONEYPOT=true|false`).
- [x] Mapping endpoint trong honeypot mode:
  - `/api/tools/ping` -> CMDI
  - `/api/tools/preview` -> SSTI
  - `/api/tools/fetch` -> SSRF
  - `/api/articles/search` -> SQLI
- [x] `/api/health` route riêng về real backend (`health_api`).
- [x] `EXPOSURE_MODE=debug|attack`: debug mode giu endpoint/metadata test; attack mode an service identity, `/routes`, docs/OpenAPI, HAProxy Stats UI. Analyzer debug endpoint `/analyze` khong con trong source hien tai.
- [x] Session map steering và source-IP map steering qua `routing_update.sh`, đã scope theo đúng API surface để không làm hỏng API khác cùng session.
- [x] Real backend có `POST /api/articles/search` để khớp SQLI honeypot contract.
- [x] Gỡ config HAProxy legacy không dùng (`gateway/haproxy.cfg`) để tránh nhầm lẫn.

### Control plane + RL
- [x] `routing_controller` expose `/decide`; cac API operator nhu `/model/reload`, add/remove route, inspect route map chi bat trong debug mode.
- [x] Refactor train offline sang PyTorch trong `train_offline.py`.
- [x] Thêm `requirements-local.txt` cho train local, tách khỏi requirements của controller/request-path services.
- [x] Runtime controller vẫn dùng JSON linear weights (`LinearQAgent`), không cần torch trong controller container.
- [x] Thêm `RL_POLICY_MODE=heuristic` làm dummy RL policy cho Web MVP.
- [x] Thêm `rl_agent` service dùng Torch trên port `8003`, chạy debug/attack mode, hỗ trợ `/predict`, `/export`, `/train/one-epoch`.
- [x] `rl_agent` export artifact JSON tương thích controller (`rl_agent_linear.json`) mà không full train.
- [x] Thêm route inspection API: `/routes`, `GET /route/session/{sid}`, `GET /route/ip/{ip}`.
- [x] Thêm route cleanup API `DELETE /routes` và Make target `make clear-routes`.
- [x] Chặn non-HTTP/L4 placeholder khi `L4_ROUTING_ENABLED=false`.
- [x] Thêm `llm_analyzer` service (`/health`) cho flow `log -> state -> decide -> route`.
- [x] Migrate runtime từ state v1 24D sang `rl_state_v2_16`.
- [x] Thêm `rl_state_decision` logging trong analyzer và `route_decision` logging có state/decision_id trong routing controller.
- [x] Thêm replay-buffer exporter dựng `(state_t, action_t, reward_t, next_state_t, done)` từ Elasticsearch/runtime logs.
- [x] Split-IP E2E `test_two_ip_split_routing.sh` pass với route honeypot theo endpoint, không route toàn bộ API của IP.

### Logging pipeline
- [x] Filebeat `drop_fields` loại bỏ metadata thừa (`agent`, `host`, `ecs`, `syslog`, `process`, v.v.) — ELK chỉ còn `@timestamp` + `app.*`.
- [x] HAProxy syslog `len 8192` — fix User-Agent bị truncate.
- [x] Service-level syslog forwarding: backend + 4 honeypot gửi structured JSON log qua UDP đến Filebeat port 5141.
- [x] Filebeat `type: udp` input với JavaScript processor strip `<priority>` prefix và trailing NUL byte.
- [x] HTTP request body capture tại service layer (Flask) — `body_preview` field với sensitive field masking (`password`, `token` → `[redacted]`).
- [x] Fix ES field type conflict: `app.ts` thống nhất unix epoch integer giữa HAProxy và service logs.
- [x] LLM analyzer two-pass enrichment: merge `body_preview` từ service logs vào gateway events theo `(session_id, method, path)`.
- [x] Control-plane decision/state events gửi sang Filebeat UDP để Elasticsearch có đủ dữ liệu export replay buffer.
- [x] Fix ES mapping conflict cho replay logs:
  - `app.ts` thống nhất unix epoch integer.
  - `app.state` ghi dạng list chuỗi số trong ES để tránh `long|float` dynamic mapping conflict; replay exporter convert lại về float.

### LLM analyzer — Groq API integration
- [x] Thay `call_llm()` stub bằng Groq API call thật (model: `llama-3.3-70b-versatile`).
- [x] System prompt trích xuất 8-field semantic output: `attack_category`, `web_subtype_scores`, `evasion_score`, `historical_intent_consistency`, `attack_progression_stage`, `intent_shift_velocity`, `llm_confidence`, `updated_memory_context`.
- [x] Validation + clamping output fields về [0, 1], graceful degradation khi LLM lỗi.
- [x] E2E verified: CMDi payload (`127.0.0.1; cat /etc/passwd`) → LLM detect cmdi (score 0.8) → route `test-llm-groq` → `cmdi_api` → request tiếp theo trên session đó đi vào honeypot.
- [x] Bổ sung fallback rule-based khi thiếu `GROQ_API_KEY` hoặc LLM timeout để adaptive flow vẫn chạy được.
- [x] Không log full `llm_input_preview` chứa body/payload nhạy cảm trong demo attack-facing.

### RL state schema
- [x] Chốt hướng giảm chiều: state v2 16D, `protocol` là metadata ngoài tensor.
- [x] Chốt các field v2:
  - `session_age_norm`
  - `interaction_rate_norm`
  - `failed_attempts_norm`
  - `payload_complexity_norm`
  - `target_diversity_norm`
  - `current_route`
  - `engagement_depth_norm`
  - `target_sqli_score`
  - `target_cmdi_score`
  - `target_ssti_score`
  - `target_ssrf_score`
  - `target_credential_attack_score`
  - `target_enumeration_score`
  - `evasion_score`
  - `attack_progression_stage`
  - `intent_stability_score`
- [x] Migrate `agent.py`, `routing_controller/main.py`, `llm_analyzer/analyzer.py`, dummy model scripts, synthetic data generator và test commands sang `STATE_DIM = 16`.

### Test harness
- [x] `test_honeypots.py` ở root repo hoạt động ổn định.
- [x] `make test-honeypots` pass.
- [x] Đã có fallback URL IPv6 (`::1`) cho SSTI trong script test để tránh timeout loopback IPv4.

### Repo hygiene (để push)
- [x] Việt hóa tài liệu chính (README, progress, RL guide).
- [x] Dọn file phát sinh trong `rl_agent/data`, `rl_agent/artifacts`, `__pycache__`.
- [x] Bổ sung `.gitignore` để tránh commit nhầm data/model local và `.env.bak`.
- [x] Bổ sung README cho các component chính: gateway, backend, frontend, honeypots, routing controller, rl_agent, llm_analyzer, observability.

## 3) Kết quả test đã xác nhận

Đã chạy trong thư mục `adaptive_honeypot_system/`:

```bash
docker compose ps
curl -s http://localhost:8001/health
curl -s http://localhost:8003/health
curl -s http://localhost:18080/api/health
make rl-agent-export
make rl-agent-one-epoch
make test-routes
make test-honeypots
make test-rl-split-ip
make test-adaptive-web
make test-adaptive-attacks
make export-replay-buffer
make train-rl-replay
make validate
```

Kết quả:
- [x] Tất cả service Up.
- [x] Routing controller health PASS.
- [x] Torch RL agent health/predict/export/one-epoch PASS.
- [x] Controller `RL_POLICY_MODE=model` smoke với artifact do `rl_agent` export PASS (`ROUTE_SQLI -> sqli_api`).
- [x] Attack mode hiding của `rl_agent` PASS (`/predict`, `/docs` 404).
- [x] Gateway `/api/health` PASS (`real-backend`).
- [x] `make test-routes` PASS.
- [x] `make test-honeypots` PASS.
- [x] `make test-rl-split-ip` PASS (Client A -> `ssti-honeypot`, Client B -> `real-backend`).
- [x] `make test-adaptive-web` PASS (`log -> analyzer -> controller -> HAProxy session route -> SQLI honeypot`).
- [x] `make test-adaptive-attacks` PASS (`SQLi`, `CMDi`, `SSTI`, `SSRF` route đúng endpoint-scoped honeypot; không route sentinel `sid="-"`).
- [x] `make export-replay-buffer` PASS (10 transitions từ runtime logs hiện tại, 5 sessions exported).
- [x] `make train-rl-replay` PASS trong Docker `rl_agent`, xuất `rl_agent_linear.json` và metrics.
- [x] `make validate` PASS (syntax check, routing controller health, honeypot tests, core route smoke).
- [x] Route maps sạch sau E2E (`session_routes={}`, `ip_routes={}`).

## 4) Ràng buộc đã xác minh

- [x] Không cài `torch` trong Docker request-path services (`routing_controller`, `backend`, `honeypots`).
- [x] `torch` chỉ dùng local để train offline và trong service riêng `rl_agent`.
- [x] Chưa test lại full benchmark train thật vì hiện chưa có dataset thật.

## 5) Lưu ý vận hành

- Lệnh make/compose nên chạy trong `adaptive_honeypot_system/`.
- `make train-rl` và `make train-rl-replay` chạy trong Docker `rl_agent` container, nên host không cần cài Torch.
- `make train-rl` cần dataset local (`control_plane/rl_agent/data/fake_transitions.jsonl`) vì thư mục data được mount vào container.
- Nếu data rỗng, dùng `make train-rl-fresh` để tự sinh data rồi train.

## 6) Việc còn lại

- [x] ~~Thay dummy `llm_analyzer` bằng LLM analyzer gọi provider thật.~~
- [x] Hoàn thiện fallback rule-based để thiếu API key/provider lỗi vẫn chạy được demo adaptive rõ ràng.
- [x] Migrate state v1 24D sang `rl_state_v2_16`.
- [x] Xây dựng decision/state logging + reward builder + replay buffer exporter.
- [ ] Thay dummy/Torch stub policy bằng policy RL train/evaluate đầy đủ trên dataset thật.
- [ ] Hoàn thiện benchmark (route accuracy, false reroute, engagement).
- [ ] Hoàn thiện L4 SSH/FTP/SMTP Drop-and-Catch nếu còn trong scope demo.
  
