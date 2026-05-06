# Ke hoach hoan thien Adaptive Honeypot RL

Ngay cap nhat: 2026-05-06

Muc dich cua file nay: lam tai lieu dieu huong cho cac lan implement tiep theo. Neu Codex quay lai repo nay, doc file nay truoc `README.md`, `Progress.md`, va `proposal.md`, sau do lam theo thu tu o muc "Next execution plan".

Nguyen tac quan trong nhat cua do an: he thong khong tap trung "bao ve service" bang block/drop request HTTP. Muc tieu nghien cuu la dung LLM/RL de phan tich hanh vi, quyet dinh route attacker sang honeypot phu hop, va tang attacker engagement trong khi benign traffic van di vao real service.

## 1) Current status snapshot

Trang thai sau khi pull/scan 2026-05-06:

- Web MVP da co data plane + control plane du de demo local:
  `real-backend log -> Filebeat/Elasticsearch -> llm_analyzer -> routing_controller -> HAProxy session map -> web honeypot`.
- Control plane van bat dong bo voi request path. Request web khong cho analyzer/RL xu ly dong bo.
- Runtime Docker services khong cai PyTorch. PyTorch chi dung local cho offline training.
- LLM analyzer da co Groq API integration, nhung fallback khi thieu API key/timeout chua chac; neu LLM khong tra output thi adaptive route co the khong dien ra.
- RL policy that chua implement. Hien tai Web MVP van dua vao `RL_POLICY_MODE=heuristic` hoac dummy JSON model.
- Runtime code da migrate sang `rl_state_v2_16` (`STATE_DIM=16`) trong analyzer, routing controller, RL agent, dummy model scripts va synthetic data generator.
- L4 SSH/FTP/SMTP Drop-and-Catch chua implement. Controller/gateway da fail ro rang neu dung L4 placeholder.
- Route maps duoc clear sau E2E tests de tranh stale state.
- Da co `EXPOSURE_MODE=debug|attack`: debug giu operator endpoints/metadata; attack an service identity, route debug APIs, docs/OpenAPI, va HAProxy Stats UI. Analyzer debug endpoint `/analyze` khong con trong source hien tai.

## 2) Verified commands

Da chay trong `adaptive_honeypot_system/` va PASS:

```bash
make test-adaptive-web
make test-rl-split-ip
make test-honeypots
make validate
```

Ket qua quan trong:

- `make test-adaptive-web`: PASS o milestone dummy/heuristic truoc do
  - SQLi-like request vao real backend.
  - Analyzer doc log tu Elasticsearch.
  - Controller route session sang `sqli_api`.
  - Request tiep theo cung `sid` vao SQLI honeypot va nhan fake DB error.
- `make test-rl-split-ip`: PASS
  - Client A -> `ssti-honeypot`.
  - Client B -> `real-backend`.
- `make test-honeypots`: PASS cho CMDI/SQLI/SSTI/SSRF health va detection.
- `make validate`: PASS syntax check, controller health, honeypot tests, core route smoke.
- Route maps sau test sach:
  - `session_routes={}`
  - `ip_routes={}`

## 3) Status matrix

| Area | Status | Da lam xong | Con lai |
| --- | --- | --- | --- |
| Web data plane | DONE for MVP | HAProxy normal/honeypot mode, session/IP route maps, 4 web honeypot, real backend/frontend | Benchmark multi-session, contract tests chuan hon |
| Real backend contract | DONE for MVP | Them `POST /api/articles/search`, frontend client `searchArticles`, DB init lock | Formal contract pytest suite, more edge cases |
| Routing controller | DONE for MVP | `/decide`, model reload/debug endpoints, heuristic mode, backend validation, inspect routes, `DELETE /routes`, L4 disabled 501, attack-mode endpoint hiding | Unit tests, route history store, policy cooldown in controller, migrate `/decide` state schema v2 |
| Demo exposure surface | DONE for MVP | `EXPOSURE_MODE=debug|attack`, generic health in attack mode, `/routes` hidden, analyzer debug injection endpoint removed, HAProxy Stats UI disabled | Network-level compose override to publish only gateway in attack demo |
| Gateway route updates | DONE for MVP | Idempotent map update/remove, clear all maps, `drop_connection` fail ro rang | L4 drop implementation neu chon lam Phase 8 |
| Structured logging | DONE for MVP | JSON logs cho backend/honeypots, request/session/body preview, masking co ban | Gateway selected-backend parsing, Kibana dashboard |
| Filebeat/ES | DONE for MVP | Docker log ingest, JSON decode, bo hardcoded container IDs, giu controller/analyzer logs | Saved searches/dashboard, retention/index template polish |
| LLM analyzer | PARTIAL DONE | Poll ES, enrich body_preview, call Groq or rule fallback, validate semantic JSON, build state v2, call controller | State builder package polish, memory durable/decay, input summary hygiene |
| Dummy RL | DONE for MVP | `RL_POLICY_MODE=heuristic`, dummy web model generator, JSON LinearQ runtime | Real replay buffer, reward, train/evaluate policy |
| RL state schema | DONE for runtime | `rl_state_v2_16`, protocol de ngoai tensor lam metadata/action-mask context, code runtime da dung 16D | Unit tests/schema package polish, replay artifacts moi |
| L4 Drop-and-Catch | NOT STARTED | Disabled safely | SSH/FTP/SMTP data plane, honeypots, reconnect tests |
| Benchmark/research metrics | NOT STARTED | E2E smoke tests only | RQ metrics, attack drivers, adaptive vs static/rule comparison |
| Docs | PARTIAL DONE | README/Progress/component READMEs updated | Benchmark docs, design notes, final report alignment |

## 4) Files/components already implemented or changed

### 4.1 Control plane

Done:

- `adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py`
  - LLM analyzer service.
  - Polls `honeypot-logs-*`.
  - Builds session context from gateway logs and enriches request body from backend/honeypot service logs.
  - Calls Groq (`GROQ_API_KEY`, default model `llama-3.3-70b-versatile`) for semantic extraction.
  - Validates/clamps LLM output fields.
  - Builds current runtime state v2 16D and calls routing controller `/decide`.
  - `EXPOSURE_MODE=attack` hides docs/OpenAPI and detailed health stats.

- `adaptive_honeypot_system/control_plane/llm_analyzer/test_adaptive_web_flow.sh`
  - E2E Web MVP test for log -> analyzer -> route -> honeypot.
  - Cleans route maps before/after test.

- `adaptive_honeypot_system/control_plane/routing_controller/main.py`
  - Adds `RL_POLICY_MODE=heuristic`.
  - Adds deterministic web heuristic policy.
  - Validates implemented HTTP backends only.
  - Rejects non-HTTP/L4 when `L4_ROUTING_ENABLED=false`.
  - Adds route inspection:
    - `GET /routes`
    - `GET /route/session/{sid}`
    - `GET /route/ip/{ip}`
  - Adds route cleanup:
    - `DELETE /routes`
  - Logs route decisions as structured JSON.
  - `EXPOSURE_MODE=attack` hides operator/debug endpoints with 404 and keeps generic `/health`.

- `adaptive_honeypot_system/control_plane/rl_agent/create_dummy_web_policy_model.py`
  - Creates deterministic subtype-based dummy web model artifact.

Remaining:

- Rule-based fallback when Groq is unavailable or returns invalid output.
- Redis or durable memory with decay and session history.
- Formal state builder package using `rl_state_v2_16`.
- Real replay buffer extraction and RL evaluation.

### 4.2 Gateway

Done:

- `adaptive_honeypot_system/gateway/routing_update.sh`
  - Supports add/remove session route.
  - Supports add/remove IP route.
  - Supports `clear_sessions`, `clear_ips`, `clear_all`.
  - `drop_connection` returns explicit error because L4 is not implemented.

- `adaptive_honeypot_system/gateway/haproxy.cfg`
  - Deleted because it was legacy/unused by Dockerfile.

Remaining:

- Optional TCP frontends for SSH/FTP/SMTP if Phase 8 is still in scope.
- Optional HAProxy log parsing for selected backend and route latency metrics.

### 4.3 Real service

Done:

- `adaptive_honeypot_system/real_service/backend/routes/articles.py`
  - Adds safe `POST /api/articles/search`.
  - Preserves real-service behavior; does not intentionally introduce SQLi.

- `adaptive_honeypot_system/real_service/backend/logging_utils.py`
  - Structured JSON request logs.
  - Session/request/body preview.
  - Sensitive field masking.

- `adaptive_honeypot_system/real_service/backend/app.py`
  - Installs request logging.
  - Adds service name to health.
  - Fixes SQLite/Gunicorn init race by using file lock.

- `adaptive_honeypot_system/real_service/frontend/src/api/client.js`
  - Adds `searchArticles`.

Remaining:

- Formal contract tests against real backend and honeypots.
- Optional frontend route/session debug page if needed for demo.

### 4.4 Honeypots

Done:

- `adaptive_honeypot_system/honeypots/base.py`
  - Structured JSON honeypot interaction logs.
  - Adds schema version, request ID, forwarded IP, payload size, body preview.
  - Masks sensitive fields.
  - Returns `X-Request-ID`.

Remaining:

- Shared contract helpers to reduce duplication.
- More engagement-oriented fake responses if benchmark shows attacker drops too fast.

### 4.5 Observability

Done:

- `adaptive_honeypot_system/observability/filebeat/filebeat.yml`
  - Stops using hardcoded container IDs.
  - Keeps controller/analyzer logs.
  - Avoids Filebeat 8 setup/template race in local stack.

Remaining:

- Kibana dashboard.
- Saved searches for sessions, route decisions, honeypot interactions.
- Benchmark latency aggregation.

### 4.6 Make targets

Done in `adaptive_honeypot_system/Makefile`:

- `make test-adaptive-web`
- `make test-rl-split-ip`
- `make test-honeypots`
- `make make-dummy-web-model`
- `make clear-routes`
- `make logs-analyzer`
- `make validate`

Remaining:

- `make test-unit`
- `make test-e2e`
- `make benchmark-web`
- `make benchmark-report`
- `make extract-replay-buffer`
- `make evaluate-rl`

## 5) Done checklist by phase

### Phase 0 - Baseline, guardrails, repo hygiene

Status: DONE for current milestone.

- [x] Baseline stack checked.
- [x] `make validate` added.
- [x] Pydantic protected namespace warning fixed.
- [x] Legacy `gateway/haproxy.cfg` deleted.
- [x] Generated/local files kept out of intended commit scope.
- [x] README/Progress updated to match current state.

Acceptance:

- [x] Python modules compile.
- [x] `make test-honeypots` PASS.
- [x] `make validate` PASS.

### Phase 1 - Web API contract real service vs honeypots

Status: PARTIAL DONE, enough for Web MVP smoke.

- [x] Real backend has `POST /api/articles/search`.
- [x] Frontend API client has `searchArticles`.
- [x] Honeypot direct tests pass for CMDI/SQLI/SSTI/SSRF.
- [x] Gateway honeypot-mode endpoint mapping exists.
- [ ] Formal contract matrix in tests/docs.
- [ ] Pytest contract tests for real backend vs each honeypot.
- [ ] Shared helper refactor for repeated honeypot common routes.

Remaining detail:

- Define expected schema for:
  - `GET /api/health`
  - `GET /api/articles`
  - `POST /api/articles/search`
  - `GET /api/articles/<id>`
  - `POST /api/tools/preview`
  - `POST /api/tools/ping`
  - `POST /api/tools/fetch`
- Add tests that assert honeypot responses do not break frontend/API clients.

### Phase 2 - Routing controller and HAProxy map hardening

Status: DONE for current Web MVP.

- [x] HTTP backend allowlist implemented:
  - `normal_api`
  - `sqli_api`
  - `ssti_api`
  - `cmdi_api`
  - `ssrf_api`
- [x] Non-HTTP/L4 routes return 501 when L4 disabled.
- [x] `endpoint_honeypot` is not accepted as manual normal-mode route backend.
- [x] Session and IP route add/remove works.
- [x] `DELETE /routes` clears both route maps.
- [x] Split-IP E2E test PASS.
- [ ] Unit tests for invalid backend and model-missing behavior.
- [ ] Optional controller-side route cooldown/history store.

Remaining detail:

- Add unit-level tests for:
  - invalid backend -> 400.
  - L4 backend while disabled -> 501.
  - missing model -> health says `model_exists=false`.
  - `apply_route=false` does not modify maps.
- Consider centralizing action/backend schema so `agent.py`, controller, and HAProxy configs cannot drift.

### Phase 3 - Structured logging and observability for AI

Status: PARTIAL DONE, enough for analyzer-driven Web MVP.

- [x] Real backend structured JSON logs.
- [x] Honeypot structured JSON logs.
- [x] Request/session/body preview fields available.
- [x] Sensitive field masking added.
- [x] Filebeat no longer depends on hardcoded container IDs.
- [x] Analyzer can read logs from Elasticsearch and make decisions.
- [ ] Kibana dashboard.
- [ ] Saved queries for route decisions and engagement.
- [ ] Gateway selected backend parsing/normalization.

Remaining detail:

- Confirm ES documents consistently include:
  - `session_id`
  - `remote_addr` or `source_ip`
  - `x_forwarded_for`
  - `path`
  - `status_code`
  - `payload_size`
  - `body_preview`
  - `service`
  - `event_type`
- Add dashboard panels:
  - normal vs honeypot traffic.
  - route decisions over time.
  - attack subtype distribution.
  - top sessions/IPs by engagement.
  - pipeline latency.

### Phase 4 - Formal state builder and LLM fallback

Status: PARTIAL DONE.

Done:

- [x] Analyzer builds runtime state v2 16D.
- [x] Groq-backed semantic extraction exists.
- [x] LLM output validation/clamping exists.
- [x] Analyzer can read logs from Elasticsearch and call `/decide`.
- [x] State schema v2 16D has been approved for migration.

Not done:

- [ ] Dedicated `state_builder/` package.
- [ ] `StateVector` dataclass with named fields and schema version.
- [ ] Unit tests for state dimension/order.
- [x] Runtime migration from `STATE_DIM=24` to `STATE_DIM=16`.
- [ ] Rule-based fallback that still routes Web attacks when LLM provider is unavailable.
- [ ] Real session memory.
- [ ] Redis service or durable memory.
- [ ] Strict LLM output schema.
- [ ] Failure/timeout policy around real LLM calls.

Runtime state schema: `rl_state_v2_16`

Protocol is required metadata of `/decide`, not a tensor field. Controller uses it for action masking and protocol-specific normalization.

1. `session_age_norm`
2. `interaction_rate_norm`
3. `failed_attempts_norm`
4. `payload_complexity_norm`
5. `target_diversity_norm`
6. `current_route`
7. `engagement_depth_norm`
8. `target_sqli_score`
9. `target_cmdi_score`
10. `target_ssti_score`
11. `target_ssrf_score`
12. `target_credential_attack_score`
13. `target_enumeration_score`
14. `evasion_score`
15. `attack_progression_stage`
16. `intent_stability_score`

Fields intentionally removed from v1 24D:

- `protocol_onehot`: moved to `/decide` metadata.
- `attack_category_onehot`: replaced by target-specific scores.
- `attack_vector_shift`: merged into `intent_stability_score`.
- `memory_decay_weight`: removed until real decay exists.
- `llm_confidence`: used to scale LLM-derived fields before tensor construction, logged separately for observability/debug.

### Phase 5 - Adaptive decision loop end-to-end for Web

Status: DONE for single-attack Web MVP, incomplete for research benchmark.

- [x] Worker service exists in analyzer.
- [x] Polls Elasticsearch.
- [x] Builds state v2 16D.
- [x] Calls routing controller.
- [x] Applies HAProxy session route.
- [x] `make test-adaptive-web` proves SQLi single-attack route.
- [x] Route cleanup keeps maps clean after tests.
- [x] Migrate adaptive flow to `rl_state_v2_16`.
- [ ] Multi-attack same session route-shift demo.
- [ ] Benign-session no-reroute benchmark.
- [ ] Dry-run report/replay mode.
- [ ] Route decision history suitable for replay buffer.

Remaining detail:

- Add tests for CMDI/SSTI/SSRF adaptive flow, not just SQLi.
- Add same-session sequence:
  - SQLi -> SQLI pot.
  - SSTI later in same session -> either shift to SSTI pot or log explicit policy reason to keep current route.
- Add `ANALYZER_APPLY_ROUTE=false` demo path and decision log assertions.

### Phase 6 - Real RL dataset, reward, training, evaluation

Status: NOT STARTED, except synthetic/bootstrap code.

Already present:

- [x] `LinearQAgent` runtime.
- [x] Synthetic data generator.
- [x] PyTorch offline training script.
- [x] JSON artifact loading in controller.
- [x] Dummy model generators.

Not done:

- [ ] Extract replay buffer from real/demo logs.
- [ ] Define transition schema version.
- [ ] Define proposal-aligned reward.
- [ ] Evaluate policy against benchmark sessions.
- [ ] Add artifact metadata.
- [ ] Compare heuristic vs learned policy.

Reward should optimize engagement, not blocking:

- Positive:
  - more attacker interactions after reroute.
  - correct subtype honeypot.
  - route shift when attacker intent shifts and keeps interacting.
- Negative:
  - benign session rerouted.
  - route to wrong honeypot causing attacker to stop.
  - frontend/API contract break.
  - excessive delay before reroute.

### Phase 7 - Benchmark and research questions

Status: NOT STARTED.

Needed to answer proposal/RQ-style claims:

- [ ] Benign baseline sessions.
- [ ] Single attack sessions for SQLi/CMDI/SSTI/SSRF.
- [ ] Multi-attack same-session scenarios.
- [ ] Static honeypot baseline.
- [ ] Rule-based baseline.
- [ ] Adaptive dummy/RL comparison.
- [ ] Metrics report.

Metrics:

- Correct honeypot routing rate.
- False rerouting rate.
- Avg requests after reroute.
- Session length after reroute.
- Honeypot engagement rate.
- Normal-service continuity rate.
- Pipeline latency:
  - app log timestamp -> ES ingest.
  - ES ingest -> analyzer decision.
  - analyzer decision -> route map update.
  - route map update -> next request routed.

### Phase 8 - L4 SSH/FTP/SMTP Drop-and-Catch

Status: NOT STARTED.

Current behavior:

- L4 is intentionally disabled.
- Controller rejects non-HTTP route attempts when `L4_ROUTING_ENABLED=false`.
- `drop_connection` returns explicit error.

If this remains in final scope:

- [ ] Add normal mock services for SSH/FTP/SMTP.
- [ ] Add honeypots or mock honeypots for SSH/FTP/SMTP.
- [ ] Add HAProxy TCP frontends.
- [ ] Add source-IP route map for TCP.
- [ ] Implement connection drop/reconnect.
- [ ] Add L4 logs to state builder.
- [ ] Add E2E reconnect tests.

If not in final scope:

- [ ] Document L4 as stretch goal.
- [ ] Keep L4 disabled safely.
- [ ] Remove unsupported L4 action claims from final demo narrative.

### Phase 9 - Docs, dashboard, final polish

Status: PARTIAL DONE.

- [x] Root README updated.
- [x] Progress updated.
- [x] Component READMEs added.
- [x] RL guide partially updated.
- [ ] Design note explaining current vs proposal scope.
- [ ] Kibana dashboard instructions/screenshots.
- [ ] Benchmark report template.
- [ ] Final demo script.

## 6) Next execution plan

Lam theo thu tu nay. Dung phase tiep theo khi acceptance cua phase hien tai chua pass.

### Step A - Lock Web MVP quality with tests

Goal: Web MVP da chay bang shell smoke, gio can tests ro hon de refactor/LLM/RL khong lam vo contract.

Tasks:

- [ ] Tao `tests/` folder.
- [ ] Add pytest dependencies neu can, giu nhe.
- [ ] Add `tests/test_state_schema.py` for `rl_state_v2_16`.
- [ ] Add `tests/test_routing_controller_unit.py`.
- [ ] Add `tests/test_contract_web.py`.
- [ ] Add Make targets:
  - `make test-unit`
  - `make test-e2e`
  - `make test-all-project`
- [ ] Keep existing shell E2E tests for Docker flow.

Acceptance:

- `make test-unit` chay duoc khong can Docker.
- `make validate` van PASS.
- Invalid backend/L4 disabled behavior duoc test tu dong.

### Step B - Harden `rl_state_v2_16` state builder

Goal: state da duoc giam tu 24D xuong 16D; buoc tiep theo la tach het logic state ra package rieng de train/evaluate RL khong bi lech field order.

Files to create:

- `adaptive_honeypot_system/control_plane/state_builder/__init__.py`
- `adaptive_honeypot_system/control_plane/state_builder/state_schema.py`
- `adaptive_honeypot_system/control_plane/state_builder/features.py`
- `adaptive_honeypot_system/control_plane/state_builder/log_query.py`

Tasks:

- [x] Define `STATE_SCHEMA_VERSION = "rl_state_v2_16"`.
- [x] Change `STATE_DIM` from 24 to 16.
- [x] Define field names/ranges for 16D state.
- [x] Define `StateVector` dataclass.
- [x] Implement `to_list()` and `validate_state()`.
- [x] Analyzer imports state builder for schema and `StateVector`.
- [ ] Move feature computation from analyzer to `features.py`.
- [x] Controller `/decide` accepts `state_schema` and validates it.
- [x] Heuristic policy indexes update:
  - SQLi score index 7.
  - CMDi score index 8.
  - SSTI score index 9.
  - SSRF score index 10.
  - credential/enumeration reserved for future L4.
- [x] Dummy model generators update to 16D.
- [x] Synthetic dataset generator update to 16D.
- [x] Test scripts and docs command examples update to 16D payloads.
- [x] Keep `protocol` as `/decide` metadata and action-mask context, not state tensor.

Acceptance:

- Unit tests prove exactly 16 floats.
- SQLi/CMDI/SSTI/SSRF samples map to highest matching subtype score.
- Benign samples keep route action normal in heuristic mode.
- `make test-adaptive-web` still PASS.

### Step C - Add route decision history and replay-friendly logs

Goal: tao du lieu cho benchmark va RL replay buffer.

Tasks:

- [ ] Add decision ID.
- [ ] Add state hash.
- [ ] Log analyzer decision with:
  - session_id
  - source_ip
  - protocol
  - detected_attack
  - subtype scores
  - selected action/backend
  - reason
  - apply_route
  - route result
- [ ] Controller route_decision log includes enough fields to join with analyzer decision.
- [ ] Optional: expose `GET /decisions/recent` in controller or analyzer for demo/debug.

Acceptance:

- After adaptive test, ES contains app docs for:
  - backend request.
  - analyzer decision.
  - controller route decision.
  - honeypot interaction.
- Route decision docs can be grouped by `session_id`.

### Step D - Web benchmark runner

Goal: co metric thay vi chi co curl smoke test.

Files to create:

- `adaptive_honeypot_system/benchmarks/web_driver.py`
- `adaptive_honeypot_system/benchmarks/report.py`
- `adaptive_honeypot_system/benchmarks/scenarios/*.json`
- `adaptive_honeypot_system/reports/.gitkeep` or ignored generated reports.

Tasks:

- [ ] Benign scenario.
- [ ] Single SQLi/CMDI/SSTI/SSRF scenarios.
- [ ] Multi-attack same-session scenario.
- [ ] Static honeypot baseline scenario.
- [ ] Rule-only/dummy adaptive scenario.
- [ ] Query ES/route maps and compute metrics.
- [ ] Add Make targets:
  - `make benchmark-web`
  - `make benchmark-report`

Acceptance:

- Benchmark produces JSON metrics.
- Benchmark produces Markdown report.
- Report contains routing accuracy, false reroute rate, engagement, latency.

### Step E - Replay buffer and RL evaluation

Goal: bat dau thay dummy policy bang policy co the danh gia tren data that.

Files to create:

- `adaptive_honeypot_system/control_plane/rl_agent/extract_replay_buffer.py`
- `adaptive_honeypot_system/control_plane/rl_agent/evaluate_policy.py`
- `adaptive_honeypot_system/control_plane/rl_agent/reward.py`

Tasks:

- [ ] Define transition schema:
  - schema_version
  - state
  - action
  - reward
  - next_state
  - done
  - protocol
  - session_id/source_ip
  - attack_label optional
  - window_start/window_end
- [ ] Extract transitions from benchmark logs.
- [ ] Implement reward aligned to engagement.
- [ ] Evaluate heuristic policy as baseline.
- [ ] Evaluate trained linear policy.
- [ ] Add artifact metadata:
  - state schema version.
  - action schema version.
  - dataset path/hash.
  - metrics.

Acceptance:

- `make extract-replay-buffer` writes JSONL.
- `make evaluate-rl` writes metrics JSON.
- Controller can load generated artifact.
- README/RL guide explains synthetic vs replay dataset clearly.

### Step F - Harden Groq LLM analyzer with safe fallback

Goal: giu Groq analyzer dung proposal nhung local demo van chay duoc khi khong co API key hoac provider timeout.

Tasks:

- [x] Groq provider integrated in `llm_analyzer`.
- [ ] Add provider mode/config abstraction if needed:
  - `LLM_PROVIDER=groq|none`
  - default safe behavior when key missing.
- [ ] Define strict LLM input summary, not raw full logs.
- [ ] Define strict JSON output schema:
  - attack_category
  - web_subtype_scores
  - evasion_score
  - historical_intent_consistency
  - attack_progression_stage
  - intent_shift_velocity
  - llm_confidence
  - updated_memory_context
- [ ] Add timeout and retry.
- [x] On LLM failure or missing Groq package/key:
  - use rule-based semantic fallback.
  - do not block request path.
- [ ] Add memory decay for fallback/LLM memory.
- [ ] Add Redis or in-process memory:
  - per HTTP session ID.
  - source IP fallback.

Acceptance:

- No API key / provider timeout path still routes obvious SQLi/CMDI/SSTI/SSRF through rule-based fallback.
- With fake/mock LLM provider, output schema validated.
- Bad LLM JSON falls back to rules and logs error.

### Step G - Decide L4 scope

Goal: tranh lam nua voi trong khi proposal co L4. Can chot L4 la final scope hay stretch.

Option 1: Stretch goal.

- [ ] Document clearly that current deliverable is Web adaptive honeypot.
- [ ] Keep L4 actions disabled in controller.
- [ ] Remove "full L4 implemented" wording from docs/report.

Option 2: Implement L4 demo.

- [ ] Add mock normal SSH/FTP/SMTP.
- [ ] Add mock or real L4 honeypots.
- [ ] Add HAProxy TCP frontends/maps.
- [ ] Implement drop/reconnect.
- [ ] Add L4 analyzer features.
- [ ] Add E2E tests.

Acceptance:

- If stretch: docs are honest and tests still pass.
- If implement: non-HTTP `/decide` has full E2E test.

## 7) Current Definition of Done

### Web MVP DoD

Already satisfied:

- [x] Normal mode benign traffic reaches real backend.
- [x] Single SQLi adaptive test routes to SQLI honeypot.
- [x] Frontend/API core contract does not break in smoke tests.
- [x] ES/Filebeat/analyzer/controller path works.
- [x] Runtime containers avoid PyTorch.
- [x] README demo commands are present.

Still needed before claiming research-complete Web MVP:

- [ ] Benign benchmark shows no false reroute.
- [ ] CMDI/SSTI/SSRF adaptive E2E tests, not just direct honeypot tests.
- [ ] Multi-attack same-session policy tested.
- [ ] Metrics report exists.
- [ ] Pipeline latency measured.
- [ ] Engagement metric measured.

### Full proposal DoD

Needed:

- [ ] Real LLM analyzer or clearly justified mock/fallback.
- [ ] Stateful memory.
- [ ] RL trained/evaluated on replay or benchmark data.
- [ ] Benchmark answers RQ-style questions.
- [ ] L4 implemented or explicitly scoped out as stretch.

## 8) Verification commands

Run from repo root unless noted.

Syntax and core smoke:

```bash
cd adaptive_honeypot_system
make validate
```

Adaptive Web E2E:

```bash
cd adaptive_honeypot_system
make test-adaptive-web
```

Split-IP route E2E:

```bash
cd adaptive_honeypot_system
make test-rl-split-ip
```

Standalone honeypots:

```bash
cd adaptive_honeypot_system
make test-honeypots
```

Route map cleanup/check:

```bash
cd adaptive_honeypot_system
make clear-routes
curl -s http://localhost:8001/routes
```

Torch runtime check:

```bash
cd adaptive_honeypot_system
docker compose exec routing_controller python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec backend python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec cmdi_pot python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
```

Expected: all `False`.

## 9) Known risks and guardrails

### Risk: stale logs trigger wrong routes

Current mitigation:

- Analyzer only processes logs newer than analyzer startup time.
- Analyzer uses service logs mainly for body enrichment/engagement observation; route creation should be driven by gateway/session context, not direct honeypot port tests.
- E2E tests clear route maps.

Future work:

- Store analyzer cursor/checkpoint.
- Use event timestamps and ingestion timestamps explicitly.

### Risk: route map remains dirty after tests

Current mitigation:

- `DELETE /routes`.
- `make clear-routes`.
- E2E cleanup traps.

Future work:

- Add route TTL.
- Add route owner/test ID metadata if maps grow.

### Risk: docs/code overclaim proposal status

Current mitigation:

- Docs distinguish current runtime v2 16D from removed v1 24D schema.
- Docs call RL policy heuristic/dummy until replay training/evaluation exists.
- L4 disabled explicitly.

Future work:

- Add design note: current demo vs full proposal.
- Benchmark before making research claims.
- Complete state v2 migration before training/evaluating RL.

### Risk: LLM makes demo unstable

Required approach:

- Rule-based state builder remains baseline.
- Missing Groq key / provider timeout must still work for obvious Web attack routing.
- LLM failure must not break routing controller or request path.

### Risk: RL optimizes blocking instead of engagement

Required approach:

- Reward must measure post-reroute interaction/engagement.
- Penalize false reroute and wrong honeypot.
- Do not reward simply dropping or denying traffic in Web MVP.
