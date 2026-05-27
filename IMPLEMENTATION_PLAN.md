# Implementation Plan

## Current Decision

Đồ án dừng ở Web-only adaptive honeypot routing. Các phần SSH/FTP/SMTP, L4 Drop-and-Catch và monitoring/Kibana dashboard được loại khỏi deliverable hiện tại để tránh lệch mục tiêu và tránh claim quá phạm vi source code.

## Done

- Real Web backend + React frontend.
- Web honeypots cho SQLi/SSTI/CMDi/SSRF.
- HAProxy gateway normal/honeypot mode.
- Debug/attack exposure mode.
- Session route map theo cookie `sid`.
- Endpoint-scoped routing để route honeypot không làm hỏng API surface khác.
- Structured service logs mount ra host.
- LLM analyzer đọc logs, parse body/context, build `web_state`.
- Rule fallback cho SQLi/SSTI/CMDi/SSRF khi không có LLM key.
- Routing controller `/decide` dùng trained JSON model.
- Offline RL training bằng torch local/VM, CQL.
- Current trained model artifact được track trong repo.
- Synthetic Web-only data generator.
- Replay buffer exporter.
- Web replay-buffer traffic generator.
- Mixed synthetic + replay dataset builder.
- Strict grouped validation và per-action/source metrics cho RL training.
- Metric evaluator từ host-mounted logs.
- Centralized control-plane docs.

## Remaining Plan

### 1. Runtime Metric Report

- Chạy demo/test trên log sạch nếu cần số liệu nộp báo cáo.
- Sinh report bằng `make evaluate-metrics`.
- Dùng `logs/metrics_report.json` để báo cáo metric trong proposal.

### 2. RL Maintenance

- Khi có replay buffer mới, build lại mixed dataset và train theo `RL_TRAINING_SUMMARY.md`.
- Giữ `gamma=0.0` cho Web routing correctness hiện tại.
- Chỉ track runtime model artifact mới nhất.

### 3. Metrics/Report

- Dùng `logs/metrics_report.json` để báo cáo:
  - Honeypot engagement rate.
  - Avg requests after adaptive rerouting.
  - Session length.
  - Correct honeypot routing rate.
  - False rerouting rate on benign sessions.
  - Normal-service continuity rate.
- Nếu metric nào `null`, cần sinh thêm traffic tương ứng thay vì sửa state RL.

### 4. Demo Polish

- Kiểm tra attack mode không expose debug endpoints.
- Kiểm tra `/api/health` không leak backend/honeypot identity trong attack mode.
- Kiểm tra SSTI honeypot vẫn render Markdown tự nhiên khi payload có `{{7*7}}`.
- Kiểm tra route maps được clear trước demo.

### 5. Optional Improvements

- Provider abstraction cho LLM analyzer.
- Retry/backoff cho LLM call.
- Memory decay rõ hơn trong analyzer.
- Thêm script report HTML/Markdown từ metrics JSON nếu cần nộp báo cáo đẹp hơn.

## Commands

```bash
cd adaptive_honeypot_system

make up
make mode-debug
make mode-normal
make clear-routes

make test-adaptive-attacks
make generate-replay-buffer PYTHON=../.venv/bin/python
make build-training-dataset PYTHON=../.venv/bin/python RL_REPLAY_REPEAT=100
make evaluate-metrics PYTHON=../.venv/bin/python

make gen-fake-data PYTHON=../.venv/bin/python
../.venv/bin/python -B control_plane/rl_agent/train_offline.py \
  --dataset control_plane/rl_agent/data/mixed_train_transitions.jsonl \
  --output control_plane/rl_agent/artifacts/rl_agent_linear.json \
  --algorithm cql \
  --epochs 80 \
  --gamma 0.0 \
  --batch-size 512 \
  --cql-alpha 1.0 \
  --behavior-cloning-weight 0.35 \
  --init-policy random \
  --split-strategy grouped \
  --val-ratio 0.2
docker compose -f docker-compose.yml up -d --force-recreate routing_controller llm_analyzer
curl -s -X POST http://localhost:8001/model/reload | python -m json.tool
```
