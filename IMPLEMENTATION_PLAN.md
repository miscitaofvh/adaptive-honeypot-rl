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
- Offline RL training bằng torch local, default CQL.
- Synthetic Web-only data generator.
- Replay buffer exporter.
- Web replay-buffer traffic generator.
- Metric evaluator từ host-mounted logs.
- Centralized control-plane docs.

## Remaining Plan

### 1. Data Collection

- Chạy nhiều phiên test Web attack/benign qua gateway.
- Sinh replay buffer bằng `make generate-replay-buffer`.
- Lưu lại metrics report sau mỗi batch bằng `make evaluate-metrics`.
- Đảm bảo dataset có đủ bốn attack surface và benign sessions.

### 2. RL Experiments

- Train CQL từ synthetic dataset lớn để có baseline ổn định.
- Train CQL từ replay buffer thật khi đủ dữ liệu.
- Train Q-learning baseline để so sánh.
- Báo cáo accuracy/proxy reward của train script và proposal metrics từ runtime logs riêng biệt.

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
make evaluate-metrics PYTHON=../.venv/bin/python

make gen-fake-data PYTHON=../.venv/bin/python
make train-rl PYTHON=../.venv/bin/python
docker compose -f docker-compose.yml up -d --force-recreate routing_controller llm_analyzer
curl -s -X POST http://localhost:8001/model/reload | python -m json.tool
```
