# Báo cáo tiến độ

Cập nhật: 2026-05-05

## 1) Tổng quan hiện tại

Dự án đã hoạt động đủ cho data plane + control plane trong web scope:
- Data plane: gateway HAProxy + real backend/frontend + 4 web honeypot.
- Control plane: routing controller FastAPI chạy runtime, cập nhật route map theo session/IP.
- RL: đã tách rõ train offline (local) và runtime inference (container); Web MVP có thêm dummy heuristic RL mode.
- Dummy LLM analyzer: đã có service tạm thời poll Elasticsearch, dựng state 24D và gọi routing controller bất đồng bộ.
- Observability: Filebeat -> Elasticsearch -> Kibana vẫn hoạt động.

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
- [x] Session map steering và source-IP map steering qua `routing_update.sh`.
- [x] Real backend có `POST /api/articles/search` để khớp SQLI honeypot contract.
- [x] Gỡ config HAProxy legacy không dùng (`gateway/haproxy.cfg`) để tránh nhầm lẫn.

### Control plane + RL
- [x] `routing_controller` expose đầy đủ API: `/health`, `/model/reload`, `/decide`, add/remove route theo session/IP.
- [x] Refactor train offline sang PyTorch trong `train_offline.py`.
- [x] Thêm `requirements-local.txt` cho train local (`torch` local-only).
- [x] Runtime controller vẫn dùng JSON linear weights (`LinearQAgent`), không cần torch trong container.
- [x] Thêm `RL_POLICY_MODE=heuristic` làm dummy RL policy cho Web MVP.
- [x] Thêm route inspection API: `/routes`, `GET /route/session/{sid}`, `GET /route/ip/{ip}`.
- [x] Thêm route cleanup API `DELETE /routes` và Make target `make clear-routes`.
- [x] Chặn non-HTTP/L4 placeholder khi `L4_ROUTING_ENABLED=false`.
- [x] Thêm dummy `llm_analyzer` service (`/health`, `/analyze`) cho flow `log -> state -> decide -> route`.
- [x] Split-IP E2E `test_two_ip_split_routing.sh` pass (1 IP honeypot, 1 IP backend thật).

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
docker compose ps -a
curl -s http://localhost:8001/health
curl -s http://localhost:18080/api/health
make test-routes
make test-honeypots
make test-rl-split-ip
make test-adaptive-web
make validate
```

Kết quả:
- [x] Tất cả service Up.
- [x] Routing controller health PASS.
- [x] Gateway `/api/health` PASS (`real-backend`).
- [x] `make test-routes` PASS.
- [x] `make test-honeypots` PASS.
- [x] `make test-rl-split-ip` PASS (Client A -> `ssti-honeypot`, Client B -> `real-backend`).
- [x] `make test-adaptive-web` PASS (`log -> dummy analyzer -> dummy RL/controller -> HAProxy session route -> SQLI honeypot`).
- [x] `make validate` PASS (syntax check, routing controller health, honeypot tests, core route smoke).
- [x] Route maps sạch sau E2E (`session_routes={}`, `ip_routes={}`).

## 4) Ràng buộc đã xác minh

- [x] Không cài `torch` trong Docker runtime services (`routing_controller`, `backend`, `honeypots`).
- [x] `torch` chỉ dùng local để train offline.
- [x] Chưa test lại full benchmark train thật vì hiện chưa có dataset thật.

## 5) Lưu ý vận hành

- Lệnh make/compose nên chạy trong `adaptive_honeypot_system/`.
- `make train-rl` cần dataset local (`control_plane/rl_agent/data/fake_transitions.jsonl`).
- Nếu data rỗng, dùng `make train-rl-fresh` để tự sinh data rồi train.

## 6) Việc còn lại

- [ ] Thay dummy `llm_analyzer` bằng LLM analyzer thật có memory/stateful analysis.
- [ ] Thay dummy policy bằng policy RL train/evaluate đầy đủ trên dataset thật.
- [ ] Hoàn thiện benchmark (route accuracy, false reroute, engagement).
- [ ] Hoàn thiện L4 SSH/FTP/SMTP Drop-and-Catch nếu còn trong scope demo.
  
