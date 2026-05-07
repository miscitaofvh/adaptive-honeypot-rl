# Hướng dẫn RL Training và Thuật toán

Tài liệu này mô tả:
- Cách chạy pipeline train RL offline.
- Thuật toán RL hiện đang dùng.
- Cách test routing controller trong Docker Compose.

## 0) Nguyên tắc control plane bất đồng bộ

Stack tuân theo kiến trúc đề xuất:
- Data plane (`gateway` + các service) phục vụ request trực tiếp.
- Control plane (`llm_analyzer`, `routing_controller`, RL model/runtime policy) cập nhật route map bất đồng bộ.

Không có phụ thuộc đồng bộ từ request path vào inference của control plane,
nên traffic web không bị chặn khi control plane chậm hoặc restart.

## 1) Phạm vi component

Phạm vi control plane hiện tại:
- `control_plane/rl_agent/generate_fake_data.py`
- `control_plane/rl_agent/train_offline.py`
- `control_plane/rl_agent/agent.py`
- `control_plane/rl_agent/service.py` (Torch RL service rieng cho debug/export/one-epoch proxy train)
- `control_plane/routing_controller/main.py`
- `control_plane/llm_analyzer/analyzer.py` (poll Elasticsearch, gọi Groq khi có key, dựng state runtime hiện tại và gọi `/decide`)

`routing_controller` đã được wiring trong `docker-compose.yml`.

## 2) Chính sách phụ thuộc (quan trọng)

- PyTorch chỉ dùng để train offline trên máy local và trong service riêng `rl_agent`.
- Không cài `torch` trong `routing_controller`, real service, honeypots, gateway hoặc analyzer.
- Runtime controller chỉ đọc JSON weights (`LinearQAgent`) và không phụ thuộc torch.
- `rl_agent` container có Torch để demo/debug/export model artifact, nhưng không nằm trên request path.
- Web MVP có thể chạy `RL_POLICY_MODE=heuristic` để dùng dummy subtype-based policy mà không cần model artifact.
- Yêu cầu local để train: `control_plane/rl_agent/requirements-local.txt`.

## 3) Thiết kế state và action

### State
- Runtime code hiện tại dùng `rl_state_v2_16` (`STATE_DIM = 16`) trong `agent.py`, `routing_controller`, analyzer và generator.
- Schema này giảm từ v1 24D xuống 16 chiều, thực tiễn hơn cho Web MVP nhưng vẫn mở rộng được SSH/FTP/SMTP.
- `protocol` không nằm trong tensor v2. Nó là metadata bắt buộc của `/decide`, dùng cho action masking và normalizer profile theo giao thức.

Schema target v2:

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

Các trường bị bỏ khỏi v1 24D:
- `protocol_onehot`: chuyển thành metadata.
- `attack_category_onehot`: thay bằng target-specific scores.
- `attack_vector_shift`: merge vào `intent_stability_score`.
- `memory_decay_weight`: bỏ cho tới khi có decay thật.
- `llm_confidence`: dùng để scale các field LLM trước khi build tensor, log riêng để debug.

### Action space
Định nghĩa trong `agent.py`:
- `0`: `KEEP_NORMAL`
- `1`: `ROUTE_SQLI`
- `2`: `ROUTE_SSTI`
- `3`: `ROUTE_CMDI`
- `4`: `ROUTE_SSRF`
- `5`: `ROUTE_SSH`
- `6`: `ROUTE_FTP`
- `7`: `ROUTE_SMTP`

### Protocol-based action masking
Chỉ cho phép action hợp lệ theo protocol:
- HTTP: keep + SQLI/SSTI/CMDI/SSRF
- SSH: keep + SSH honeypot
- FTP: keep + FTP honeypot
- SMTP: keep + SMTP honeypot

Mask được enforce bởi `allowed_action_indices()` khi inference và khi tính training target.

## 4) Thuật toán RL hiện tại

Implementation hiện tại là offline Q-learning với mô hình tuyến tính trên PyTorch:

- Mô hình: `Q(s, a) = w_a^T s + b_a`
- Kiến trúc runtime hiện tại: `nn.Linear(16, 8)` / JSON linear weights 16D.
- Tối ưu: `AdamW` + weight decay (`l2`) + gradient clipping.
- Loss: `MSE(Q(s,a), target)`.

Target cho từng transition `(s, a, r, s', done)`:
- Nếu `done`: `y = r`
- Nếu chưa done:
  - `y = r + gamma * max_{a' hop le theo protocol(s')} Q(s', a')`

Sau khi train, model được export về JSON (`weights`, `bias`) để runtime controller sử dụng.

Torch RL service hiện tại dùng cùng kiến trúc `nn.Linear(16, 8)`. Mặc định service khởi tạo `web_policy` deterministic theo subtype score để giữ demo ổn định. Endpoint debug `/train/one-epoch` chỉ chạy một proxy epoch nhỏ trên vài sample cố định; đây không phải full train và không đại diện chất lượng policy thật.

## 5) Setup môi trường train local

Từ root repo:

```bash
cd adaptive_honeypot_system/control_plane/rl_agent
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-local.txt
```

Lưu ý: bước này chỉ dành cho máy local train offline, không dùng trong Docker runtime.

## 6) Sinh dữ liệu offline

Từ `adaptive_honeypot_system/`:

```bash
python control_plane/rl_agent/generate_fake_data.py \
  --sessions 800 \
  --min-steps 6 \
  --max-steps 14 \
  --output control_plane/rl_agent/data/fake_transitions.jsonl
```

Hoặc dùng Makefile:

```bash
make gen-fake-data
```

Output mong đợi:
- File JSONL, mỗi dòng 1 transition.
- Các trường: `state`, `action`, `reward`, `next_state`, `done`, `protocol`, `optimal_action`.

## 7) Train offline RL

Từ `adaptive_honeypot_system/`:

```bash
python control_plane/rl_agent/train_offline.py \
  --dataset control_plane/rl_agent/data/fake_transitions.jsonl \
  --output control_plane/rl_agent/artifacts/rl_agent_linear.json \
  --epochs 40 \
  --log-every 5
```

Hoặc dùng Makefile:

```bash
make train-rl
```

Sinh data + train trong 1 lệnh:

```bash
make train-rl-fresh
```

Tạo dummy model để test split-route (HTTP luôn vào SSTI):

```bash
make make-dummy-model
```

Tạo dummy web policy model theo subtype `[sqli, cmdi, ssti, ssrf]`:

```bash
make make-dummy-web-model
```

Export artifact từ Torch RL service:

```bash
make rl-agent-export
```

Chạy một proxy epoch rất nhỏ rồi export artifact:

```bash
make rl-agent-one-epoch
```

Artifact mong đợi:
- `control_plane/rl_agent/artifacts/rl_agent_linear.json`
- `control_plane/rl_agent/artifacts/rl_agent_linear.metrics.json`

Lưu ý: Docker Compose mặc định dùng `RL_POLICY_MODE=heuristic` để flow demo Web chạy ổn định ngay cả khi chưa có model thật. Khi muốn test artifact JSON, đặt `RL_POLICY_MODE=model`.

## 8) Validate nhanh sau train

### Kiểm tra syntax

```bash
python -m py_compile \
  control_plane/rl_agent/agent.py \
  control_plane/rl_agent/generate_fake_data.py \
  control_plane/rl_agent/train_offline.py \
  control_plane/rl_agent/service.py \
  control_plane/routing_controller/main.py
```

### Kiểm tra chất lượng cơ bản
Theo dõi log train và metrics:
- `train_acc`
- `val_acc`
- `val_proxy_reward`

Mức tối thiểu:
- Không có runtime exception.
- Có file metrics.
- Validation accuracy ổn định, tốt hơn mốc random.

## 9) Chạy và test routing controller trong stack

### Start stack

```bash
cd adaptive_honeypot_system
docker compose up -d --build
```

Endpoint routing controller:
- `http://localhost:8001`

### Health check

```bash
curl -s http://localhost:8001/health | jq .
```

### Kiểm tra Torch chỉ có trong `rl_agent`

```bash
docker compose exec routing_controller python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec backend python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec cmdi_pot python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec rl_agent python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
```

Kết quả mong đợi: `routing_controller`, `backend`, `cmdi_pot` đều `False`; riêng `rl_agent` là `True`.

### Test Torch RL service

```bash
curl -s http://localhost:8003/health | jq .

curl -s -X POST http://localhost:8003/predict \
  -H 'Content-Type: application/json' \
  -d '{
    "state_schema": "rl_state_v2_16",
    "protocol": "http",
    "state": [0,0,0,0,0,0,0,0.9,0.05,0.05,0.05,0,0,0.2,0.4,0.8]
  }' | jq .

curl -s -X POST http://localhost:8003/export | jq .
curl -s -X POST http://localhost:8001/model/reload | jq .
```

### Reload model sau khi train

```bash
curl -s -X POST http://localhost:8001/model/reload | jq .
```

### Route helper cho test tích hợp

Set route theo session:

```bash
curl -s -X POST "http://localhost:8001/route/session/sid_demo_001?backend=ssti_api" | jq .
```

Set route theo source IP:

```bash
curl -s -X POST "http://localhost:8001/route/ip/172.22.0.99?backend=ssti_api" | jq .
```

### Test quyết định route HTTP

```bash
curl -s -X POST http://localhost:8001/decide \
  -H 'Content-Type: application/json' \
  -d '{
    "state_schema": "rl_state_v2_16",
    "protocol": "http",
    "session_id": "sid_demo_001",
    "apply_route": true,
    "state": [0.2,0.8,0.7,0.6,0.4,0,0,0.9,0.05,0.03,0.02,0,0,0.7,0.5,0.9]
  }' | jq .
```

Mong đợi:
- Controller trả về `action_name` và `backend`.
- Nếu `apply_route=true`, map sẽ được cập nhật qua `routing_update.sh`.

### Xóa route test thủ công

```bash
curl -s -X DELETE http://localhost:8001/route/session/sid_demo_001 | jq .
```

### End-to-end split test (2 IP)

```bash
make test-rl-split-ip
```

Script sẽ:
- Ép gateway về `TEST_HONEYPOT=false` (normal-first).
- Tạo dummy model và reload.
- Tạo 2 container client tạm (IP khác nhau).
- Chỉ apply route cho client A qua `POST /decide` với `source_ip`.
- Kiểm tra route theo endpoint: preview của A => `ssti-honeypot`; health/ping của A và traffic của B vẫn về `real-backend`.

### End-to-end adaptive web test

```bash
make test-adaptive-web
make test-adaptive-attacks
```

Script sẽ:
- Ép gateway về normal-first mode.
- Chạy analyzer và routing controller ở `RL_POLICY_MODE=heuristic`.
- Gửi SQLi-like payload vào real backend search endpoint.
- Đợi analyzer poll Elasticsearch, dựng state runtime hiện tại và gọi `/decide`.
- Xác nhận request tiếp theo cùng `sid` được route sang SQLi honeypot.
- Test mở rộng xác nhận SQLi/CMDi/SSTI/SSRF đều route đúng endpoint-scoped honeypot và không route sentinel `sid="-"`.

## 10) Giới hạn hiện tại

- `llm_analyzer` đã gọi Groq khi có key, có rule fallback/guardrail khi provider lỗi hoặc LLM bỏ sót payload rõ ràng; phần còn lại là provider abstraction, retry/backoff, và memory decay.
- Runtime state đã là `rl_state_v2_16`.
- Mô hình hiện tại là linear Q approximation/Torch stub, chưa phải DQN/BCQ đầy đủ.
- Backend route cho non-HTTP (`ssh_honeypot`, `ftp_honeypot`, `smtp_honeypot`) là placeholder cho giai đoạn L4.
- Dataset hiện tại synthetic; chất lượng thực tế cần dữ liệu từ log thật.

## 11) Hướng phát triển tiếp

- Tách feature computation còn nằm trong analyzer sang state builder package.
- Tách rule fallback/guardrail của LLM analyzer thành module testable riêng.
- Train trên replay buffer tách từ traffic logs.
- Thêm integration test đầy đủ: `log ingest -> state build -> RL decide -> routing update`.
