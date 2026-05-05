# Hướng dẫn RL Training và Thuật toán

Tài liệu này mô tả:
- Cách chạy pipeline train RL offline.
- Thuật toán RL hiện đang dùng.
- Cách test routing controller trong Docker Compose.

## 0) Nguyên tắc control plane bất đồng bộ

Stack tuân theo kiến trúc đề xuất:
- Data plane (`gateway` + các service) phục vụ request trực tiếp.
- Control plane (`routing_controller`, RL model, và sau này là LLM analyzer) cập nhật route map bất đồng bộ.

Không có phụ thuộc đồng bộ từ request path vào inference của control plane,
nên traffic web không bị chặn khi control plane chậm hoặc restart.

## 1) Phạm vi component

Phạm vi control plane hiện tại (chưa tính LLM analyzer):
- `control_plane/rl_agent/generate_fake_data.py`
- `control_plane/rl_agent/train_offline.py`
- `control_plane/rl_agent/agent.py`
- `control_plane/routing_controller/main.py`
- `control_plane/llm_analyzer/analyzer.py` (dummy analyzer cho Web MVP, chưa phải LLM thật)

`routing_controller` đã được wiring trong `docker-compose.yml`.

## 2) Chính sách phụ thuộc (quan trọng)

- PyTorch chỉ dùng để train offline trên máy local.
- Tuyệt đối không cài `torch` trong Docker runtime của hệ thống.
- Runtime controller chỉ đọc JSON weights (`LinearQAgent`) và không phụ thuộc torch.
- Web MVP có thể chạy `RL_POLICY_MODE=heuristic` để dùng dummy subtype-based policy mà không cần model artifact.
- Yêu cầu local để train: `control_plane/rl_agent/requirements-local.txt`.

## 3) Thiết kế state và action

### State
- Vector cố định 24 chiều (`STATE_DIM = 24`), đồng bộ với proposal.
- Gồm protocol one-hot, metrics session, payload signals, routing state, semantic-like features.
- Generator dataset hiện tại mô phỏng các trường này (chưa phụ thuộc LLM).

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
- Kiến trúc: `nn.Linear(24, 8)`
- Tối ưu: `AdamW` + weight decay (`l2`) + gradient clipping.
- Loss: `MSE(Q(s,a), target)`.

Target cho từng transition `(s, a, r, s', done)`:
- Nếu `done`: `y = r`
- Nếu chưa done:
  - `y = r + gamma * max_{a' hop le theo protocol(s')} Q(s', a')`

Sau khi train, model được export về JSON (`weights`, `bias`) để runtime controller sử dụng.

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

### Kiểm tra torch không có trong container runtime

```bash
docker compose exec routing_controller python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec backend python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec cmdi_pot python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
```

Kết quả mong đợi: đều `False`.

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
    "protocol": "http",
    "session_id": "sid_demo_001",
    "apply_route": true,
    "state": [1,0,0,0,0.2,0.8,0.7,0.6,0.4,1,0,0,0,0.9,0.05,0.03,0.02,0.7,0,0.1,0.7,0.5,0.9,0.2]
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
- Kiểm tra kết quả split: A => `ssti-honeypot`, B => `real-backend`.

### End-to-end adaptive web test

```bash
make test-adaptive-web
```

Script sẽ:
- Ép gateway về normal-first mode.
- Chạy dummy analyzer và routing controller ở `RL_POLICY_MODE=heuristic`.
- Gửi SQLi-like payload vào real backend search endpoint.
- Đợi analyzer poll Elasticsearch, dựng state 24D và gọi `/decide`.
- Xác nhận request tiếp theo cùng `sid` được route sang SQLi honeypot.

## 10) Giới hạn hiện tại

- `llm_analyzer` hiện là dummy/rule-based analyzer; LLM thật và memory/stateful analysis vẫn chưa implement.
- Mô hình hiện tại là linear Q approximation, chưa phải DQN/BCQ đầy đủ.
- Backend route cho non-HTTP (`ssh_honeypot`, `ftp_honeypot`, `smtp_honeypot`) là placeholder cho giai đoạn L4.
- Dataset hiện tại synthetic; chất lượng thực tế cần dữ liệu từ log thật.

## 11) Hướng phát triển tiếp

- Nối state builder thật từ pipeline LLM/log.
- Train trên replay buffer tách từ traffic logs.
- Thêm integration test đầy đủ: `log ingest -> state build -> RL decide -> routing update`.
