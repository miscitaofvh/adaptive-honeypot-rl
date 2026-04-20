# Huong dan RL Training va Thuat toan

Tai lieu nay mo ta:
- Cach chay pipeline train RL offline.
- Thuat toan RL hien dang dung.
- Cach test routing controller trong Docker Compose.

## 0) Nguyen tac control plane bat dong bo

Stack tuan theo kien truc de xuat:
- Data plane (`gateway` + cac service) phuc vu request truc tiep.
- Control plane (`routing_controller`, RL model, va sau nay la LLM analyzer) cap nhat route map bat dong bo.

Khong co phu thuoc dong bo tu request path vao inference cua control plane,
nen traffic web khong bi chan khi control plane cham hoac restart.

## 1) Pham vi component

Pham vi control plane hien tai (chua tinh LLM analyzer):
- `control_plane/rl_agent/generate_fake_data.py`
- `control_plane/rl_agent/train_offline.py`
- `control_plane/rl_agent/agent.py`
- `control_plane/routing_controller/main.py`

`routing_controller` da duoc wiring trong `docker-compose.yml`.

## 2) Chinh sach phu thuoc (quan trong)

- PyTorch chi dung de train offline tren may local.
- Tuyet doi khong cai `torch` trong Docker runtime cua he thong.
- Runtime controller chi doc JSON weights (`LinearQAgent`) va khong phu thuoc torch.
- Yeu cau local de train: `control_plane/rl_agent/requirements-local.txt`.

## 3) Thiet ke state va action

### State
- Vector co dinh 24 chieu (`STATE_DIM = 24`), dong bo voi proposal.
- Gom protocol one-hot, metrics session, payload signals, routing state, semantic-like features.
- Generator dataset hien tai mo phong cac truong nay (chua phu thuoc LLM).

### Action space
Dinh nghia trong `agent.py`:
- `0`: `KEEP_NORMAL`
- `1`: `ROUTE_SQLI`
- `2`: `ROUTE_SSTI`
- `3`: `ROUTE_CMDI`
- `4`: `ROUTE_SSRF`
- `5`: `ROUTE_SSH`
- `6`: `ROUTE_FTP`
- `7`: `ROUTE_SMTP`

### Protocol-based action masking
Chi cho phep action hop le theo protocol:
- HTTP: keep + SQLI/SSTI/CMDI/SSRF
- SSH: keep + SSH honeypot
- FTP: keep + FTP honeypot
- SMTP: keep + SMTP honeypot

Mask duoc enforce boi `allowed_action_indices()` khi inference va khi tinh training target.

## 4) Thuat toan RL hien tai

Implementation hien tai la offline Q-learning voi mo hinh tuyen tinh tren PyTorch:

- Mo hinh: `Q(s, a) = w_a^T s + b_a`
- Kien truc: `nn.Linear(24, 8)`
- Toi uu: `AdamW` + weight decay (`l2`) + gradient clipping.
- Loss: `MSE(Q(s,a), target)`.

Target cho tung transition `(s, a, r, s', done)`:
- Neu `done`: `y = r`
- Neu chua done:
  - `y = r + gamma * max_{a' hop le theo protocol(s')} Q(s', a')`

Sau khi train, model duoc export ve JSON (`weights`, `bias`) de runtime controller su dung.

## 5) Setup moi truong train local

Tu root repo:

```bash
cd adaptive_honeypot_system/control_plane/rl_agent
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-local.txt
```

Luu y: buoc nay chi danh cho may local train offline, khong dung trong Docker runtime.

## 6) Sinh du lieu offline

Tu `adaptive_honeypot_system/`:

```bash
python control_plane/rl_agent/generate_fake_data.py \
  --sessions 800 \
  --min-steps 6 \
  --max-steps 14 \
  --output control_plane/rl_agent/data/fake_transitions.jsonl
```

Hoac dung Makefile:

```bash
make gen-fake-data
```

Output mong doi:
- File JSONL, moi dong 1 transition.
- Cac truong: `state`, `action`, `reward`, `next_state`, `done`, `protocol`, `optimal_action`.

## 7) Train offline RL

Tu `adaptive_honeypot_system/`:

```bash
python control_plane/rl_agent/train_offline.py \
  --dataset control_plane/rl_agent/data/fake_transitions.jsonl \
  --output control_plane/rl_agent/artifacts/rl_agent_linear.json \
  --epochs 40 \
  --log-every 5
```

Hoac dung Makefile:

```bash
make train-rl
```

Sinh data + train trong 1 lenh:

```bash
make train-rl-fresh
```

Tao dummy model de test split-route (HTTP luon vao SSTI):

```bash
make make-dummy-model
```

Artifact mong doi:
- `control_plane/rl_agent/artifacts/rl_agent_linear.json`
- `control_plane/rl_agent/artifacts/rl_agent_linear.metrics.json`

## 8) Validate nhanh sau train

### Kiem tra syntax

```bash
python -m py_compile \
  control_plane/rl_agent/agent.py \
  control_plane/rl_agent/generate_fake_data.py \
  control_plane/rl_agent/train_offline.py \
  control_plane/routing_controller/main.py
```

### Kiem tra chat luong co ban
Theo doi log train va metrics:
- `train_acc`
- `val_acc`
- `val_proxy_reward`

Muc toi thieu:
- Khong co runtime exception.
- Co file metrics.
- Validation accuracy on dinh, tot hon moc random.

## 9) Chay va test routing controller trong stack

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

### Kiem tra torch khong co trong container runtime

```bash
docker compose exec routing_controller python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec backend python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec cmdi_pot python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
```

Ket qua mong doi: deu `False`.

### Reload model sau khi train

```bash
curl -s -X POST http://localhost:8001/model/reload | jq .
```

### Route helper cho test tich hop

Set route theo session:

```bash
curl -s -X POST "http://localhost:8001/route/session/sid_demo_001?backend=ssti_api" | jq .
```

Set route theo source IP:

```bash
curl -s -X POST "http://localhost:8001/route/ip/172.22.0.99?backend=ssti_api" | jq .
```

### Test quyet dinh route HTTP

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

Mong doi:
- Controller tra ve `action_name` va `backend`.
- Neu `apply_route=true`, map se duoc cap nhat qua `routing_update.sh`.

### Xoa route test thu cong

```bash
curl -s -X DELETE http://localhost:8001/route/session/sid_demo_001 | jq .
```

### End-to-end split test (2 IP)

```bash
make test-rl-split-ip
```

Script se:
- Ep gateway ve `TEST_HONEYPOT=false` (normal-first).
- Tao dummy model va reload.
- Tao 2 container client tam (IP khac nhau).
- Chi apply route cho client A qua `POST /decide` voi `source_ip`.
- Kiem tra ket qua split: A => `ssti-honeypot`, B => `real-backend`.

## 10) Gioi han hien tai

- `llm_analyzer` chua noi end-to-end, semantic features van la synthetic.
- Mo hinh hien tai la linear Q approximation, chua phai DQN/BCQ day du.
- Backend route cho non-HTTP (`ssh_honeypot`, `ftp_honeypot`, `smtp_honeypot`) la placeholder cho giai doan L4.
- Dataset hien tai synthetic; chat luong thuc te can du lieu tu log that.

## 11) Huong phat trien tiep

- Noi state builder that tu pipeline LLM/log.
- Train tren replay buffer tach tu traffic logs.
- Them integration test day du: `log ingest -> state build -> RL decide -> routing update`.
