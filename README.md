# Adaptive Honeypot System

## 1) Tong quan
Day la bo lab local de nghien cuu adaptive honeypot routing, gom day du data plane + control plane.

Kien truc hien tai:
- Data plane: HAProxy gateway voi 2 mode normal/honeypot.
- Real service: Flask backend + React frontend.
- Lop honeypot web: CMDI, SQLI, SSTI, SSRF.
- Control plane: FastAPI routing controller + RL model loading/inference.
- Observability: Filebeat -> Elasticsearch -> Kibana.

Nguyen tac quan trong: control plane chay bat dong bo voi luong request, khong chen duong dong bo vao request path.

## 2) Trang thai hien tai
- Da co route theo mode qua `TEST_HONEYPOT=true|false`.
- Da co map endpoint -> honeypot trong honeypot mode.
- Da co route rieng `/api/health` ve real backend o ca 2 mode.
- Da co dynamic routing theo session va source IP qua HAProxy map.
- Da co API routing controller (`/health`, `/model/reload`, `/decide`, add/remove route).
- Da co bo RL offline + dummy model de test route co tinh lap lai.
- Da co script test honeypot doc lap (`test_honeypots.py`) + Make target.
- Da co test split-IP end-to-end (1 IP vao honeypot, 1 IP vao backend that).

## 3) Chinh sach PyTorch (bat buoc)
- PyTorch chi dung de train RL offline tren may local.
- Khong cai PyTorch trong bat ky Docker image runtime nao.
- Khong them `torch` vao requirements cua `routing_controller` hay service runtime.
- File local-only cho train: `adaptive_honeypot_system/control_plane/rl_agent/requirements-local.txt`.

## 4) Cau truc thu muc

```text
adaptive_honeypot_system/
|-- Makefile
|-- docker-compose.yml
|-- gateway/
|-- honeypots/
|-- real_service/
|-- observability/
`-- control_plane/
    |-- llm_analyzer/
    |-- rl_agent/
    `-- routing_controller/

test_honeypots.py  (o root repo)
```

## 5) Hanh vi routing

### Chon mode
- Gateway doc `TEST_HONEYPOT` trong `.env`:
  - `false` -> `haproxy.normal.cfg`
  - `true` -> `haproxy.honeypot.cfg`

### Normal mode
- Mac dinh request vao real backend.
- Session/IP map co the override backend.

### Honeypot mode
- Mac dinh request vao endpoint honeypot.
- Mapping endpoint:
  - `/api/tools/ping` -> CMDI
  - `/api/tools/preview` -> SSTI
  - `/api/tools/fetch` -> SSRF
  - `/api/articles/search` -> SQLI
- `/api/health` luon vao `health_api` (real backend).

### Dynamic map update
- Session map: `/etc/haproxy/maps/session_routes.map`
- IP map: `/etc/haproxy/maps/ip_honeypot.map`
- Script cap nhat: `gateway/routing_update.sh`

## 6) API control plane
- `GET /health`
- `POST /model/reload`
- `POST /decide`
- `POST /route/session/{session_id}`
- `DELETE /route/session/{session_id}`
- `POST /route/ip/{source_ip}`
- `DELETE /route/ip/{source_ip}`

URL dich vu: `http://localhost:8001`

## 7) Chay nhanh

Luu y: toan bo lenh van hanh chay trong `adaptive_honeypot_system/`.

```bash
cd adaptive_honeypot_system
cp .env.example .env
make up
```

## 8) Lenh kiem thu nhanh

```bash
cd adaptive_honeypot_system
docker compose ps -a
curl -s http://localhost:8001/health
curl -s http://localhost:8080/api/health
make test-routes
make test-honeypots
make test-rl-split-ip
```

## 9) Kiem tra rang buoc "khong torch trong container"

```bash
cd adaptive_honeypot_system
docker compose exec routing_controller python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec backend python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
docker compose exec cmdi_pot python -c "import importlib.util; print(importlib.util.find_spec('torch') is not None)"
```

Ket qua mong doi: tat ca deu `False`.

## 10) Ket qua xac nhan gan nhat
Lan chay hop nhat gan nhat (2026-04-19):
- Container status: PASS
- Routing controller health: PASS
- Gateway `/api/health`: PASS
- `make test-routes`: PASS
- `make test-honeypots`: PASS
- `make test-rl-split-ip`: PASS
  - Client A -> `ssti-honeypot`
  - Client B -> `real-backend`

## 11) Service URLs
- Gateway: `http://localhost:8080`
- Routing controller: `http://localhost:8001`
- HAProxy stats: `http://localhost:8404/stats`
- Kibana: `http://localhost:5601`
- Elasticsearch: `http://localhost:9200`
- Honeypot direct ports:
  - CMDI: `http://localhost:5002`
  - SQLI: `http://localhost:5003`
  - SSTI: `http://localhost:5004`
  - SSRF: `http://localhost:5005`

## 12) Gioi han hien tai
- `llm_analyzer` chua noi day du vao loop adaptive end-to-end.
- Policy dung trong split-IP demo la dummy model de test tinh on dinh, chua phai policy production.
- Routing controller hien van co warning Pydantic namespace (`model_path`) nhung khong anh huong chuc nang.
