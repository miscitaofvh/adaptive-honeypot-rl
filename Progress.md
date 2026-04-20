# Bao cao tien do

Cap nhat: 2026-04-20

## 1) Tong quan hien tai

Du an da hoat dong du cho data plane + control plane trong web scope:
- Data plane: gateway HAProxy + real backend/frontend + 4 web honeypot.
- Control plane: routing controller FastAPI chay runtime, cap nhat route map theo session/IP.
- RL: da tach ro train offline (local) va runtime inference (container).
- Observability: Filebeat -> Elasticsearch -> Kibana van hoat dong.

Control plane tiep tuc duoc giu theo nguyen tac bat dong bo, khong chan request path.

## 2) Hang muc da hoan thanh

### Data plane
- [x] Route theo 2 mode (`TEST_HONEYPOT=true|false`).
- [x] Mapping endpoint trong honeypot mode:
  - `/api/tools/ping` -> CMDI
  - `/api/tools/preview` -> SSTI
  - `/api/tools/fetch` -> SSRF
  - `/api/articles/search` -> SQLI
- [x] `/api/health` route rieng ve real backend (`health_api`).
- [x] Session map steering va source-IP map steering qua `routing_update.sh`.

### Control plane + RL
- [x] `routing_controller` expose day du API: `/health`, `/model/reload`, `/decide`, add/remove route theo session/IP.
- [x] Refactor train offline sang PyTorch trong `train_offline.py`.
- [x] Them `requirements-local.txt` cho train local (`torch` local-only).
- [x] Runtime controller van dung JSON linear weights (`LinearQAgent`), khong can torch trong container.
- [x] Split-IP E2E `test_two_ip_split_routing.sh` pass (1 IP honeypot, 1 IP backend that).

### Test harness
- [x] `test_honeypots.py` o root repo hoat dong on dinh.
- [x] `make test-honeypots` pass.
- [x] Da co fallback URL IPv6 (`::1`) cho SSTI trong script test de tranh timeout loopback IPv4.

### Repo hygiene (de push)
- [x] Viet hoa tai lieu chinh (README, progress, RL guide).
- [x] Don file phat sinh trong `rl_agent/data`, `rl_agent/artifacts`, `__pycache__`.
- [x] Bo sung `.gitignore` de tranh commit nham data/model local va `.env.bak`.

## 3) Ket qua test da xac nhan

Da chay trong thu muc `adaptive_honeypot_system/`:

```bash
docker compose ps -a
curl -s http://localhost:8001/health
curl -s http://localhost:8080/api/health
make test-routes
make test-honeypots
make test-rl-split-ip
```

Ket qua:
- [x] Tat ca service Up.
- [x] Routing controller health PASS.
- [x] Gateway `/api/health` PASS (`real-backend`).
- [x] `make test-routes` PASS.
- [x] `make test-honeypots` PASS.
- [x] `make test-rl-split-ip` PASS (Client A -> `ssti-honeypot`, Client B -> `real-backend`).

## 4) Rang buoc da xac minh

- [x] Khong cai `torch` trong Docker runtime services (`routing_controller`, `backend`, `honeypots`).
- [x] `torch` chi dung local de train offline.
- [x] Chua test lai full benchmark train that vi hien chua co dataset that.

## 5) Luu y van hanh

- Lenh make/compose nen chay trong `adaptive_honeypot_system/`.
- `make train-rl` can dataset local (`control_plane/rl_agent/data/fake_transitions.jsonl`).
- Neu data rong, dung `make train-rl-fresh` de tu sinh data roi train.

## 6) Viec con lai

- [ ] Noi `llm_analyzer` vao loop adaptive end-to-end.
- [ ] Thay dummy policy bang policy RL train/evaluate day du tren dataset that.
- [ ] Hoan thien benchmark (route accuracy, false reroute, engagement).
- [ ] Don warning Pydantic namespace (`model_path`) trong routing controller.
  