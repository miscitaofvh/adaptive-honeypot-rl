# Routing Controller

Component nay la FastAPI service dieu khien HAProxy dynamic maps.

Chuc nang:

- Load RL model JSON neu `RL_POLICY_MODE=model`.
- Chay dummy heuristic policy neu `RL_POLICY_MODE=heuristic`.
- Nhan 24D state vector qua `/decide`.
- Chon action/backend va cap nhat session/IP map bang `gateway/routing_update.sh`.
- Expose route inspection endpoints trong debug mode de test.

Endpoints:

- Always available internally: `POST /decide`.
- `GET /health`: debug mode tra ve metadata; attack mode chi tra ve `{"status":"ok"}`.
- Debug-only endpoints: `POST /model/reload`, `POST|DELETE|GET /route/session/{session_id}`, `POST|DELETE|GET /route/ip/{source_ip}`, `GET|DELETE /routes`.

Exposure modes:

- `EXPOSURE_MODE=debug`: bat docs/OpenAPI va cac route inspection/update endpoints de manual test.
- `EXPOSURE_MODE=attack`: tat docs/OpenAPI va tra `404` cho cac endpoint debug nhu `/routes`; giu `/decide` cho analyzer noi bo.

Policy modes:

- `model`: dung `LinearQAgent` JSON artifact.
- `heuristic`: dummy RL stand-in, route HTTP theo web subtype scores trong state.

Luu y:

- L4 routing dang bi disable bang `L4_ROUTING_ENABLED=false`.
- Non-HTTP backend placeholders se bi reject cho toi khi HAProxy TCP/L4 duoc implement.
