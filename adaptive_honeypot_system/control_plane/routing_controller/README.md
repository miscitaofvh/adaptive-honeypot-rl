# Routing Controller

Component nay la FastAPI service dieu khien HAProxy dynamic maps.

Chuc nang:

- Load RL model JSON neu `RL_POLICY_MODE=model`.
- Chay dummy heuristic policy neu `RL_POLICY_MODE=heuristic`.
- Nhan 24D state vector qua `/decide`.
- Chon action/backend va cap nhat session/IP map bang `gateway/routing_update.sh`.
- Expose route inspection endpoints de debug.

Endpoints:

- `GET /health`
- `POST /model/reload`
- `POST /decide`
- `POST /route/session/{session_id}`
- `DELETE /route/session/{session_id}`
- `GET /route/session/{session_id}`
- `POST /route/ip/{source_ip}`
- `DELETE /route/ip/{source_ip}`
- `GET /route/ip/{source_ip}`
- `GET /routes`

Policy modes:

- `model`: dung `LinearQAgent` JSON artifact.
- `heuristic`: dummy RL stand-in, route HTTP theo web subtype scores trong state.

Luu y:

- L4 routing dang bi disable bang `L4_ROUTING_ENABLED=false`.
- Non-HTTP backend placeholders se bi reject cho toi khi HAProxy TCP/L4 duoc implement.

