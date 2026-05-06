# LLM Analyzer

This component is the asynchronous analyzer for the Web MVP control plane.

Responsibilities:

- Poll Elasticsearch for recent structured backend/honeypot logs.
- Build session context from HAProxy gateway logs.
- Enrich gateway events with service-level `body_preview` from backend/honeypot logs.
- Call Groq when `GROQ_API_KEY` is available.
- Validate semantic output for SQLi, CMDI, SSTI, SSRF, evasion, progression, and memory.
- Build the current runtime 24D state vector and call the routing controller.
- Call `routing_controller /decide` asynchronously.
- Log route-decision events for observability.

Important constraints:

- It currently calls Groq directly; provider abstraction/fallback is still incomplete.
- It does not train or run a real RL model.
- It keeps the control plane asynchronous: request traffic never waits on this service.
- If Groq is missing or times out, the next implementation step is to fall back to rule-based state extraction so the demo remains stable.
- Runtime code still builds state schema v1 24D; approved target schema is `rl_state_v2_16`.

Runtime endpoints:

- `GET /health`: debug mode tra ve analyzer stats; attack mode chi tra ve `{"status":"ok"}`.

Exposure modes:

- `EXPOSURE_MODE=debug`: bat docs/OpenAPI va health stats.
- `EXPOSURE_MODE=attack`: tat docs/OpenAPI va an analyzer stats.

State migration target:

- `rl_state_v2_16`, 16 floats.
- `protocol` is `/decide` metadata, not part of the tensor.
- LLM confidence should scale semantic fields before building the tensor, while the raw confidence remains in logs for debugging.
