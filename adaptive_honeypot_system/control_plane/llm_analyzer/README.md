# LLM Analyzer

This component is the asynchronous analyzer for the Web MVP control plane.

Responsibilities:

- Poll Elasticsearch for recent structured backend/honeypot logs.
- Build session context from HAProxy gateway logs.
- Enrich gateway events with service-level `body_preview` from backend/honeypot logs.
- Defer body-bearing gateway events briefly when Filebeat/Elasticsearch ingests the gateway log before the service log.
- Call Groq when `GROQ_API_KEY` is available.
- Validate semantic output for SQLi, CMDI, SSTI, SSRF, evasion, progression, and memory.
- Apply a deterministic rule guardrail when LLM output misses an obvious web subtype from request-body evidence.
- Build the current runtime `rl_state_v2_16` state vector and call the routing controller.
- Call `routing_controller /decide` asynchronously.
- Log route-decision events for observability.

Important constraints:

- It currently calls Groq directly; provider abstraction/retry polish is still incomplete.
- It does not train or run a real RL model.
- It keeps the control plane asynchronous: request traffic never waits on this service.
- If Groq is missing or times out, analyzer falls back to rule-based semantic extraction so the demo remains stable.
- HAProxy `"-"` sentinel session IDs are treated as missing; analyzer only routes real `sid` cookies.
- Runtime code builds state schema `rl_state_v2_16`.

Important environment variables:

- `ANALYZER_INTERVAL_SECONDS`: Elasticsearch polling interval.
- `ANALYZER_ROUTE_THRESHOLD`: minimum scaled subtype score to request routing.
- `SERVICE_BODY_WAIT_SECONDS`: max wait for service `body_preview` before processing a body-bearing gateway event without body enrichment.
- `SERVICE_BODY_CACHE_SECONDS`: cache TTL for service `body_preview` keyed by `(session_id, method, path)`.
- `GROQ_API_KEY`: enables Groq calls; leave empty for deterministic rule-fallback tests.

Runtime endpoints:

- `GET /health`: debug mode tra ve analyzer stats; attack mode chi tra ve `{"status":"ok"}`.

Exposure modes:

- `EXPOSURE_MODE=debug`: bat docs/OpenAPI va health stats.
- `EXPOSURE_MODE=attack`: tat docs/OpenAPI va an analyzer stats.

State migration target:

- `rl_state_v2_16`, 16 floats.
- `protocol` is `/decide` metadata, not part of the tensor.
- LLM confidence should scale semantic fields before building the tensor, while the raw confidence remains in logs for debugging.
