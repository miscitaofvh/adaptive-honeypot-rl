# Dummy LLM Analyzer

This component is a temporary, deterministic stand-in for the proposal's stateful LLM analyzer.

Responsibilities:

- Poll Elasticsearch for recent structured backend/honeypot logs.
- Detect SQLi, CMDI, SSTI, and SSRF with conservative regex heuristics.
- Build a proposal-compatible 24D state vector.
- Call `routing_controller /decide` asynchronously.
- Log route-decision events for observability.

Important constraints:

- It does not call a real LLM provider.
- It does not train or run a real RL model.
- It keeps the control plane asynchronous: request traffic never waits on this service.
- It exists so the full lab flow works end-to-end while LLM/RL research pieces are developed later.
- On startup it only analyzes events newer than the analyzer process start time, so old lab traffic cannot replay stale routes into HAProxy maps.
- In this dummy milestone, only `real-backend` events can create route decisions. Honeypot events are treated as passive engagement observations so direct honeypot tests cannot poison IP/session maps.

Runtime endpoints:

- `GET /health`
- `POST /analyze` for manual/debug event injection
