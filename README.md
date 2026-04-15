# Adaptive Honeypot System

## 1) Overview
This project is a local Docker-based lab for adaptive honeypot research.

High-level layers:
- Data plane: request routing and traffic steering (gateway).
- Real service: normal frontend/backend used as bait workloads.
- Honeypot service layer: web honeypots that emulate vulnerable behavior.
- Control plane: log analysis + RL decision + routing control APIs.
- Observability: ELK stack for log collection, indexing, and visualization.

## 2) Project Structure

```text
adaptive_honeypot_system/
|-- .env
|-- .env.example
|-- Makefile
|-- docker-compose.yml
|
|-- gateway/
|   |-- Dockerfile
|   |-- entrypoint.sh
|   |-- haproxy.cfg
|   |-- haproxy.normal.cfg
|   |-- haproxy.honeypot.cfg
|   `-- routing_update.sh
|
|-- real_service/
|   |-- backend/
|   |   |-- Dockerfile
|   |   |-- app.py
|   |   |-- models.py
|   |   |-- requirements.txt
|   |   `-- routes/
|   |       |-- __init__.py
|   |       |-- auth.py
|   |       |-- articles.py
|   |       `-- tools.py
|   `-- frontend/
|       |-- Dockerfile
|       |-- nginx.conf
|       |-- index.html
|       |-- package.json
|       |-- vite.config.js
|       `-- src/
|           |-- main.jsx
|           |-- App.jsx
|           |-- index.css
|           |-- api/client.js
|           |-- components/Navbar.jsx
|           `-- pages/
|               |-- Home.jsx
|               |-- Login.jsx
|               |-- Articles.jsx
|               |-- ArticleDetail.jsx
|               `-- Tools.jsx
|
|-- honeypots/
|   |-- base.py
|   |-- fake_data.py
|   |-- cmdi_pot/
|   |   |-- Dockerfile
|   |   |-- app.py
|   |   `-- requirements.txt
|   |-- sqli_pot/
|   |   |-- Dockerfile
|   |   |-- app.py
|   |   `-- requirements.txt
|   |-- ssti_pot/
|   |   |-- Dockerfile
|   |   |-- app.py
|   |   `-- requirements.txt
|   `-- ssrf_pot/
|       |-- Dockerfile
|       |-- app.py
|       `-- requirements.txt
|
|-- control_plane/
|   |-- llm_analyzer/
|   |   |-- analyzer.py
|   |   |-- state_builder.py
|   |   `-- requirements.txt
|   |-- rl_agent/
|   |   |-- agent.py
|   |   |-- train_offline.py
|   |   `-- requirements.txt
|   `-- routing_controller/
|       |-- Dockerfile
|       |-- main.py
|       `-- requirements.txt
|
`-- observability/
    |-- elasticsearch/elasticsearch.yml
    |-- kibana/kibana.yml
    `-- filebeat/filebeat.yml
```

## 3) What Each Part Does

### Root config files
- `.env` / `.env.example`
  - Runtime variables (gateway mode switch, ELK connection, secrets).
- `docker-compose.yml`
  - Defines all containers, networks, and volumes.
- `Makefile`
  - Convenience commands for build, run, logs, mode switching, and checks.

### gateway/
- Purpose: unified ingress and HTTP routing.
- `entrypoint.sh`
  - Chooses normal vs honeypot HAProxy config based on `TEST_HONEYPOT`.
- `haproxy.normal.cfg`
  - Routes API traffic to real backend.
- `haproxy.honeypot.cfg`
  - Routes API traffic to honeypot backend pool.
- `routing_update.sh`
  - Helper script for route map updates used by controller workflows.

### real_service/backend/
- Purpose: normal API service used as realistic target application.
- `app.py`
  - Flask app bootstrap, DB initialization, route registration.
- `models.py`
  - SQLAlchemy models for users/articles.
- `routes/auth.py`
  - Login/register flows.
- `routes/articles.py`
  - Article listing/detail/create APIs.
- `routes/tools.py`
  - Utility endpoints (markdown preview, ping, URL fetch).

### real_service/frontend/
- Purpose: user-facing UI for interacting with the service.
- React + Vite source in `src/`.
- API calls centralized in `src/api/client.js`.
- Nginx serves built assets in container runtime.

### honeypots/
- Purpose: specialized web honeypot services with different attack signatures.
- `base.py`
  - Shared middleware for structured request logging.
- `fake_data.py`
  - Shared fake dataset used by honeypot responses.
- `cmdi_pot/app.py`
  - Command injection themed behavior.
- `sqli_pot/app.py`
  - SQL injection themed behavior.
- `ssti_pot/app.py`
  - Server-side template injection themed behavior.
- `ssrf_pot/app.py`
  - SSRF themed behavior.

### control_plane/
- Purpose: asynchronous analysis and decision layer.
- `llm_analyzer/`
  - Builds semantic features from aggregated logs.
- `rl_agent/`
  - Offline RL policy logic and training scripts.
- `routing_controller/`
  - API bridge that applies routing decisions to gateway route maps.

### observability/
- Purpose: centralized logging and dashboarding.
- `filebeat/`
  - Collects container logs and ships to Elasticsearch.
- `elasticsearch/`
  - Stores and indexes logs.
- `kibana/`
  - Visualization and analysis dashboards.

## 4) Runtime Flow (Current)
1. Client traffic enters gateway.
2. Gateway routes requests to real backend or honeypot pool based on mode/config.
3. Services emit logs.
4. Filebeat forwards logs to Elasticsearch.
5. Kibana is used for monitoring and analysis.

## 5) Quick Start

```bash
cd adaptive_honeypot_system
cp .env.example .env
make up
```

Useful commands:
- `make ps` -> list container status
- `make logs-gateway` -> watch gateway logs
- `make mode-normal` -> route API to real backend
- `make mode-honeypot` -> route API to honeypots
- `make down` -> stop all services
