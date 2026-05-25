.PHONY: help build up down logs clean restart test mode-normal mode-honeypot mode-debug mode-attack mode-show status ps shell gen-fake-data generate-replay-buffer export-replay-buffer evaluate-metrics train-rl train-rl-replay train-rl-fresh clear-routes test-rl-split-ip test-adaptive-web test-adaptive-attacks validate

# Variables
COMPOSE_FILE := docker-compose.yml
PROJECT_NAME := adaptive-honeypot-rl
DOCKER_COMPOSE := docker-compose -f $(COMPOSE_FILE)
GATEWAY_URL := http://localhost:18080
PYTHON ?= python
RL_DATASET := control_plane/rl_agent/data/fake_transitions.jsonl
RL_REPLAY_BUFFER := control_plane/rl_agent/data/replay_buffer.jsonl
RL_REPLAY_EVENTS := control_plane/replay_buffer/data/generated_events.jsonl
METRICS_REPORT := logs/metrics_report.json
RL_MODEL := control_plane/rl_agent/artifacts/rl_agent_linear.json
RL_SYNTHETIC_SESSIONS := 10000
RL_SYNTHETIC_MIN_STEPS := 8
RL_SYNTHETIC_MAX_STEPS := 12
RL_SYNTHETIC_SEED := 20260524
RL_REPLAY_SESSIONS := 48
RL_REPLAY_SEED := 20260524
RL_ALGORITHM := cql
RL_EPOCHS := 40
RL_BATCH_SIZE := 256
RL_LEARNING_RATE := 0.003
RL_BEHAVIOR_CLONING_WEIGHT := 0.50
RL_INIT_POLICY := web_prior
RL_DEVICE := cpu
RL_LOG_EVERY := 5
CQL_ALPHA := 0.50
CQL_TEMPERATURE := 1.0
RL_TARGET_UPDATE_PERIOD := 1
EXPOSURE_SERVICES := gateway backend cmdi_pot sqli_pot ssti_pot ssrf_pot routing_controller llm_analyzer

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
RESET := \033[0m

.DEFAULT_GOAL := help

## Help
help:
	@echo "$(CYAN)╔════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(CYAN)║  Adaptive Honeypot System - Makefile                       ║$(RESET)"
	@echo "$(CYAN)╚════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(GREEN)Usage:$(RESET) make [target]"
	@echo ""
	@echo "$(YELLOW)DEPLOYMENT TARGETS:$(RESET)"
	@echo "  $(CYAN)build$(RESET)              Build all Docker images"
	@echo "  $(CYAN)up$(RESET)                 Start all containers (development mode)"
	@echo "  $(CYAN)down$(RESET)               Stop and remove all containers"
	@echo "  $(CYAN)restart$(RESET)            Restart all containers"
	@echo "  $(CYAN)ps$(RESET)                 Show running containers status"
	@echo ""
	@echo "$(YELLOW)MODE SWITCHING:$(RESET)"
	@echo "  $(CYAN)mode-normal$(RESET)        Switch traffic mode to normal-first (TEST_HONEYPOT=false)"
	@echo "  $(CYAN)mode-honeypot$(RESET)      Switch traffic mode to endpoint honeypots (TEST_HONEYPOT=true)"
	@echo "  $(CYAN)mode-debug$(RESET)         Enable operator/debug endpoints and detailed health metadata"
	@echo "  $(CYAN)mode-attack$(RESET)        Hide debug endpoints/metadata for attacker-facing demos"
	@echo "  $(CYAN)mode-show$(RESET)          Show current traffic and exposure modes"
	@echo ""
	@echo "$(YELLOW)MONITORING & LOGS:$(RESET)"
	@echo "  $(CYAN)logs$(RESET)               Show logs from all services"
	@echo "  $(CYAN)logs-gateway$(RESET)       Show gateway (HAProxy) logs"
	@echo "  $(CYAN)logs-backend$(RESET)       Show backend service logs"
	@echo "  $(CYAN)logs-honeypots$(RESET)     Show all honeypot logs"
	@echo "  $(CYAN)logs-cmdi$(RESET)          Show CMDi honeypot logs"
	@echo "  $(CYAN)logs-sqli$(RESET)          Show SQLi honeypot logs"
	@echo "  $(CYAN)logs-ssti$(RESET)          Show SSTI honeypot logs"
	@echo "  $(CYAN)logs-ssrf$(RESET)          Show SSRF honeypot logs"
	@echo "  $(CYAN)logs-ingest$(RESET)        Show Elasticsearch & Filebeat logs"
	@echo ""
	@echo "$(YELLOW)TESTING:$(RESET)"
	@echo "  $(CYAN)test-api$(RESET)           Test API endpoint (/api/health)"
	@echo "  $(CYAN)test-cmdi$(RESET)          Test command injection detection"
	@echo "  $(CYAN)test-all$(RESET)           Run all tests"
	@echo "  $(CYAN)test-routes$(RESET)        Test core API routes"
	@echo "  $(CYAN)test-honeypots$(RESET)     Run standalone honeypot detection script"
	@echo "  $(CYAN)test-rl-split-ip$(RESET)   Validate one-IP honeypot split routing via controller"
	@echo "  $(CYAN)test-adaptive-web$(RESET)  Validate log -> analyzer -> route -> honeypot flow"
	@echo "  $(CYAN)test-adaptive-attacks$(RESET) Validate SQLi/CMDi/SSTI/SSRF adaptive routes"
	@echo "  $(CYAN)validate$(RESET)           Run syntax + core smoke checks"
	@echo ""
	@echo "$(YELLOW)RL TRAINING:$(RESET)"
	@echo "  $(CYAN)gen-fake-data$(RESET)      Generate synthetic transitions for offline RL"
	@echo "  $(CYAN)generate-replay-buffer$(RESET) Drive Web traffic and export host logs to replay buffer"
	@echo "  $(CYAN)export-replay-buffer$(RESET) Export runtime logs to offline RL replay buffer"
	@echo "  $(CYAN)evaluate-metrics$(RESET)   Evaluate proposal metrics from host-mounted logs"
	@echo "  $(CYAN)train-rl$(RESET)           Train RL agent locally from synthetic dataset"
	@echo "  $(CYAN)train-rl-replay$(RESET)    Train RL agent locally from exported replay buffer"
	@echo "  $(CYAN)train-rl-fresh$(RESET)     Generate data then train model locally"
	@echo ""
	@echo "$(YELLOW)CONTAINER INTERACTION:$(RESET)"
	@echo "  $(CYAN)shell-backend$(RESET)      Open shell in backend container"
	@echo "  $(CYAN)shell-gateway$(RESET)      Open shell in gateway container"
	@echo "  $(CYAN)shell-cmdi$(RESET)         Open shell in CMDi honeypot"
	@echo ""
	@echo "$(YELLOW)MAINTENANCE:$(RESET)"
	@echo "  $(CYAN)clean$(RESET)              Remove containers, volumes, and images"
	@echo "  $(CYAN)clean-logs$(RESET)         Clear all container logs"
	@echo "  $(CYAN)clear-routes$(RESET)       Clear HAProxy adaptive route maps"
	@echo "  $(CYAN)status$(RESET)             Show detailed system status"
	@echo "  $(CYAN)health$(RESET)             Check health of all services"
	@echo ""

## Build
build:
	@echo "$(CYAN)[Building Docker images...]$(RESET)"
	$(DOCKER_COMPOSE) build --no-cache
	@echo "$(GREEN)✓ Build complete$(RESET)"

## Start services
up:
	@echo "$(CYAN)[Starting all containers...]$(RESET)"
	$(DOCKER_COMPOSE) up -d --build --remove-orphans
	@echo "$(GREEN)✓ All services started$(RESET)"
	@sleep 5
	@make ps

## Stop services
down:
	@echo "$(CYAN)[Stopping all containers...]$(RESET)"
	$(DOCKER_COMPOSE) down
	@echo "$(GREEN)✓ All services stopped$(RESET)"

## Restart services
restart: down up
	@echo "$(GREEN)✓ Services restarted$(RESET)"

## Show container status
ps:
	@echo ""
	@echo "$(CYAN)Container Status:$(RESET)"
	$(DOCKER_COMPOSE) ps
	@echo ""

status:
	@echo ""
	@echo "$(CYAN)Service Status Report:$(RESET)"
	@echo "$(YELLOW)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	$(DOCKER_COMPOSE) ps
	@echo ""
	@echo "$(YELLOW)Network:$(RESET)"
	docker network ls | grep -E "adaptive|honeypot" || echo "No networks found"
	@echo ""
	@echo "$(YELLOW)Volumes:$(RESET)"
	docker volume ls | grep -E "adaptive|honeypot" | head -10 || echo "No volumes found"
	@echo ""

## Logs
logs:
	@$(DOCKER_COMPOSE) logs -f

logs-gateway:
	@$(DOCKER_COMPOSE) logs -f gateway

logs-backend:
	@$(DOCKER_COMPOSE) logs -f backend

logs-honeypots:
	@$(DOCKER_COMPOSE) logs -f cmdi_pot sqli_pot ssti_pot ssrf_pot

logs-cmdi:
	@$(DOCKER_COMPOSE) logs -f cmdi_pot

logs-sqli:
	@$(DOCKER_COMPOSE) logs -f sqli_pot

logs-ssti:
	@$(DOCKER_COMPOSE) logs -f ssti_pot

logs-ssrf:
	@$(DOCKER_COMPOSE) logs -f ssrf_pot

logs-ingest:
	@$(DOCKER_COMPOSE) logs -f elasticsearch filebeat

logs-analyzer:
	@$(DOCKER_COMPOSE) logs -f llm_analyzer routing_controller

## Mode switching
mode-normal:
	@echo "$(CYAN)[Switching to NORMAL mode (TEST_HONEYPOT=false)]$(RESET)"
	@sed -i.bak 's/TEST_HONEYPOT=.*/TEST_HONEYPOT=false/' .env
	@echo "$(YELLOW)Updated .env file$(RESET)"
	@$(DOCKER_COMPOSE) up -d --no-deps --build --remove-orphans gateway
	@echo "$(GREEN)✓ Gateway restarted in NORMAL mode (traffic → real backend)$(RESET)"
	@sleep 3
	@curl -s $(GATEWAY_URL)/api/health || echo "Health check failed"

mode-honeypot:
	@echo "$(CYAN)[Switching to HONEYPOT mode (TEST_HONEYPOT=true)]$(RESET)"
	@sed -i.bak 's/TEST_HONEYPOT=.*/TEST_HONEYPOT=true/' .env
	@echo "$(YELLOW)Updated .env file$(RESET)"
	@$(DOCKER_COMPOSE) up -d --no-deps --build --remove-orphans gateway
	@echo "$(GREEN)✓ Gateway restarted in HONEYPOT mode (traffic → honeypots)$(RESET)"
	@sleep 3
	@curl -s $(GATEWAY_URL)/api/health || echo "Health check failed"

mode-debug:
	@echo "$(CYAN)[Switching to DEBUG exposure mode (EXPOSURE_MODE=debug)]$(RESET)"
	@test -f .env || cp .env.example .env
	@if grep -q '^EXPOSURE_MODE=' .env; then \
		sed -i.bak 's/EXPOSURE_MODE=.*/EXPOSURE_MODE=debug/' .env; \
	else \
		printf '\nEXPOSURE_MODE=debug\n' >> .env; \
	fi
	@echo "$(YELLOW)Updated .env file$(RESET)"
	@$(DOCKER_COMPOSE) up -d --no-deps --build --force-recreate --remove-orphans $(EXPOSURE_SERVICES)
	@echo "$(GREEN)✓ Debug exposure enabled$(RESET)"
	@sleep 3
	@curl -s $(GATEWAY_URL)/api/health || echo "Health check failed"

mode-attack:
	@echo "$(CYAN)[Switching to ATTACK exposure mode (EXPOSURE_MODE=attack)]$(RESET)"
	@test -f .env || cp .env.example .env
	@if grep -q '^EXPOSURE_MODE=' .env; then \
		sed -i.bak 's/EXPOSURE_MODE=.*/EXPOSURE_MODE=attack/' .env; \
	else \
		printf '\nEXPOSURE_MODE=attack\n' >> .env; \
	fi
	@echo "$(YELLOW)Updated .env file$(RESET)"
	@$(DOCKER_COMPOSE) up -d --no-deps --build --force-recreate --remove-orphans $(EXPOSURE_SERVICES)
	@echo "$(GREEN)✓ Attack-facing exposure enabled$(RESET)"
	@sleep 3
	@curl -s $(GATEWAY_URL)/api/health || echo "Health check failed"

mode-show:
	@echo "$(CYAN)Current mode:$(RESET)"
	@grep "^TEST_HONEYPOT" .env || echo "TEST_HONEYPOT=false (default)"
	@grep "^EXPOSURE_MODE" .env || echo "EXPOSURE_MODE=debug (default)"
	@if grep -q "TEST_HONEYPOT=true" .env; then \
		echo "$(YELLOW)Status: HONEYPOT MODE (traffic → honeypots)$(RESET)"; \
	else \
		echo "$(YELLOW)Status: NORMAL MODE (traffic → real backend)$(RESET)"; \
	fi
	@if grep -q "EXPOSURE_MODE=attack" .env; then \
		echo "$(YELLOW)Exposure: ATTACK MODE (debug surface hidden)$(RESET)"; \
	else \
		echo "$(YELLOW)Exposure: DEBUG MODE (operator endpoints enabled)$(RESET)"; \
	fi

## Testing
test-api:
	@echo "$(CYAN)[Testing API endpoint...]$(RESET)"
	@echo ""
	@echo "$(YELLOW)Request: GET /api/health$(RESET)"
	@curl -s $(GATEWAY_URL)/api/health | jq . 2>/dev/null || curl -s $(GATEWAY_URL)/api/health
	@echo ""

test-cmdi:
	@echo "$(CYAN)[Testing Command Injection Detection...]$(RESET)"
	@echo ""
	@echo "$(YELLOW)Payload: {\"host\":\"127.0.0.1|whoami\"}$(RESET)"
	@echo "$(YELLOW)Endpoint: POST /api/tools/ping$(RESET)"
	@echo ""
	@curl -s -X POST "$(GATEWAY_URL)/api/tools/ping" \
		-H "Content-Type: application/json" \
		-d '{"host":"127.0.0.1|whoami"}' | jq . 2>/dev/null || \
	curl -s -X POST "$(GATEWAY_URL)/api/tools/ping" \
		-H "Content-Type: application/json" \
		-d '{"host":"127.0.0.1|whoami"}'
	@echo ""

test-all: test-api test-cmdi
	@echo "$(GREEN)✓ All tests completed$(RESET)"

test-routes:
	@echo "$(CYAN)[Testing Core API Routes...]$(RESET)"
	@MODE=$$(grep '^EXPOSURE_MODE=' .env 2>/dev/null | cut -d= -f2); \
	case "$$MODE" in ""|debug|dev|development|operator|test) ;; \
		*) echo "$(RED)FAIL: test-routes needs EXPOSURE_MODE=debug because it uses /routes$(RESET)"; exit 1 ;; \
	esac
	@curl -fsS -X DELETE http://localhost:8001/routes >/dev/null 2>&1 || true
	@echo ""
	@echo "$(YELLOW)1. Health Check (/api/health):$(RESET)"
	@HEALTH_BODY=$$(curl -fsS $(GATEWAY_URL)/api/health); \
	echo "$$HEALTH_BODY"; \
	HEALTH_SERVICE=$$(printf '%s' "$$HEALTH_BODY" | python -c 'import json, sys; print(json.load(sys.stdin).get("service", ""))'); \
	echo "$$HEALTH_SERVICE"; \
	if [ "$$HEALTH_SERVICE" != "real-backend" ]; then \
		echo "$(RED)FAIL: expected real-backend after route cleanup, got $$HEALTH_SERVICE$(RESET)"; \
		exit 1; \
	fi
	@echo ""
	@echo "$(YELLOW)2. Article List (/api/articles):$(RESET)"
	@curl -s "$(GATEWAY_URL)/api/articles?page=1&limit=2" | jq . 2>/dev/null || curl -s "$(GATEWAY_URL)/api/articles?page=1&limit=2"
	@echo ""
	@echo "$(YELLOW)3. Article Search (/api/articles/search):$(RESET)"
	@curl -s -X POST "$(GATEWAY_URL)/api/articles/search" \
		-H "Content-Type: application/json" \
		-d '{"query":"tcp"}' | jq . 2>/dev/null || \
	curl -s -X POST "$(GATEWAY_URL)/api/articles/search" \
		-H "Content-Type: application/json" \
		-d '{"query":"tcp"}'
	@echo ""
	@echo "$(YELLOW)4. Tools Preview (/api/tools/preview):$(RESET)"
	@curl -s -X POST "$(GATEWAY_URL)/api/tools/preview" \
		-H "Content-Type: application/json" \
		-d '{"content":"hello world"}' | jq . 2>/dev/null || \
	curl -s -X POST "$(GATEWAY_URL)/api/tools/preview" \
		-H "Content-Type: application/json" \
		-d '{"content":"hello world"}'
	@echo ""

clear-routes:
	@echo "$(CYAN)[Clearing adaptive route maps...]$(RESET)"
	@MODE=$$(grep '^EXPOSURE_MODE=' .env 2>/dev/null | cut -d= -f2); \
	case "$$MODE" in ""|debug|dev|development|operator|test) ;; \
		*) echo "$(RED)clear-routes uses debug-only /routes. Run make mode-debug first.$(RESET)"; exit 1 ;; \
	esac
	@curl -fsS -X DELETE http://localhost:8001/routes

test-honeypots:
	@echo "$(CYAN)[Running standalone honeypot tests...]$(RESET)"
	@$(PYTHON) ../test_honeypots.py

## RL offline training
gen-fake-data:
	@echo "$(CYAN)[Generating synthetic RL dataset...]$(RESET)"
	@$(PYTHON) control_plane/rl_agent/generate_fake_data.py \
		--output $(RL_DATASET) \
		--sessions $(RL_SYNTHETIC_SESSIONS) \
		--min-steps $(RL_SYNTHETIC_MIN_STEPS) \
		--max-steps $(RL_SYNTHETIC_MAX_STEPS) \
		--seed $(RL_SYNTHETIC_SEED)

generate-replay-buffer:
	@echo "$(CYAN)[Generating replay buffer via Web traffic + host logs...]$(RESET)"
	@$(PYTHON) control_plane/replay_buffer/generate_web_replay_buffer.py \
		--sessions $(RL_REPLAY_SESSIONS) \
		--seed $(RL_REPLAY_SEED) \
		--event-output $(RL_REPLAY_EVENTS) \
		--output $(RL_REPLAY_BUFFER)

export-replay-buffer:
	@echo "$(CYAN)[Exporting replay buffer from runtime logs...]$(RESET)"
	@$(PYTHON) control_plane/replay_buffer/export_replay_buffer.py --output $(RL_REPLAY_BUFFER)

evaluate-metrics:
	@echo "$(CYAN)[Evaluating proposal metrics from host-mounted logs...]$(RESET)"
	@$(PYTHON) control_plane/replay_buffer/evaluate_metrics.py \
		--logs-dir logs \
		--output $(METRICS_REPORT) \
		--pretty

train-rl:
	@echo "$(CYAN)[Training offline RL agent locally...]$(RESET)"
	@test -f $(RL_DATASET) || (echo "$(RED)Missing dataset: $(RL_DATASET). Run: make gen-fake-data$(RESET)"; exit 1)
	@$(PYTHON) -c "import torch" >/dev/null 2>&1 || (echo "$(RED)Missing torch for $(PYTHON). Activate venv or run: $(PYTHON) -m pip install -r control_plane/rl_agent/requirements-local.txt$(RESET)"; exit 1)
	@$(PYTHON) -B control_plane/rl_agent/train_offline.py \
		--dataset $(RL_DATASET) \
		--output $(RL_MODEL) \
		--algorithm $(RL_ALGORITHM) \
		--epochs $(RL_EPOCHS) \
		--batch-size $(RL_BATCH_SIZE) \
		--learning-rate $(RL_LEARNING_RATE) \
		--cql-alpha $(CQL_ALPHA) \
		--cql-temperature $(CQL_TEMPERATURE) \
		--behavior-cloning-weight $(RL_BEHAVIOR_CLONING_WEIGHT) \
		--init-policy $(RL_INIT_POLICY) \
		--target-update-period $(RL_TARGET_UPDATE_PERIOD) \
		--device $(RL_DEVICE) \
		--log-every $(RL_LOG_EVERY)

train-rl-replay:
	@echo "$(CYAN)[Training offline RL agent locally from replay buffer...]$(RESET)"
	@test -f $(RL_REPLAY_BUFFER) || (echo "$(RED)Missing replay buffer: $(RL_REPLAY_BUFFER). Run: make export-replay-buffer$(RESET)"; exit 1)
	@$(PYTHON) -c "import torch" >/dev/null 2>&1 || (echo "$(RED)Missing torch for $(PYTHON). Activate venv or run: $(PYTHON) -m pip install -r control_plane/rl_agent/requirements-local.txt$(RESET)"; exit 1)
	@$(PYTHON) -B control_plane/rl_agent/train_offline.py \
		--dataset $(RL_REPLAY_BUFFER) \
		--output $(RL_MODEL) \
		--algorithm $(RL_ALGORITHM) \
		--epochs $(RL_EPOCHS) \
		--batch-size $(RL_BATCH_SIZE) \
		--learning-rate $(RL_LEARNING_RATE) \
		--cql-alpha $(CQL_ALPHA) \
		--cql-temperature $(CQL_TEMPERATURE) \
		--behavior-cloning-weight $(RL_BEHAVIOR_CLONING_WEIGHT) \
		--init-policy $(RL_INIT_POLICY) \
		--target-update-period $(RL_TARGET_UPDATE_PERIOD) \
		--device $(RL_DEVICE) \
		--log-every $(RL_LOG_EVERY)

train-rl-fresh: gen-fake-data train-rl
	@echo "$(GREEN)✓ RL dataset + training completed$(RESET)"

test-rl-split-ip:
	@echo "$(CYAN)[Running split IP routing test via routing controller...]$(RESET)"
	@bash control_plane/routing_controller/test_two_ip_split_routing.sh

test-adaptive-web:
	@echo "$(CYAN)[Running adaptive Web MVP flow test...]$(RESET)"
	@bash control_plane/llm_analyzer/test_adaptive_web_flow.sh

test-adaptive-attacks:
	@echo "$(CYAN)[Running adaptive Web attack surface test suite...]$(RESET)"
	@bash control_plane/llm_analyzer/test_adaptive_attack_surfaces.sh

validate:
	@echo "$(CYAN)[Python syntax check...]$(RESET)"
	@$(PYTHON) -m py_compile \
		../test_honeypots.py \
		real_service/backend/app.py \
		real_service/backend/logging_utils.py \
		real_service/backend/models.py \
		real_service/backend/routes/auth.py \
		real_service/backend/routes/articles.py \
		real_service/backend/routes/tools.py \
		honeypots/base.py \
		honeypots/fake_data.py \
		honeypots/cmdi_pot/app.py \
		honeypots/sqli_pot/app.py \
		honeypots/ssti_pot/app.py \
		honeypots/ssrf_pot/app.py \
		control_plane/state_builder/__init__.py \
		control_plane/state_builder/state_schema.py \
		control_plane/rl_agent/agent.py \
		control_plane/rl_agent/generate_fake_data.py \
		control_plane/rl_agent/train_offline.py \
		control_plane/replay_buffer/__init__.py \
		control_plane/replay_buffer/export_replay_buffer.py \
		control_plane/replay_buffer/evaluate_metrics.py \
		control_plane/replay_buffer/generate_web_replay_buffer.py \
		control_plane/routing_controller/main.py \
		control_plane/llm_analyzer/analyzer.py
	@echo "$(GREEN)✓ Syntax check complete$(RESET)"
	@echo "$(CYAN)[Checking routing controller health...]$(RESET)"
	@curl -fsS http://localhost:8001/health >/dev/null
	@echo "$(GREEN)✓ Routing controller healthy$(RESET)"
	@$(MAKE) test-honeypots
	@$(MAKE) test-routes

## Shell access
shell-backend:
	@echo "$(CYAN)[Opening shell in backend container...]$(RESET)"
	$(DOCKER_COMPOSE) exec backend /bin/sh

shell-gateway:
	@echo "$(CYAN)[Opening shell in gateway container...]$(RESET)"
	$(DOCKER_COMPOSE) exec gateway /bin/sh

shell-cmdi:
	@echo "$(CYAN)[Opening shell in CMDi honeypot...]$(RESET)"
	$(DOCKER_COMPOSE) exec cmdi_pot /bin/sh

## Health checks
health:
	@echo "$(CYAN)[Checking service health...]$(RESET)"
	@echo ""
	@echo "$(YELLOW)Gateway:$(RESET)"
	@curl -s -I http://localhost:8404/stats 2>&1 | head -1 || echo "❌ Unreachable"
	@echo ""
	@echo "$(YELLOW)Backend:$(RESET)"
	@curl -s $(GATEWAY_URL)/api/health | jq . 2>/dev/null || echo "❌ Unreachable"
	@echo ""
	@echo "$(YELLOW)Frontend:$(RESET)"
	@curl -s -I $(GATEWAY_URL) 2>&1 | head -1 || echo "❌ Unreachable"
	@echo ""
	@echo "$(YELLOW)Honeypots (direct ports):$(RESET)"
	@for p in 5002 5003 5004 5005; do \
		body=$$(curl -s "http://localhost:$$p/api/health"); \
		service=$$(printf '%s' "$$body" | jq -r '.service // empty' 2>/dev/null); \
		if [ -n "$$service" ]; then \
			echo "  • Port $$p → $$service"; \
		elif printf '%s' "$$body" | jq -e '.status == "ok"' >/dev/null 2>&1; then \
			echo "  • Port $$p → healthy (generic attack-mode health)"; \
		else \
			echo "  • Port $$p → unreachable"; \
		fi; \
	done
	@echo ""

## Cleanup
clean:
	@echo "$(CYAN)[Cleaning up Docker resources...]$(RESET)"
	@echo "$(YELLOW)Stopping containers...$(RESET)"
	$(DOCKER_COMPOSE) down -v
	@echo "$(YELLOW)Removing dangling images...$(RESET)"
	docker image prune -f --filter "dangling=true"
	@echo "$(GREEN)✓ Cleanup complete$(RESET)"

clean-logs:
	@echo "$(CYAN)[Clearing container logs...]$(RESET)"
	@find /var/lib/docker/containers -name "*.log" -delete 2>/dev/null || echo "No logs to clear"
	@echo "$(GREEN)✓ Logs cleared$(RESET)"

## Development commands
dev-up:
	@echo "$(CYAN)[Starting in development mode...]$(RESET)"
	$(DOCKER_COMPOSE) up --build

dev-rebuild:
	@echo "$(CYAN)[Rebuilding all images...]$(RESET)"
	$(DOCKER_COMPOSE) build --no-cache --pull

## Documentation
info:
	@echo "$(CYAN)╔════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(CYAN)║  Adaptive Honeypot System - Quick Reference                ║$(RESET)"
	@echo "$(CYAN)╚════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)Services:$(RESET)"
	@echo "  • Gateway (HAProxy).......... http://localhost:18080"
	@echo "  • Frontend (via Gateway).... http://localhost:18080"
	@echo "  • Backend API (via Gateway). http://localhost:18080/api/*"
	@echo "  • CMDi Honeypot............. http://localhost:5002"
	@echo "  • SQLi Honeypot............. http://localhost:5003"
	@echo "  • SSTI Honeypot............. http://localhost:5004"
	@echo "  • SSRF Honeypot............. http://localhost:5005"
	@echo "  • HAProxy Stats............. http://localhost:8404/stats"
	@echo ""
	@echo "$(YELLOW)Common Commands:$(RESET)"
	@echo "  make up                 # Start all services"
	@echo "  make down               # Stop all services"
	@echo "  make logs-gateway       # View gateway logs"
	@echo "  make test-api           # Test API"
	@echo "  make mode-honeypot      # Switch to honeypot mode"
	@echo "  make mode-normal        # Switch to normal mode"
	@echo "  make mode-debug         # Enable debug/operator exposure"
	@echo "  make mode-attack        # Hide debug surface for demos"
	@echo ""

version:
	@echo "$(CYAN)Adaptive Honeypot System - v1.0.0$(RESET)"
	@echo "$(YELLOW)Docker Compose Version:$(RESET)"
	docker-compose --version
	@echo "$(YELLOW)Docker Version:$(RESET)"
	docker --version
