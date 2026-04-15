.PHONY: help build up down logs clean restart test mode-normal mode-honeypot status ps shell

# Variables
COMPOSE_FILE := docker-compose.yml
PROJECT_NAME := adaptive-honeypot-rl
DOCKER_COMPOSE := docker-compose -f $(COMPOSE_FILE)

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
	@echo "  $(CYAN)mode-normal$(RESET)        Switch to production mode (TEST_HONEYPOT=false)"
	@echo "  $(CYAN)mode-honeypot$(RESET)      Switch to honeypot mode (TEST_HONEYPOT=true)"
	@echo "  $(CYAN)mode-show$(RESET)          Show current mode (TEST_HONEYPOT value)"
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
	@echo "  $(CYAN)logs-siem$(RESET)          Show Elasticsearch & Kibana logs"
	@echo ""
	@echo "$(YELLOW)TESTING:$(RESET)"
	@echo "  $(CYAN)test-api$(RESET)           Test API endpoint (/api/health)"
	@echo "  $(CYAN)test-cmdi$(RESET)          Test command injection detection"
	@echo "  $(CYAN)test-all$(RESET)           Run all tests"
	@echo "  $(CYAN)test-routes$(RESET)        Test all API routes"
	@echo ""
	@echo "$(YELLOW)CONTAINER INTERACTION:$(RESET)"
	@echo "  $(CYAN)shell-backend$(RESET)      Open shell in backend container"
	@echo "  $(CYAN)shell-gateway$(RESET)      Open shell in gateway container"
	@echo "  $(CYAN)shell-cmdi$(RESET)         Open shell in CMDi honeypot"
	@echo ""
	@echo "$(YELLOW)MAINTENANCE:$(RESET)"
	@echo "  $(CYAN)clean$(RESET)              Remove containers, volumes, and images"
	@echo "  $(CYAN)clean-logs$(RESET)         Clear all container logs"
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
	$(DOCKER_COMPOSE) up -d --build
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

logs-siem:
	@$(DOCKER_COMPOSE) logs -f elasticsearch kibana filebeat

## Mode switching
mode-normal:
	@echo "$(CYAN)[Switching to NORMAL mode (TEST_HONEYPOT=false)]$(RESET)"
	@sed -i.bak 's/TEST_HONEYPOT=.*/TEST_HONEYPOT=false/' .env
	@echo "$(YELLOW)Updated .env file$(RESET)"
	@$(DOCKER_COMPOSE) up -d --no-deps --build gateway
	@echo "$(GREEN)✓ Gateway restarted in NORMAL mode (traffic → real backend)$(RESET)"
	@sleep 3
	@curl -s http://localhost/api/health || echo "Health check failed"

mode-honeypot:
	@echo "$(CYAN)[Switching to HONEYPOT mode (TEST_HONEYPOT=true)]$(RESET)"
	@sed -i.bak 's/TEST_HONEYPOT=.*/TEST_HONEYPOT=true/' .env
	@echo "$(YELLOW)Updated .env file$(RESET)"
	@$(DOCKER_COMPOSE) up -d --no-deps --build gateway
	@echo "$(GREEN)✓ Gateway restarted in HONEYPOT mode (traffic → honeypots)$(RESET)"
	@sleep 3
	@curl -s http://localhost/api/health || echo "Health check failed"

mode-show:
	@echo "$(CYAN)Current mode:$(RESET)"
	@grep "^TEST_HONEYPOT" .env
	@if grep -q "TEST_HONEYPOT=true" .env; then \
		echo "$(YELLOW)Status: HONEYPOT MODE (traffic → honeypots)$(RESET)"; \
	else \
		echo "$(YELLOW)Status: NORMAL MODE (traffic → real backend)$(RESET)"; \
	fi

## Testing
test-api:
	@echo "$(CYAN)[Testing API endpoint...]$(RESET)"
	@echo ""
	@echo "$(YELLOW)Request: GET /api/health$(RESET)"
	@curl -s http://localhost/api/health | jq . 2>/dev/null || curl -s http://localhost/api/health
	@echo ""

test-cmdi:
	@echo "$(CYAN)[Testing Command Injection Detection...]$(RESET)"
	@echo ""
	@echo "$(YELLOW)Payload: {\"host\":\"127.0.0.1|whoami\"}$(RESET)"
	@echo "$(YELLOW)Endpoint: POST /api/tools/ping$(RESET)"
	@echo ""
	@curl -s -X POST "http://localhost/api/tools/ping" \
		-H "Content-Type: application/json" \
		-d '{"host":"127.0.0.1|whoami"}' | jq . 2>/dev/null || \
	curl -s -X POST "http://localhost/api/tools/ping" \
		-H "Content-Type: application/json" \
		-d '{"host":"127.0.0.1|whoami"}'
	@echo ""

test-all: test-api test-cmdi
	@echo "$(GREEN)✓ All tests completed$(RESET)"

test-routes:
	@echo "$(CYAN)[Testing All API Routes...]$(RESET)"
	@echo ""
	@echo "$(YELLOW)1. Health Check:$(RESET)"
	@curl -s http://localhost/api/health | jq -r '.service' 2>/dev/null || curl -s http://localhost/api/health
	@echo ""
	@echo "$(YELLOW)2. Another request (load-balance test):$(RESET)"
	@curl -s http://localhost/api/health | jq -r '.service' 2>/dev/null || curl -s http://localhost/api/health
	@echo ""
	@echo "$(YELLOW)3. Third request (verify round-robin):$(RESET)"
	@curl -s http://localhost/api/health | jq -r '.service' 2>/dev/null || curl -s http://localhost/api/health
	@echo ""

## Shell access
shell-backend:
	@echo "$(CYAN)[Opening shell in backend container...]$(RESET)"
	$(DOCKER_COMPOSE) exec backend /bin/bash

shell-gateway:
	@echo "$(CYAN)[Opening shell in gateway container...]$(RESET)"
	$(DOCKER_COMPOSE) exec gateway /bin/sh

shell-cmdi:
	@echo "$(CYAN)[Opening shell in CMDi honeypot...]$(RESET)"
	$(DOCKER_COMPOSE) exec cmdi_pot /bin/bash

## Health checks
health:
	@echo "$(CYAN)[Checking service health...]$(RESET)"
	@echo ""
	@echo "$(YELLOW)Gateway:$(RESET)"
	@curl -s -I http://localhost:8404/stats 2>&1 | head -1 || echo "❌ Unreachable"
	@echo ""
	@echo "$(YELLOW)Backend:$(RESET)"
	@curl -s http://localhost:5000/api/health | jq -r '.service' 2>/dev/null || echo "❌ Unreachable"
	@echo ""
	@echo "$(YELLOW)Frontend:$(RESET)"
	@curl -s -I http://localhost:3000 2>&1 | head -1 || echo "❌ Unreachable"
	@echo ""
	@echo "$(YELLOW)Honeypots (via gateway):$(RESET)"
	@for i in 1 2 3 4; do \
		service=$$(curl -s http://localhost/api/health | jq -r '.service' 2>/dev/null); \
		if [ -n "$$service" ]; then \
			echo "  • Port 80 → $$service"; \
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
	@echo "  • Gateway (HAProxy).......... http://localhost:80"
	@echo "  • Frontend (React).......... http://localhost:3000"
	@echo "  • Backend API............... http://localhost:5000"
	@echo "  • CMDi Honeypot............. http://localhost:5002"
	@echo "  • SQLi Honeypot............. http://localhost:5003"
	@echo "  • SSTI Honeypot............. http://localhost:5004"
	@echo "  • SSRF Honeypot............. http://localhost:5005"
	@echo "  • Kibana Dashboard.......... http://localhost:5601"
	@echo "  • HAProxy Stats............. http://localhost:8404/stats"
	@echo ""
	@echo "$(YELLOW)Common Commands:$(RESET)"
	@echo "  make up                 # Start all services"
	@echo "  make down               # Stop all services"
	@echo "  make logs-gateway       # View gateway logs"
	@echo "  make test-api           # Test API"
	@echo "  make mode-honeypot      # Switch to honeypot mode"
	@echo "  make mode-normal        # Switch to normal mode"
	@echo ""

version:
	@echo "$(CYAN)Adaptive Honeypot System - v1.0.0$(RESET)"
	@echo "$(YELLOW)Docker Compose Version:$(RESET)"
	docker-compose --version
	@echo "$(YELLOW)Docker Version:$(RESET)"
	docker --version
