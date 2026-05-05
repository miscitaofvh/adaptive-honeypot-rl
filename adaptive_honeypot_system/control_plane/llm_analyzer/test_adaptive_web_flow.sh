#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

GATEWAY_URL="${GATEWAY_URL:-http://localhost:18080}"
CONTROLLER_URL="${CONTROLLER_URL:-http://localhost:8001}"
ANALYZER_URL="${ANALYZER_URL:-http://localhost:8002}"
ES_URL="${ES_URL:-http://localhost:9200}"
SID="flow_$(date +%s)_$RANDOM"

wait_for_url() {
  local url="$1"
  local label="$2"
  local max_attempts="${3:-60}"

  for _ in $(seq 1 "$max_attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "$label is not ready: $url"
  return 1
}

json_post() {
  local url="$1"
  local payload="$2"
  curl -sS -X POST "$url" \
    -H "Content-Type: application/json" \
    -H "Cookie: sid=$SID" \
    -d "$payload"
}

cleanup() {
  curl -fsS -X DELETE "$CONTROLLER_URL/routes" >/dev/null 2>&1 || true
  curl -fsS -X DELETE "$CONTROLLER_URL/route/session/$SID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/5] Start Web MVP stack in normal-first mode with dummy heuristic RL..."
TEST_HONEYPOT=false RL_POLICY_MODE=heuristic ANALYZER_ENABLED=true docker compose up -d --build --force-recreate \
  elasticsearch \
  backend \
  sqli_pot \
  ssti_pot \
  cmdi_pot \
  ssrf_pot \
  routing_controller \
  llm_analyzer \
  gateway \
  filebeat >/dev/null

echo "[2/5] Wait for gateway, routing controller, dummy analyzer, and Elasticsearch..."
wait_for_url "$GATEWAY_URL/api/health" "gateway"
wait_for_url "$CONTROLLER_URL/health" "routing controller"
wait_for_url "$ANALYZER_URL/health" "dummy analyzer"
wait_for_url "$ES_URL" "elasticsearch" 120
cleanup

echo "[3/5] Send SQLi-like request to real backend path; analyzer should reroute session asynchronously..."
json_post "$GATEWAY_URL/api/articles/search" '{"query":"union select password from users"}' >/dev/null || true

echo "[4/5] Poll route map for session $SID -> sqli_api..."
for _ in $(seq 1 90); do
  ROUTE_BODY="$(curl -fsS "$CONTROLLER_URL/route/session/$SID" || true)"
  if echo "$ROUTE_BODY" | grep -q '"backend":"sqli_api"'; then
    echo "Route detected: $ROUTE_BODY"
    break
  fi
  sleep 1
done

ROUTE_BODY="$(curl -fsS "$CONTROLLER_URL/route/session/$SID")"
if ! echo "$ROUTE_BODY" | grep -q '"backend":"sqli_api"'; then
  echo "FAIL: analyzer did not route session to sqli_api"
  echo "Route body: $ROUTE_BODY"
  echo "Analyzer health: $(curl -s "$ANALYZER_URL/health" || true)"
  echo "Recent ES indices:"
  curl -s "$ES_URL/_cat/indices/honeypot-logs-*?v" || true
  echo ""
  echo "Recent analyzer/filebeat/backend logs:"
  docker compose logs --no-color --tail=80 llm_analyzer filebeat backend routing_controller || true
  exit 1
fi

echo "[5/5] Verify next request with same sid lands in SQLi honeypot..."
BODY_FILE="$(mktemp)"
STATUS="$(curl -sS -o "$BODY_FILE" -w "%{http_code}" -X POST "$GATEWAY_URL/api/articles/search" \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=$SID" \
  -d '{"query":"union select password from users"}')"
BODY="$(cat "$BODY_FILE")"
rm -f "$BODY_FILE"

echo "HTTP status: $STATUS"
echo "Body: $BODY"

if [[ "$STATUS" != "500" ]] || ! echo "$BODY" | grep -q "DatabaseError"; then
  echo "FAIL: expected SQLi honeypot DatabaseError response"
  exit 1
fi

echo "PASS: log -> dummy analyzer -> dummy RL/controller -> HAProxy session route -> SQLi honeypot flow works."
