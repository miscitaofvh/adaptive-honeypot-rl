#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

CONTROLLER_URL="${CONTROLLER_URL:-http://localhost:8001}"
MODEL_PATH="${MODEL_PATH:-control_plane/rl_agent/artifacts/rl_agent_linear.json}"

CLIENT_A="rc-test-client-a"
CLIENT_B="rc-test-client-b"
IP_A=""
IP_B=""

wait_for_controller() {
  local max_attempts="${1:-30}"
  local attempt

  for attempt in $(seq 1 "$max_attempts"); do
    if curl -fsS "$CONTROLLER_URL/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "Routing controller is not ready after ${max_attempts}s"
  return 1
}

reload_model_with_retry() {
  local max_attempts="${1:-15}"
  local attempt

  for attempt in $(seq 1 "$max_attempts"); do
    if curl -fsS -X POST "$CONTROLLER_URL/model/reload" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "Failed to reload model after ${max_attempts} attempts"
  return 1
}

cleanup() {
  curl -fsS -X DELETE "$CONTROLLER_URL/routes" >/dev/null 2>&1 || true
  if [[ -n "$IP_A" ]]; then
    curl -fsS -X DELETE "$CONTROLLER_URL/route/ip/$IP_A" >/dev/null 2>&1 || true
  fi
  if [[ -n "$IP_B" ]]; then
    curl -fsS -X DELETE "$CONTROLLER_URL/route/ip/$IP_B" >/dev/null 2>&1 || true
  fi
  docker rm -f "$CLIENT_A" "$CLIENT_B" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/6] Create dummy model (always SSTI for HTTP)..."
python control_plane/rl_agent/create_dummy_ssti_model.py --output "$MODEL_PATH"

echo "[2/6] Start gateway + routing_controller in NORMAL mode (control plane async, service-first)..."
TEST_HONEYPOT=false EXPOSURE_MODE=debug RL_POLICY_MODE=model docker compose up -d --build gateway routing_controller >/dev/null
wait_for_controller

echo "[3/6] Reload model in routing controller..."
reload_model_with_retry
curl -fsS -X DELETE "$CONTROLLER_URL/routes" >/dev/null 2>&1 || true

NETWORK_NAME="$(docker inspect adaptive-gateway --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' | head -n1 | tr -d '[:space:]')"
if [[ -z "$NETWORK_NAME" ]]; then
  echo "Could not detect docker network for adaptive-gateway"
  exit 1
fi

echo "[4/6] Create two isolated clients on network: $NETWORK_NAME"
docker rm -f "$CLIENT_A" "$CLIENT_B" >/dev/null 2>&1 || true
docker run -d --rm --name "$CLIENT_A" --network "$NETWORK_NAME" curlimages/curl:8.7.1 sleep 300 >/dev/null
docker run -d --rm --name "$CLIENT_B" --network "$NETWORK_NAME" curlimages/curl:8.7.1 sleep 300 >/dev/null

IP_A="$(docker inspect "$CLIENT_A" --format '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
IP_B="$(docker inspect "$CLIENT_B" --format '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"

if [[ -z "$IP_A" || -z "$IP_B" ]]; then
  echo "Could not resolve client container IPs"
  exit 1
fi

echo "Client A IP: $IP_A"
echo "Client B IP: $IP_B"

echo "[5/6] Route only client A via /decide (dummy model => ssti_api)..."
curl -fsS -X DELETE "$CONTROLLER_URL/route/ip/$IP_A" >/dev/null 2>&1 || true

DECIDE_PAYLOAD=$(cat <<EOF
{"state_schema":"rl_state_v2_16","protocol":"http","source_ip":"$IP_A","apply_route":true,"state":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
EOF
)

DECIDE_RESPONSE="$(curl -fsS -X POST "$CONTROLLER_URL/decide" -H 'Content-Type: application/json' -d "$DECIDE_PAYLOAD")"
echo "Decision: $DECIDE_RESPONSE"

if ! echo "$DECIDE_RESPONSE" | grep -q '"backend":"ssti_api"'; then
  echo "Expected backend ssti_api from dummy model, got: $DECIDE_RESPONSE"
  exit 1
fi

echo "[6/6] Verify split routing result is endpoint-scoped (A preview => SSTI, other APIs normal)..."
RESP_A_PREVIEW="$(docker exec "$CLIENT_A" curl -fsS -X POST http://gateway/api/tools/preview -H 'Content-Type: application/json' -d '{"content":"{{7*7}}"}')"
RESP_A_HEALTH="$(docker exec "$CLIENT_A" curl -fsS http://gateway/api/health)"
RESP_A_PING="$(docker exec "$CLIENT_A" curl -sS -X POST http://gateway/api/tools/ping -H 'Content-Type: application/json' -d '{"host":"8.8.8.8; id"}')"
RESP_B_PREVIEW="$(docker exec "$CLIENT_B" curl -fsS -X POST http://gateway/api/tools/preview -H 'Content-Type: application/json' -d '{"content":"{{7*7}}"}')"
RESP_B_HEALTH="$(docker exec "$CLIENT_B" curl -fsS http://gateway/api/health)"

echo "Response A preview: $RESP_A_PREVIEW"
echo "Response A health: $RESP_A_HEALTH"
echo "Response A ping: $RESP_A_PING"
echo "Response B preview: $RESP_B_PREVIEW"
echo "Response B health: $RESP_B_HEALTH"

if ! echo "$RESP_A_PREVIEW" | grep -q '"rendered":"49"'; then
  echo "FAIL: client A preview was not routed to ssti-honeypot"
  exit 1
fi

if ! echo "$RESP_A_HEALTH" | grep -q '"service":"real-backend"'; then
  echo "FAIL: client A health should remain real-backend"
  exit 1
fi

if ! echo "$RESP_A_PING" | grep -q "Invalid host"; then
  echo "FAIL: client A ping should remain real service validation, not SSTI"
  exit 1
fi

if echo "$RESP_B_PREVIEW" | grep -q '"rendered":"49"'; then
  echo "FAIL: client B preview was incorrectly routed to ssti-honeypot"
  exit 1
fi

if ! echo "$RESP_B_HEALTH" | grep -q '"service":"real-backend"'; then
  echo "FAIL: client B was not routed to real-backend"
  exit 1
fi

echo "PASS: split routing works with endpoint-scoped honeypot routing."
