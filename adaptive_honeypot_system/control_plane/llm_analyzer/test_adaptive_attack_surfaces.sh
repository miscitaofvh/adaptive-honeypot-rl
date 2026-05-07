#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

GATEWAY_URL="${GATEWAY_URL:-http://localhost:18080}"
CONTROLLER_URL="${CONTROLLER_URL:-http://localhost:8001}"
ANALYZER_URL="${ANALYZER_URL:-http://localhost:8002}"
ES_URL="${ES_URL:-http://localhost:9200}"

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

post_json() {
  local sid="$1"
  local path="$2"
  local payload="$3"
  curl -sS -X POST "$GATEWAY_URL$path" \
    -H "Content-Type: application/json" \
    -H "Cookie: sid=$sid" \
    -d "$payload"
}

post_json_status() {
  local sid="$1"
  local path="$2"
  local payload="$3"
  local body_file="$4"
  curl -sS -o "$body_file" -w "%{http_code}" -X POST "$GATEWAY_URL$path" \
    -H "Content-Type: application/json" \
    -H "Cookie: sid=$sid" \
    -d "$payload"
}

wait_for_route() {
  local sid="$1"
  local expected_backend="$2"
  local route_body=""

  for _ in $(seq 1 75); do
    route_body="$(curl -fsS "$CONTROLLER_URL/route/session/$sid" || true)"
    if echo "$route_body" | grep -q "\"backend\":\"$expected_backend\""; then
      echo "Route detected for $sid: $route_body"
      return 0
    fi
    sleep 1
  done

  echo "FAIL: expected $sid -> $expected_backend, got: $route_body"
  echo "Analyzer health: $(curl -s "$ANALYZER_URL/health" || true)"
  docker compose logs --no-color --tail=100 llm_analyzer routing_controller filebeat backend || true
  return 1
}

assert_contains() {
  local body="$1"
  local pattern="$2"
  local message="$3"
  if ! echo "$body" | grep -q "$pattern"; then
    echo "FAIL: $message"
    echo "Body: $body"
    exit 1
  fi
}

assert_not_contains() {
  local body="$1"
  local pattern="$2"
  local message="$3"
  if echo "$body" | grep -q "$pattern"; then
    echo "FAIL: $message"
    echo "Body: $body"
    exit 1
  fi
}

cleanup() {
  curl -fsS -X DELETE "$CONTROLLER_URL/routes" >/dev/null 2>&1 || true
}

settled_cleanup() {
  sleep 8
  cleanup
  sleep 3
  cleanup
}
trap cleanup EXIT

echo "[1/8] Start normal-first stack with deterministic analyzer fallback..."
GROQ_API_KEY= TEST_HONEYPOT=false EXPOSURE_MODE=debug RL_POLICY_MODE=heuristic ANALYZER_ENABLED=true SERVICE_BODY_WAIT_SECONDS=8 docker compose up -d --build --force-recreate \
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

echo "[2/8] Wait for gateway, controller, analyzer, and Elasticsearch..."
wait_for_url "$GATEWAY_URL/api/health" "gateway"
wait_for_url "$CONTROLLER_URL/health" "routing controller"
wait_for_url "$ANALYZER_URL/health" "analyzer"
wait_for_url "$ES_URL" "elasticsearch" 120
cleanup

echo "[3/8] Verify attacks without sid do not create fake '-' session routes..."
curl -sS -X POST "$GATEWAY_URL/api/tools/ping" \
  -H "Content-Type: application/json" \
  -d '{"host":"8.8.8.8; id"}' >/dev/null || true
sleep 6
NO_SID_ROUTE="$(curl -fsS "$CONTROLLER_URL/route/session/-")"
echo "No-sid route: $NO_SID_ROUTE"
assert_contains "$NO_SID_ROUTE" '"found":false' "analyzer should not route HAProxy '-' sentinel as a real session"

run_sqli_case() {
  local sid="attack_sqli_$(date +%s)_$RANDOM"
  echo "[4/8] SQLi route: $sid"
  post_json "$sid" "/api/articles/search" '{"query":"union select password from users"}' >/dev/null || true
  wait_for_route "$sid" "sqli_api"

  local body_file
  body_file="$(mktemp)"
  local status
  status="$(post_json_status "$sid" "/api/articles/search" '{"query":"union select password from users"}' "$body_file")"
  local body
  body="$(cat "$body_file")"
  rm -f "$body_file"
  echo "SQLi status/body: $status $body"
  if [[ "$status" != "500" ]]; then
    echo "FAIL: expected SQLi honeypot HTTP 500"
    exit 1
  fi
  assert_contains "$body" "DatabaseError" "expected SQLi honeypot database error"

  local preview
  preview="$(post_json "$sid" "/api/tools/preview" '{"content":"# Hello"}')"
  assert_not_contains "$preview" "DatabaseError" "SQLi route should not break markdown preview"
  assert_contains "$preview" '"rendered"' "expected real markdown preview response"
  curl -fsS -X DELETE "$CONTROLLER_URL/route/session/$sid" >/dev/null || true
}

run_cmdi_case() {
  local sid="attack_cmdi_$(date +%s)_$RANDOM"
  echo "[5/8] CMDi route: $sid"
  post_json "$sid" "/api/tools/ping" '{"host":"8.8.8.8; id"}' >/dev/null || true
  wait_for_route "$sid" "cmdi_api"

  local body
  body="$(post_json "$sid" "/api/tools/ping" '{"host":"8.8.8.8; id"}')"
  echo "CMDi body: $body"
  assert_contains "$body" "uid=33" "expected CMDi honeypot command output"

  local preview
  preview="$(post_json "$sid" "/api/tools/preview" '{"content":"# Hello"}')"
  assert_contains "$preview" '"rendered"' "CMDi route should not break markdown preview"
  curl -fsS -X DELETE "$CONTROLLER_URL/route/session/$sid" >/dev/null || true
}

run_ssti_case() {
  local sid="attack_ssti_$(date +%s)_$RANDOM"
  echo "[6/8] SSTI route: $sid"
  local payload='{"content":"# Hello\n\nType some **Markdown** here.\n\n```python\nprint(\"hello\")\n```\n\n{{7*7}}"}'
  post_json "$sid" "/api/tools/preview" "$payload" >/dev/null || true
  wait_for_route "$sid" "ssti_api"

  local body
  body="$(post_json "$sid" "/api/tools/preview" "$payload")"
  echo "SSTI body: $body"
  assert_contains "$body" "<h1>Hello</h1>" "expected SSTI honeypot to preserve markdown heading"
  assert_contains "$body" "<strong>Markdown</strong>" "expected SSTI honeypot to preserve markdown formatting"
  assert_contains "$body" "49" "expected SSTI honeypot evaluated template output"
  assert_not_contains "$body" "{{7*7}}" "expected SSTI expression to be evaluated"

  local ping
  ping="$(post_json "$sid" "/api/tools/ping" '{"host":"bad host"}')"
  assert_contains "$ping" "Invalid host" "SSTI route should not break ping validation"
  curl -fsS -X DELETE "$CONTROLLER_URL/route/session/$sid" >/dev/null || true
}

run_ssrf_case() {
  local sid="attack_ssrf_$(date +%s)_$RANDOM"
  echo "[7/8] SSRF route: $sid"
  post_json "$sid" "/api/tools/fetch" '{"url":"http://169.254.169.254/latest/meta-data/"}' >/dev/null || true
  wait_for_route "$sid" "ssrf_api"

  local body
  body="$(post_json "$sid" "/api/tools/fetch" '{"url":"http://169.254.169.254/latest/meta-data/"}')"
  echo "SSRF body: $body"
  assert_contains "$body" "instanceId" "expected SSRF honeypot fake metadata response"

  local preview
  preview="$(post_json "$sid" "/api/tools/preview" '{"content":"# Hello"}')"
  assert_contains "$preview" '"rendered"' "SSRF route should not break markdown preview"
  curl -fsS -X DELETE "$CONTROLLER_URL/route/session/$sid" >/dev/null || true
}

run_sqli_case
run_cmdi_case
run_ssti_case
run_ssrf_case

echo "[8/8] Confirm route maps are clean..."
settled_cleanup
ROUTES="$(curl -fsS "$CONTROLLER_URL/routes")"
echo "Routes: $ROUTES"
assert_contains "$ROUTES" '"session_routes":{}' "session route map should be empty after cleanup"
assert_contains "$ROUTES" '"ip_routes":{}' "IP route map should be empty after cleanup"

echo "PASS: all adaptive Web attack surfaces route to the matching endpoint-scoped honeypot."
