#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "$WEB_DIR"

BASE_URL="${BASE_URL:-http://localhost:8080}"
SID="${SID:-test-sid-auto}"
MAP_FILE="${MAP_FILE:-haproxy/maps/session_routes.map}"
HAPROXY_SERVICE="${HAPROXY_SERVICE:-haproxy}"

PASS_COUNT=0
FAIL_COUNT=0
CASE_RESPONSE=""

log_info() { printf '[INFO] %s\n' "$*"; }
log_pass() { printf '[PASS] %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
log_fail() { printf '[FAIL] %s\n' "$*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

wait_for_gateway() {
  curl -fsS \
    --retry 60 \
    --retry-delay 1 \
    --retry-connrefused \
    --retry-all-errors \
    "$BASE_URL/api/health" >/dev/null 2>/dev/null
}

restart_haproxy() {
  docker compose restart "$HAPROXY_SERVICE" >/dev/null
  wait_for_gateway
}

set_route() {
  local backend="${1:-}"
  if [[ -z "$backend" ]]; then
    : > "$MAP_FILE"
  else
    printf '%s %s\n' "$SID" "$backend" > "$MAP_FILE"
  fi
  restart_haproxy
}

cleanup() {
  set +e
  : > "$MAP_FILE"
  docker compose restart "$HAPROXY_SERVICE" >/dev/null 2>&1
}
trap cleanup EXIT

expect_contains_all() {
  local case_name="$1"
  local response="$2"
  shift 2

  local needle
  for needle in "$@"; do
    if ! grep -Fq "$needle" <<<"$response"; then
      log_fail "$case_name -> missing: $needle"
      printf '       response: %s\n' "$response"
      return
    fi
  done

  log_pass "$case_name"
}

run_case() {
  local name="$1"
  local backend="$2"
  local method="$3"
  local path="$4"
  local payload="${5:-}"

  set_route "$backend"

  local response
  if [[ "$method" == "GET" ]]; then
    response="$(curl -sS -H "Cookie: sid=$SID" "$BASE_URL$path")"
  else
    response="$(curl -sS -X "$method" -H "Cookie: sid=$SID" -H "Content-Type: application/json" -d "$payload" "$BASE_URL$path")"
  fi

  printf '[CASE] %s\n' "$name"
  printf '       %s\n' "$response"
  CASE_RESPONSE="$response"
}

main() {
  require_cmd docker
  require_cmd curl

  [[ -f "$MAP_FILE" ]] || die "Map file not found: $MAP_FILE"
  wait_for_gateway || die "Gateway is not ready at $BASE_URL. Run: docker compose up --build -d"

  log_info "Running web honeypot tests with sid=$SID"

  run_case "Normal route" "" "GET" "/api/health"
  expect_contains_all "Normal route" "$CASE_RESPONSE" '"service":"normal"' '"status":"ok"'

  run_case "SQLi honeypot" "sqli_pot" "POST" "/api/articles/search" '{"query":"union select 1"}'
  expect_contains_all "SQLi honeypot" "$CASE_RESPONSE" '"error":"DatabaseError"' '"code":1064'

  run_case "SSTI honeypot" "ssti_pot" "POST" "/api/tools/preview" '{"content":"{{7*7}}"}'
  expect_contains_all "SSTI honeypot" "$CASE_RESPONSE" '"rendered":"49"'

  run_case "CMDi honeypot" "cmdi_pot" "POST" "/api/tools/ping" '{"host":"8.8.8.8; whoami","count":2}'
  expect_contains_all "CMDi honeypot" "$CASE_RESPONSE" 'www-data' '"reachable":true'

  run_case "SSRF honeypot" "ssrf_pot" "POST" "/api/tools/fetch" '{"url":"http://169.254.169.254/latest/meta-data"}'
  expect_contains_all "SSRF honeypot" "$CASE_RESPONSE" '"status_code":200' 'instanceId'

  printf '\n[SUMMARY] %d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
  if (( FAIL_COUNT > 0 )); then
    exit 1
  fi
}

main
