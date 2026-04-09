# Meridian — Web Layer

## Quick start
```bash
docker compose up --build -d
```
- App: http://localhost:8080
- HAProxy stats: http://localhost:8404/stats  (admin / meridian)

## Demo credentials
| Username | Password  |
|----------|-----------|
| admin    | admin123  |
| alice    | alice123  |

## Automated test script
```bash
bash scripts/test_web_honeypots.sh
```

Optional variables:
- `SID` (default: `test-sid-auto`)
- `BASE_URL` (default: `http://localhost:8080`)
- `MAP_FILE` (default: `haproxy/maps/session_routes.map`)

Example:
```bash
SID=my-session BASE_URL=http://localhost:8080 bash scripts/test_web_honeypots.sh
```

## Single honeypot test (by parameter)
```bash
bash scripts/test_one_honeypot.sh sqli_pot
bash scripts/test_one_honeypot.sh ssti_pot
bash scripts/test_one_honeypot.sh cmdi_pot
bash scripts/test_one_honeypot.sh ssrf_pot
```

You can also use short names: `sqli`, `ssti`, `cmdi`, `ssrf`.

Example:
```bash
SID=my-session BASE_URL=http://localhost:8080 bash scripts/test_one_honeypot.sh sqli
```

## Manual rerouting (Control Plane integration)
### Option A: file-based map update (works with current default image)
```bash
# Route session <sid> to SQLi honeypot
echo "<sid> sqli_pot" > haproxy/maps/session_routes.map
docker compose restart haproxy

# Remove all session rules
: > haproxy/maps/session_routes.map
docker compose restart haproxy

# Show current map file
cat haproxy/maps/session_routes.map
```

### Option B: runtime socket API (requires `socat` inside haproxy container)
```bash
# Route session <sid> to SQLi honeypot
echo "set map /etc/haproxy/maps/session_routes.map <sid> sqli_pot" \
  | docker compose exec -T haproxy socat stdio /tmp/admin.sock

# Remove rule
echo "del map /etc/haproxy/maps/session_routes.map <sid>" \
  | docker compose exec -T haproxy socat stdio /tmp/admin.sock

# Show current table
echo "show map /etc/haproxy/maps/session_routes.map" \
  | docker compose exec -T haproxy socat stdio /tmp/admin.sock
```

## Attack surface per honeypot
| Honeypot  | Primary endpoint          | Trigger                        |
|-----------|--------------------------|--------------------------------|
| sqli_pot  | POST /api/articles/search | SQL keywords, quotes, --       |
| ssti_pot  | POST /api/tools/preview   | {{...}}, ${...}, {%...%}       |
| cmdi_pot  | POST /api/tools/ping      | ;, |, backtick, shell builtins |
| ssrf_pot  | POST /api/tools/fetch     | 169.254.x, RFC1918, file://    |
