#!/bin/sh
# HAProxy Gateway Entrypoint
# Selects config based on TEST_HONEYPOT environment variable

TEST_HONEYPOT=${TEST_HONEYPOT:-false}
EXPOSURE_MODE=$(echo "${EXPOSURE_MODE:-debug}" | tr '[:upper:]' '[:lower:]')
MAP_DIR="/etc/haproxy/maps"

mkdir -p "$MAP_DIR"
touch "$MAP_DIR/session_routes.map"
touch "$MAP_DIR/ip_honeypot.map"

# Choose config file based on TEST_HONEYPOT
if [ "$TEST_HONEYPOT" = "true" ] || [ "$TEST_HONEYPOT" = "True" ] || [ "$TEST_HONEYPOT" = "TRUE" ]; then
    CONFIG_FILE="/etc/haproxy/haproxy.honeypot.cfg"
    echo "[Gateway] TEST_HONEYPOT=true - Using HONEYPOT routing (traffic → honeypots)"
else
    CONFIG_FILE="/etc/haproxy/haproxy.normal.cfg"
    echo "[Gateway] TEST_HONEYPOT=false - Using NORMAL routing (traffic → real backend)"
fi

# Verify config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[ERROR] Config file not found: $CONFIG_FILE"
    exit 1
fi

EFFECTIVE_CONFIG="$CONFIG_FILE"
case "$EXPOSURE_MODE" in
    debug|dev|development|operator|test)
        echo "[Gateway] EXPOSURE_MODE=$EXPOSURE_MODE - Stats UI enabled for debugging"
        ;;
    *)
        EFFECTIVE_CONFIG="/tmp/haproxy.attack.cfg"
        sed '/^# Stats UI/,$d' "$CONFIG_FILE" > "$EFFECTIVE_CONFIG"
        echo "[Gateway] EXPOSURE_MODE=$EXPOSURE_MODE - Stats UI disabled for attacker-facing demo"
        ;;
esac

# Start HAProxy with selected config
exec haproxy -f "$EFFECTIVE_CONFIG" "$@"
