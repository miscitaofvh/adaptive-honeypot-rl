#!/bin/sh
# HAProxy Gateway Entrypoint
# Selects config based on TEST_HONEYPOT environment variable

TEST_HONEYPOT=${TEST_HONEYPOT:-false}

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

# Start HAProxy with selected config
exec haproxy -f "$CONFIG_FILE" "$@"
