#!/bin/sh
# Script to update HAProxy routing maps dynamically.

set -eu

HAPROXY_SOCK="/var/run/haproxy/admin.sock"
SESSION_ROUTES_MAP="/etc/haproxy/maps/session_routes.map"
IP_HONEYPOT_MAP="/etc/haproxy/maps/ip_honeypot.map"

ensure_map() {
    map_file="$1"
    mkdir -p "$(dirname "$map_file")"
    touch "$map_file"
}

update_map_file() {
    map_file="$1"
    key="$2"
    value="$3"
    tmp_file="${map_file}.tmp"

    awk -v k="$key" -v v="$value" '
        BEGIN { updated = 0 }
        $1 == k {
            if (!updated) {
                print k, v
                updated = 1
            }
            next
        }
        { print }
        END {
            if (!updated) {
                print k, v
            }
        }
    ' "$map_file" > "$tmp_file"

    mv "$tmp_file" "$map_file"
}

remove_map_file() {
    map_file="$1"
    key="$2"
    tmp_file="${map_file}.tmp"

    awk -v k="$key" '$1 != k { print }' "$map_file" > "$tmp_file"
    mv "$tmp_file" "$map_file"
}

runtime_set() {
    map_file="$1"
    key="$2"
    value="$3"

    if [ -S "$HAPROXY_SOCK" ] && command -v socat >/dev/null 2>&1; then
        printf 'add map %s %s %s\n' "$map_file" "$key" "$value" | socat - UNIX-CONNECT:"$HAPROXY_SOCK" >/dev/null 2>&1 || true
        printf 'set map %s %s %s\n' "$map_file" "$key" "$value" | socat - UNIX-CONNECT:"$HAPROXY_SOCK" >/dev/null 2>&1 || true
    fi
}

runtime_del() {
    map_file="$1"
    key="$2"

    if [ -S "$HAPROXY_SOCK" ] && command -v socat >/dev/null 2>&1; then
        printf 'del map %s %s\n' "$map_file" "$key" | socat - UNIX-CONNECT:"$HAPROXY_SOCK" >/dev/null 2>&1 || true
    fi
}

usage() {
    echo "Usage: $0 {add_session|add_ip|remove_session|remove_ip|clear_sessions|clear_ips|clear_all|drop_connection} <identifier> [backend_name]"
    echo "Example backend_name: normal_api|sqli_api|ssti_api|cmdi_api|ssrf_api"
}

ensure_map "$SESSION_ROUTES_MAP"
ensure_map "$IP_HONEYPOT_MAP"

clear_map() {
    map_file="$1"

    if [ -s "$map_file" ]; then
        while read -r key _; do
            [ -n "${key:-}" ] || continue
            case "$key" in
                \#*) continue ;;
            esac
            runtime_del "$map_file" "$key"
        done < "$map_file"
    fi

    : > "$map_file"
}

case "${1:-}" in
    add_session)
        [ "${2:-}" ] && [ "${3:-}" ] || { usage; exit 1; }
        update_map_file "$SESSION_ROUTES_MAP" "$2" "$3"
        runtime_set "$SESSION_ROUTES_MAP" "$2" "$3"
        echo "Session routing updated: $2 -> $3"
        ;;
    add_ip)
        [ "${2:-}" ] && [ "${3:-}" ] || { usage; exit 1; }
        update_map_file "$IP_HONEYPOT_MAP" "$2" "$3"
        runtime_set "$IP_HONEYPOT_MAP" "$2" "$3"
        echo "IP routing updated: $2 -> $3"
        ;;
    remove_session)
        [ "${2:-}" ] || { usage; exit 1; }
        remove_map_file "$SESSION_ROUTES_MAP" "$2"
        runtime_del "$SESSION_ROUTES_MAP" "$2"
        echo "Session routing removed: $2"
        ;;
    remove_ip)
        [ "${2:-}" ] || { usage; exit 1; }
        remove_map_file "$IP_HONEYPOT_MAP" "$2"
        runtime_del "$IP_HONEYPOT_MAP" "$2"
        echo "IP routing removed: $2"
        ;;
    clear_sessions)
        clear_map "$SESSION_ROUTES_MAP"
        echo "Session routes cleared"
        ;;
    clear_ips)
        clear_map "$IP_HONEYPOT_MAP"
        echo "IP routes cleared"
        ;;
    clear_all)
        clear_map "$SESSION_ROUTES_MAP"
        clear_map "$IP_HONEYPOT_MAP"
        echo "All adaptive routes cleared"
        ;;
    drop_connection)
        [ "${2:-}" ] || { usage; exit 1; }
        echo "drop_connection requested for $2 - L4 drop flow is not implemented in current gateway" >&2
        exit 2
        ;;
    *)
        usage
        exit 1
        ;;
esac
