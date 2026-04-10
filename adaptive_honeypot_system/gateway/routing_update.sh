#!/bin/bash
# Script to update HAProxy routing maps dynamically
# Called by Routing Controller when RL Agent makes routing decisions

HAPROXY_SOCK="/var/run/haproxy/admin.sock"
SESSION_ROUTES_MAP="/etc/haproxy/maps/session_routes.map"
IP_HONEYPOT_MAP="/etc/haproxy/maps/ip_honeypot.map"

# Usage: ./routing_update.sh add_session <session_id> <backend_name>
# Usage: ./routing_update.sh add_ip <ip_address> <backend_name>
# Usage: ./routing_update.sh remove_session <session_id>
# Usage: ./routing_update.sh remove_ip <ip_address>
# Usage: ./routing_update.sh drop_connection <ip_address>  # TCP RST for L4 protocols

case "$1" in
    add_session)
        echo "$2 $3" >> "$SESSION_ROUTES_MAP"
        echo "Session routing updated: $2 -> $3"
        ;;
    add_ip)
        echo "$2 $3" >> "$IP_HONEYPOT_MAP"
        echo "IP routing updated: $2 -> $3"
        ;;
    remove_session)
        sed -i "/$2/d" "$SESSION_ROUTES_MAP"
        echo "Session routing removed: $2"
        ;;
    remove_ip)
        sed -i "/$2/d" "$IP_HONEYPOT_MAP"
        echo "IP routing removed: $2"
        ;;
    drop_connection)
        # Trigger TCP connection drop via HAProxy admin socket
        # This is typically handled by the Routing Controller service
        echo "drop_connection requested for $2 - handled by controller"
        ;;
    *)
        echo "Usage: $0 {add_session|add_ip|remove_session|remove_ip|drop_connection} <identifier> [backend_name]"
        exit 1
        ;;
esac
