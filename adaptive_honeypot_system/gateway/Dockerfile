FROM haproxy:2.9-alpine

USER root

RUN apk add --no-cache bash socat

# Copy pre-generated config files
COPY haproxy.normal.cfg /etc/haproxy/haproxy.normal.cfg
COPY haproxy.honeypot.cfg /etc/haproxy/haproxy.honeypot.cfg

# Copy entrypoint script that selects config based on TEST_HONEYPOT env var
COPY entrypoint.sh /entrypoint.sh
COPY routing_update.sh /usr/local/bin/routing_update.sh

RUN chmod +x /entrypoint.sh /usr/local/bin/routing_update.sh

# Expose ports: 80 (HTTP), 8404 (Stats)
EXPOSE 80 8404

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
