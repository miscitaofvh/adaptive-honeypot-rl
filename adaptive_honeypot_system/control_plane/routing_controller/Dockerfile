FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
	&& apt-get install -y --no-install-recommends socat \
	&& rm -rf /var/lib/apt/lists/*

COPY control_plane/routing_controller/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY control_plane/rl_agent /app/control_plane/rl_agent
COPY control_plane/routing_controller /app/control_plane/routing_controller
COPY gateway/routing_update.sh /app/gateway/routing_update.sh

RUN chmod +x /app/gateway/routing_update.sh

WORKDIR /app/control_plane/routing_controller
EXPOSE 8001

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
