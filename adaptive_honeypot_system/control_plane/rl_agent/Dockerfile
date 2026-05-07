FROM python:3.11-slim

WORKDIR /app

COPY control_plane/rl_agent/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --retries 5 --timeout 120 --prefer-binary -r /tmp/requirements.txt

COPY control_plane/state_builder /app/control_plane/state_builder
COPY control_plane/rl_agent /app/control_plane/rl_agent

WORKDIR /app/control_plane/rl_agent
EXPOSE 8003

CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "8003"]
