FROM python:3.11-slim

WORKDIR /app

COPY control_plane/llm_analyzer/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY control_plane/state_builder /app/control_plane/state_builder
COPY control_plane/llm_analyzer /app/control_plane/llm_analyzer

WORKDIR /app/control_plane/llm_analyzer
EXPOSE 8002

CMD ["uvicorn", "analyzer:app", "--host", "0.0.0.0", "--port", "8002"]
