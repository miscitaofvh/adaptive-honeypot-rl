# Observability

Component này chỉ còn phục vụ log ingest cho Web MVP, không còn là monitoring dashboard deliverable.

Chức năng:

- Filebeat nhận HAProxy syslog UDP trên port `5140`.
- Filebeat nhận backend/honeypot/control-plane JSON events qua UDP port `5141`.
- Backend/honeypot/controller/analyzer JSON logs được decode thành fields.
- Elasticsearch lưu index `honeypot-logs-*` để analyzer poll và replay exporter đọc lại.

File chính:

- `filebeat/filebeat.yml`: input/processor/output Filebeat.
- `elasticsearch/elasticsearch.yml`: Elasticsearch single-node config.

Lưu ý:

- Không có Kibana/dashboard trong scope hiện tại.
- Filebeat không còn filter theo hardcoded container IDs.
- Control plane không scrape Docker stdout; analyzer/controller gửi event replay quan trọng qua UDP syslog (`CONTROL_PLANE_SYSLOG=true`).
- Host-mounted logs trong `logs/` là nguồn dễ đọc nhất để debug/evaluate metric.
