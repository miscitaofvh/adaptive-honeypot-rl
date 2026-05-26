# Observability

Component này phục vụ log ingest cho Web MVP. Kibana được giữ lại như UI debug tùy chọn để đọc index Elasticsearch, nhưng không phải monitoring dashboard deliverable mới.

Chức năng:

- Filebeat nhận HAProxy syslog UDP trên port `5140`.
- Filebeat nhận backend/honeypot/control-plane JSON events qua UDP port `5141`.
- Backend/honeypot/controller/analyzer JSON logs được decode thành fields.
- Elasticsearch lưu index `honeypot-logs-*` để analyzer poll và replay exporter đọc lại.
- Kibana mở ở `http://localhost:5601` để inspect index/logs khi cần debug.

File chính:

- `filebeat/filebeat.yml`: input/processor/output Filebeat.
- `elasticsearch/elasticsearch.yml`: Elasticsearch single-node config.
- `kibana/kibana.yml`: Kibana config trỏ vào Elasticsearch nội bộ.

Lưu ý:

- Không xây thêm dashboard mới trong scope hiện tại; Kibana chỉ là công cụ đọc/debug logs như trước.
- Filebeat không còn filter theo hardcoded container IDs.
- Control plane không scrape Docker stdout; analyzer/controller gửi event replay quan trọng qua UDP syslog (`CONTROL_PLANE_SYSLOG=true`).
- Host-mounted logs trong `logs/` là nguồn dễ đọc nhất để debug/evaluate metric.
