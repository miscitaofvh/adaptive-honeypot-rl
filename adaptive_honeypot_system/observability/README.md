# Observability

Component nay gom Filebeat, Elasticsearch, va Kibana cho lab local.

Chuc nang:

- Filebeat doc Docker container logs.
- Backend/honeypot/controller/analyzer JSON logs duoc decode thanh fields.
- Elasticsearch luu index `honeypot-logs-*`.
- Kibana dung de xem traffic, interactions, va route decisions.

File chinh:

- `filebeat/filebeat.yml`: input/processor/output Filebeat.
- `elasticsearch/elasticsearch.yml`: Elasticsearch single-node config.
- `kibana/kibana.yml`: Kibana config.

Luu y:

- Filebeat khong con filter theo hardcoded container IDs.
- Analyzer hien poll Elasticsearch de tao LLM-backed route decisions, nen ES/Filebeat la mot phan cua flow demo Web MVP.
- Runtime state hien la `rl_state_v2_16`.
