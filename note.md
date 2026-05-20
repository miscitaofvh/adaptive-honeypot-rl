Hệ thống đang chạy theo mô hình **data plane ở Gateway/HAProxy**, còn **control plane chạy bất đồng bộ**: log được đẩy vào Elasticsearch, LLM Analyzer đọc log để dựng state, gọi Routing Controller quyết định route, rồi Controller cập nhật HAProxy map để request sau của cùng session bị đưa vào honeypot tương ứng.

**1. Tổng Quan Flow**
1. Browser/frontend tạo `sid` cookie cho mỗi session.
2. Request đi qua HAProxy Gateway.
3. Gateway log request vào Filebeat/Elasticsearch và vẫn forward request ban đầu về real backend nếu chưa có route.
4. Real backend hoặc honeypot log thêm `body_preview`, tức payload request.
5. `llm_analyzer` poll Elasticsearch, ghép gateway log với service log để có đủ method/path/session/body.
6. Analyzer gọi LLM hoặc rule fallback để phân loại attack: SQLi/CMDi/SSTI/SSRF.
7. Analyzer build state vector `rl_state_v2_16`, gọi `routing_controller /decide`.
8. Controller dùng heuristic/RL policy chọn action, ví dụ `ROUTE_SSTI`.
9. Controller gọi `routing_update.sh` cập nhật HAProxy runtime map.
10. Request tiếp theo cùng `sid`, đúng endpoint tương ứng, sẽ được route vào honeypot.

**2. Session ID**
Frontend tạo session bằng cookie `sid`, đây là khóa chính để route theo attacker/session thay vì route toàn bộ IP hay toàn bộ service.

File quan trọng: [client.js](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/real_service/frontend/src/api/client.js:1)

Ở [client.js](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/real_service/frontend/src/api/client.js:1), hàm `ensureSessionId()` lấy `sid` từ `localStorage`; nếu chưa có thì tạo UUID-like value, lưu vào `localStorage`, rồi set cookie:

`document.cookie = sid=...; path=/; max-age=86400; SameSite=Lax`

Nhờ vậy HAProxy có thể đọc `req.cook(sid)`.

**3. Gateway/HAProxy**
Gateway là điểm vào chính của traffic. File normal mode quan trọng: [haproxy.normal.cfg](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/haproxy.normal.cfg:1)

Gateway log JSON tại [haproxy.normal.cfg](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/haproxy.normal.cfg:20). Log này chứa các field như:

`event_type`, `client_ip`, `backend`, `status`, `method`, `path`, `query`, `content_type`, `content_length`, `referer`, `session_id`.

Gateway capture cookie `sid` ở [haproxy.normal.cfg](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/haproxy.normal.cfg:29), rồi dùng nó trong log và route map.

Các endpoint attack surface được phân loại ở [haproxy.normal.cfg](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/haproxy.normal.cfg:37):

- `/api/articles/search` -> SQLi surface
- `/api/tools/ping` -> CMDi surface
- `/api/tools/preview` -> SSTI surface
- `/api/tools/fetch` -> SSRF surface

Điểm rất quan trọng: route được scope theo endpoint, không phải route toàn session vào một pot cho mọi API. Logic nằm ở [haproxy.normal.cfg](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/haproxy.normal.cfg:44) và [haproxy.normal.cfg](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/haproxy.normal.cfg:54).

Ví dụ:

`sid -> ssti_api` chỉ ảnh hưởng `/api/tools/preview`.

Cùng session đó gọi `/api/tools/ping` vẫn đi real backend, trừ khi session/IP cũng được route vào `cmdi_api`.

Nếu không match route map, API traffic đi real backend tại [haproxy.normal.cfg](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/haproxy.normal.cfg:64). Frontend/static đi `web_frontend` tại [haproxy.normal.cfg](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/haproxy.normal.cfg:65).

**4. HAProxy Dynamic Route Map**
File cập nhật map: [routing_update.sh](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/routing_update.sh:1)

Có hai map chính:

- `session_routes.map`: `sid -> backend`
- `ip_honeypot.map`: `source_ip -> backend`

Định nghĩa ở [routing_update.sh](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/routing_update.sh:6).

Khi controller muốn route session, nó gọi:

`routing_update.sh add_session <sid> <backend>`

Script vừa update file map ở [routing_update.sh](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/routing_update.sh:16), vừa update HAProxy runtime qua admin socket ở [routing_update.sh](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/gateway/routing_update.sh:51). Vì vậy không cần restart gateway.

**5. Log Ingestion**
Filebeat cấu hình ở [filebeat.yml](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/observability/filebeat/filebeat.yml:1).

Có hai nguồn log:

- HAProxy gateway logs qua UDP syslog port `5140`: [filebeat.yml](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/observability/filebeat/filebeat.yml:1)
- Backend/honeypot service logs qua UDP port `5141`: [filebeat.yml](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/observability/filebeat/filebeat.yml:14)

Filebeat decode JSON vào field `app` tại [filebeat.yml](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/observability/filebeat/filebeat.yml:8) và [filebeat.yml](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/observability/filebeat/filebeat.yml:35), rồi đẩy vào Elasticsearch index `honeypot-logs-*` ở [filebeat.yml](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/observability/filebeat/filebeat.yml:56).

**6. Service Logs Và body_preview**
Gateway log không có body request. Vì vậy backend/honeypot phải log thêm `body_preview`.

Real backend logging nằm ở [logging_utils.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/real_service/backend/logging_utils.py:50). Hàm `_body_preview()` đọc body, mask field nhạy cảm như `password`, `token`, rồi truncate 2048 bytes.

Record log backend có các field quan trọng ở [logging_utils.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/real_service/backend/logging_utils.py:79):

`event_type=request`, `method`, `path`, `session_id`, `status_code`, `payload_size`, `body_preview`.

Honeypot logging tương tự trong [base.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/honeypots/base.py:34), nhưng `event_type` là `honeypot_interaction`.

**7. LLM Analyzer**
File chính: [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:1)

Analyzer chạy background worker tại startup ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:1093). Worker loop ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:1063) liên tục poll Elasticsearch mỗi `ANALYZER_INTERVAL_SECONDS`.

Các config chính nằm ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:35):

- `ELASTICSEARCH_URL`
- `ROUTING_CONTROLLER_URL`
- `ANALYZER_ROUTE_THRESHOLD`
- `SERVICE_BODY_WAIT_SECONDS`
- `GROQ_API_KEY`

Mapping attack -> backend nằm ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:63):

- `sqli -> sqli_api`
- `cmdi -> cmdi_api`
- `ssti -> ssti_api`
- `ssrf -> ssrf_api`

Analyzer parse Elasticsearch hit bằng `parse_source()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:307). Nó ưu tiên đọc `_source.app`, tức field JSON mà Filebeat decode ra.

Sau đó `clean_event()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:330) giữ lại các field cần cho phân tích:

`session_id`, `client_ip`, `method`, `path`, `query`, `status`, `bytes_in`, `content_type`, `response_ms`, `user_agent`, `backend`, và nếu có thì thêm `request_body` từ `body_preview`.

**8. Cách Analyzer Ghép Gateway Log Với Body**
Phần quan trọng nhất nằm ở `poll_elasticsearch_once()` tại [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:952).

Analyzer làm 2 pass:

Pass 1: đọc service-level logs (`request`, `honeypot_interaction`) để lấy `body_preview`, cache theo key:

`(session_id, method, path)`

Đoạn này ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:994).

Pass 2: xử lý gateway logs, rồi enrich gateway event bằng body đã cache. Đoạn enrich ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:1022).

Nếu gateway log đến trước service log, analyzer chưa xử lý ngay mà defer vài giây bằng `defer_gateway_event()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:710). Cơ chế này giúp tránh mất payload attack trong body.

Ngoài ra analyzer bỏ qua session sentinel `"-"` của HAProxy bằng `_nullify()` và `_clean_str()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:184), tránh route session giả.

**9. LLM Input Và Rule Fallback**
Analyzer dựng session summary bằng `build_session_context()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:373). Context gồm:

- `session_id`
- `client_ip`
- window start/end
- request count
- failed count
- current backend
- unique paths
- events đã clean
- memory từ lần phân tích trước

Prompt yêu cầu LLM trả JSON nằm ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:519). Output gồm:

`attack_category`, `web_subtype_scores`, `evasion_score`, `attack_progression_stage`, `llm_confidence`, `updated_memory_context`.

Nếu không có Groq API key hoặc LLM lỗi, analyzer dùng `rule_based_semantic_fallback()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:226). Rule này regex các dấu hiệu SQLi/CMDi/SSTI/SSRF.

Một chi tiết thực tế: với markdown có code block, analyzer bỏ fenced code block khỏi CMDi scoring ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:215), để payload markdown chứa triple backtick không bị hiểu nhầm thành command injection.

Nếu LLM trả kết quả yếu nhưng rule thấy attack rõ, `apply_rule_guardrail()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:753) sẽ override bằng rule fallback.

**10. State Vector**
State schema hiện tại là `rl_state_v2_16`, định nghĩa ở [state_schema.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/state_builder/state_schema.py:6).

16 chiều gồm:

- session age
- interaction rate
- failed attempts
- payload complexity
- target diversity
- current route
- engagement depth
- target scores SQLi/CMDi/SSTI/SSRF
- credential/enumeration score
- evasion
- progression
- intent stability

Danh sách field nằm ở [state_schema.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/state_builder/state_schema.py:8).

Analyzer build state ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:783). Các subtype score `[sqli, cmdi, ssti, ssrf]` nằm ở index `[7:11]`.

**11. Analyzer Gọi Controller**
Pipeline chính nằm ở `analyze_session()` tại [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:863).

Nó làm:

1. Build context
2. Gọi LLM hoặc rule fallback
3. Build state vector
4. Lấy subtype score lớn nhất
5. Nếu score vượt threshold thì gọi controller `/decide`

Payload gửi controller nằm ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:906), gồm:

`state_schema`, `protocol=http`, `session_id`, `source_ip`, `state`, `apply_route`.

Request POST `/decide` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:914).

**12. Routing Controller**
File chính: [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:1)

Controller nhận request `/decide` bằng model `DecisionRequest` ở [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:72). Nó validate:

- `state_schema == rl_state_v2_16`
- `protocol` thuộc `http`, `ssh`, `ftp`, `smtp`
- state đủ 16 chiều

Trong MVP, policy có thể chạy `heuristic` hoặc `model`. Hàm chọn policy ở [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:189).

Heuristic action nằm ở [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:198). Nó đọc state indices:

- `state[7]` -> SQLi
- `state[8]` -> CMDi
- `state[9]` -> SSTI
- `state[10]` -> SSRF

Nếu subtype score vượt `HEURISTIC_ROUTE_THRESHOLD`, nó chọn action tương ứng.

Action/backend mapping nằm ở [agent.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/rl_agent/agent.py:19) và [agent.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/rl_agent/agent.py:39).

Endpoint `/decide` nằm ở [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:433). Nó:

1. `select_policy_action(req)`
2. map action -> backend
3. `apply_route_decision(...)`
4. log `route_decision`

**13. Controller Apply Route**
`apply_route_decision()` ở [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:226).

Nếu request có `session_id`, controller gọi:

`routing_update.sh add_session <session_id> <backend>`

Logic này ở [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:238).

Nếu không có session nhưng có `source_ip`, controller fallback sang IP route ở [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:243).

Các debug endpoint để inspect route map nằm ở:

- `GET /routes`: [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:497)
- `GET /route/session/{sid}`: [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:507)
- `DELETE /routes`: [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:481)

Trong `EXPOSURE_MODE=attack`, debug endpoints bị ẩn bằng `require_debug_exposure()` ở [main.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/routing_controller/main.py:163).

**14. Tóm lại**
- Control plane chạy **asynchronous**, request đầu tiên không bị chặn; hệ thống chỉ route các request sau khi analyzer ra quyết định.
- Mục tiêu không phải “protect real service” mà là **tăng engagement**: attacker thấy endpoint vẫn phản hồi hợp lý nhưng bị đưa vào honeypot đúng loại attack.
- Routing theo `sid` giúp cô lập attacker session; user/session khác vẫn dùng real service bình thường.
- Routing được scope theo API surface, nên route `ssti_api` không làm hỏng ping/search/fetch.
- Analyzer dùng cả gateway log và service log: gateway cho routing/session/backend metadata, service log cho payload/body.
- LLM output không cần cover mọi state thô; analyzer/rule code trích xuất state 16D từ logs rồi mới gửi controller.
- Hệ thống có fallback rule-based để demo vẫn hoạt động khi thiếu/quá quota LLM.

LLM output hiện tại **không phải toàn bộ state**. Nó là phần semantic để analyzer suy luận attacker đang làm gì, sau đó code mới chuyển một phần output đó thành state vector 16 chiều.

**LLM Output**
Schema LLM output nằm trong prompt ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:519):

```json
{
  "attack_category": "injection | bruteforce | enumeration | malformed | benign",
  "web_subtype_scores": [sqli, cmdi, ssti, ssrf],
  "evasion_score": 0-1,
  "historical_intent_consistency": 0-1,
  "attack_progression_stage": 0-1,
  "intent_shift_velocity": 0-1,
  "llm_confidence": 0-1,
  "updated_memory_context": "..."
}
```

Output này được validate/normalize ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:568).

Trong bộ state 16 chiều, LLM chiếm **9 chiều trực tiếp/gián tiếp**, từ index `7` đến `15`:

- `7`: `target_sqli_score`
- `8`: `target_cmdi_score`
- `9`: `target_ssti_score`
- `10`: `target_ssrf_score`
- `11`: `target_credential_attack_score`
- `12`: `target_enumeration_score`
- `13`: `evasion_score`
- `14`: `attack_progression_stage`
- `15`: `intent_stability_score`

Mapping nằm ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:783).

Lưu ý: `llm_confidence` **không là một state riêng**, mà dùng để scale các semantic features:

```python
target_scores = web_subtype_scores * llm_confidence
evasion_score = evasion_score * llm_confidence
attack_progression_stage = attack_progression_stage * llm_confidence
intent_stability = historical_intent_consistency * (1 - intent_shift_velocity) * llm_confidence
```

`updated_memory_context` cũng **không vào state**, mà lưu vào `_session_memory` để lần phân tích sau có context.

**Bộ State Đầy Đủ**
Định nghĩa chính thức nằm ở [state_schema.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/state_builder/state_schema.py:8):

```text
0  session_age_norm
1  interaction_rate_norm
2  failed_attempts_norm
3  payload_complexity_norm
4  target_diversity_norm
5  current_route
6  engagement_depth_norm
7  target_sqli_score
8  target_cmdi_score
9  target_ssti_score
10 target_ssrf_score
11 target_credential_attack_score
12 target_enumeration_score
13 evasion_score
14 attack_progression_stage
15 intent_stability_score
```

Tổng cộng: **16 dimensions**, schema version là `rl_state_v2_16`.

**7 State Còn Lại Lấy Từ Đâu**
Các state `0-6` không đến từ LLM, mà được tính trực tiếp từ logs trong `compute_rule_features()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:436):

- `session_age_norm`: thời gian từ request đầu tiên của session, normalize theo 600s.
- `interaction_rate_norm`: số request / thời gian session.
- `failed_attempts_norm`: tỷ lệ response status `>= 400`.
- `payload_complexity_norm`: dựa trên payload size + regex dangerous patterns.
- `target_diversity_norm`: số path khác nhau / tổng request.
- `current_route`: `0` nếu đang ở real backend, `1` nếu đã ở honeypot.
- `engagement_depth_norm`: độ sâu tương tác khi đã vào honeypot.

Nguồn dữ liệu đầu vào cho các state này là clean event từ logs. `clean_event()` ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:330) giữ các field:

```text
session_id, client_ip, method, path, query, status,
bytes_in, bytes_out, content_type, content_length,
response_ms, user_agent, referer, backend, request_body
```

`request_body` được lấy từ `body_preview`.

**Logs Đi Vào Analyzer Như Thế Nào**
Analyzer poll Elasticsearch ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:952).

Nó ghép 2 loại log:

- Gateway log: có `session_id`, `method`, `path`, `backend`, `status`, nhưng không có body.
- Service log: từ real backend/honeypot, có `body_preview`.

Phần cache `body_preview` nằm ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:994).  
Phần enrich gateway event bằng body nằm ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:1022).

Tóm lại:

```text
logs -> clean_event -> rule_features 7D
logs -> session_context -> LLM/rule semantic output -> semantic 9D
7D + 9D = rl_state_v2_16
```

Sau đó analyzer lấy `state[7:11]` để chọn subtype mạnh nhất trước khi gọi controller `/decide`, đoạn này ở [analyzer.py](/home/nhan/adaptive-honeypot-rl/adaptive_honeypot_system/control_plane/llm_analyzer/analyzer.py:884).