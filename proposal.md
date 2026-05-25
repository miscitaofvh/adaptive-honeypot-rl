# Hệ thống lựa chọn honeypot thích ứng dựa trên học tăng cường và phân tích hành vi tấn công bằng mô hình ngôn ngữ lớn

## 1. Mục tiêu
Xây dựng một hệ thống honeypot thông minh có khả năng tự động chọn honeypot phù hợp dựa trên hành vi tấn công của attacker, và sử dụng RL để đưa ra quyết định routing chính xác theo thời gian thực. Hệ thống sẽ được thiết kế để xử lý nhiều loại attack trên nhiều service và protocol khác nhau.



Hệ thống phải xử lý được cả trường hợp attacker đổi hoặc xài nhiều loại attack lên nhiều endpoint khác nhau trong cùng một session (SQLi, SSTI, CMDi, SSRF), GIẢ SỬ KHÔNG XÀI AUTOMATED TOOLS.

Lưu ý: 
* Mục tiêu không phải là BẢO VỆ SERVICE, mà là TĂNG THỜI GIAN TƯƠNG TÁC VỚI HONEYPOT, giữ cho attacker ở lại càng lâu càng tốt để thu thập thông tin và phân tích.
* Trọng tâm sẽ là ở LLM và RL nên các thiết kế về web, service, monitoring được tinh giản bớt, không nhằm phản ánh đầy đủ môi trường production.
* Huấn luyện RL model sẽ được thực hiện bằng **Offline RL (Batch RL)** thay vì phải tự setup môi trường cho **Online RL**. 

## 2. Ý tưởng cốt lõi
Hệ thống áp dụng kiến trúc tách biệt giữa Data Plane (xử lý luồng traffic tốc độ cao) và Control Plane (phân tích AI bất đồng bộ). Do đặc thù của các giao thức mạng, cơ chế định tuyến được chia làm 2:
* **Web (HTTP - L7)**: Mid-session Rerouting. Gateway định tuyến linh hoạt dựa trên session_id (Cookie/Header). Quá trình định tuyến lại sang honeypot diễn ra mượt mà giữa các request trong cùng một phiên mà không làm đứt kết nối.
* **Các service khác (SSH, FTP, SMTP - L4 TCP)**: Drop-and-Catch Rerouting. Việc định tuyến lại một kết nối TCP đang thiết lập là bất khả thi. Do đó, hệ thống sử dụng IP-based tracking. Khi RL Agent quyết định adaptive routing, Controller sẽ cập nhật luật định tuyến (map IP của attacker sang Honeypot) và chủ động ngắt kết nối (TCP RST) hiện tại. Khi attacker/tool tự động reconnect, traffic sẽ đi thẳng vào Honeypot.

## 3. Scope
### In scope
- Local Docker demo.
- Frontend + backend API tách lớp (WEB app service).
- Unified L4/L7 Gateway (HAProxy) để phân luồng traffic.
- Triển khai ELK Stack và Monitoring Dashboard.
- Cấu trúc AI Control Plane: LLM trích xuất TTPs/Intent từ logs + RL Agent đưa ra quyết định định tuyến.
- Adaptive Rerouting:
    - Định tuyến cấp session (Session-level) cho Web và các loại honeypot.
    - Định tuyến cấp IP kết hợp Drop-and-Catch cho SSH, FTP, SMTP. (attacker reconnect sau TCP reset là assumption thực nghiệm)
- Demo attack với web gồm 4 loại server-side attack: SQLi, command injection, SSTI, SSRF.
- Demo attack với các service khác:
    * SSH: bruteforce authentication
    * FTP: bruteforce authentication, file enumeration / unauthorized file access
    * SMTP: bruteforce authentication, user enumeration


### Out of scope
- Public Internet deployment, production hardening.
- Online RL training trên hệ thống chạy thực.
- Auto-scaling/Kubernetes orchestration.
- LLM fine-tuning.
- High-interaction honeypot phức tạp.

## 4. Research Questions
- RQ1: Phương pháp đề xuất có hiệu quả hơn các rule-based route hay static honeypot không?
- RQ2: RL action có chính xác trong việc route attacker tới honeypot phù hợp không? Có giảm thiểu false positives trên benign sessions không?
- RQ3: Độ trễ của pipeline phân tích (log aggregation, LLM inference, RL decision, policy update) có đủ thấp để hỗ trợ adaptive rerouting mà không gây ảnh hưởng đáng kể đến luồng phục vụ bình thường không?
- RQ4: Khi attacker triển khai nhiều loại attack trong cùng session, hệ thống có adaptive rerouting đủ tốt và vẫn giữ service behavior ổn định/không lộ chuyển hướng không?

## 5. System Architecture
### Data Plane (Luồng xử lý tốc độ cao)
**Unified Gateway (HAProxy)**: Đóng vai trò Reverse Proxy L4/L7. Duy trì Bảng định tuyến động (Dynamic Routing Table) được cấp phát từ Control Plane để bẻ traffic dựa trên IP hoặc Session.

**Normal Services**: Web API thật, SSH/FTP/SMTP server.
*Note: Chỉ cần dựng mock service, không cần phải hoàn chỉnh*

**Honeypot Services**: Các container chạy dịch vụ giả mạo (Web Honeypots API, Cowrie, Dionaea)

### Control Plane (Luồng phân tích AI - Chạy Async)
**Log Forwarder (Filebeat)**: Đẩy raw logs/events từ Gateway và Normal Services về ELK.

**LLM Analyzer**: Bắt buộc không xử lý raw logs để tránh tràn token và trễ (latency). Elasticsearch sẽ thực hiện Aggregation (tổng hợp tần suất, gom nhóm payload) mỗi 5s/lần cho từng IP nghi ngờ. LLM chỉ nhận bản tóm tắt (Summary JSON) để trích xuất semantic/feature states.

LLM Analyzer sẽ không hoạt động độc lập trên từng window mà hoạt động theo cơ chế Stateful Analysis:

- Input: [Log hiện tại (5s)] + [Tóm tắt lịch sử (Memory từ Redis)].
- Task: LLM phân tích sự thay đổi hành vi và cập nhật lại bản tóm tắt mới vào Redis.
- Output: Trích xuất các Semantic Features bao quát cả quá trình tấn công thay vì chỉ snapshot hiện tại.

**RL Agent**: Nhận State Vector kết hợp từ rule-based + LLM, suy luận Action (Route đi đâu).

**Routing Controller**: Giao tiếp qua API với HAProxy để cập nhật rule. Chủ động gửi tín hiệu kill connection nếu là giao thức L4 để kích hoạt Drop-and-Catch.

Flow chung cho toàn bộ service:
```text
[Attacker] 
   │
   ▼ (1. Kết nối & Tương tác ban đầu)
[ Unified Gateway (HAProxy) ] ──(L4/L7 Routing)──► [ Normal Services (Web/SSH/FTP) ]
   │                                                         │
   │ (5. Cập nhật Rule & Ngắt kết nối TCP)                   │ (2. Sinh Logs)
   ▼                                                         ▼
[ Routing Controller ] ◄──(4. Quyết định)── [ RL Agent ] ◄── [ LLM Analyzer ] (3. Trích xuất State)
   │
   ▼ (6. Kẻ tấn công Reconnect hoặc gửi Request tiếp theo)
[ Unified Gateway ] ──(Dựa vào Bảng Rule mới)──► [ Honeypot Services (Cowrie/Web_POT) ]
```
### Luồng xử lý chi tiết theo Protocol
#### WEB (L7): 
Gateway đọc HTTP Header/Cookie. Đổi route mượt mà giữa các request ngay lập tức khi bảng định tuyến cập nhật. Frontend render response theo API contract thống nhất.

#### SSH / FTP / SMTP (L4):
* Attacker tấn công Normal Service. Log được sinh ra.
* AI Pipeline xác định hành vi độc hại. Controller cập nhật rule `[Attacker_IP]` -> `[Honeypot_IP]`.
* Controller ra lệnh Gateway/Normal Server ngắt kết nối TCP hiện hành của attacker.
* Attacker reconnect. Dựa trên Bảng định tuyến mới, Gateway chuyển tiếp thẳng luồng TCP L4 vào Cowrie (SSH), Dionaea (FTP) hoặc Mailoney (SMTP).


## 6. Thành phần chính 
**Unified Gateway (HAProxy)**: Quản lý kết nối L4/L7, thực thi các rule định tuyến động.

**Frontend service**: Render response JSON, tách biệt hoàn toàn khỏi logic bảo mật.

**Normal Services**: Backend thật.

**Honeypot Services**: SQLI_POT, SSTI_POT, CMDI_POT, SSRF_POT (cùng API contract với Normal Web); Cowrie (SSH); Dionaea (FTP); Mailoney (SMTP).

**Routing Controller**: Dịch vụ FastAPI trung gian, nhận lệnh từ RL Agent và điều khiển cấu hình của HAProxy qua Data Plane API.

**SIEM & Log Forwarder**: Elasticsearch + Filebeat.


## 7. LLM + State Extraction
LLM nhận Summary JSON từ Elasticsearch (pre-aggregated mỗi 5s), trả ra các trường ngữ nghĩa.
Các trường dự tính: 
```json
{
  "attack_category": "injection", 
  "web_subtype_scores": [0.82, 0.05, 0.07, 0.06], 
  "evasion_score": 0.60,
  
  "historical_intent_consistency": 0.85, // Đánh giá độ kiên định của attacker so với quá khứ
  "attack_progression_stage": 0.40, // 0.2: Recon, 0.5: Exploit, 0.8: Lateral/Post-exploit
  "intent_shift_velocity": 0.12, // Tốc độ rẽ nhánh chiến thuật
  
  "llm_confidence": 0.92, // Trọng số tin cậy
  
  "updated_memory_context": "Attacker initially performed directory enumeration (recon). Now shifted entirely to SQLi probing on /api/login." // Chuỗi này sẽ được Control Plane ghi đè lại vào Redis
}
```
Thông qua state builder, các state này sẽ được kết hợp cùng các state được extract (tự build script hoặc cấu hình) từ logs, (ví dụ như session_age) để tạo bộ state hoàn chỉnh cho RL agent. 

## 8. RL Formulation (BCQ hoặc các thuật toán khác)
### 8.1 State
State vector được tinh gọn để giảm số chiều nhưng vẫn mở rộng được sang HTTP/SSH/FTP/SMTP. `protocol` không nằm trong tensor mà là metadata bắt buộc gửi kèm `/decide`; controller dùng metadata này để action masking và chọn profile normalize theo giao thức.

```python
state = {
    # SESSION METRICS (3)
    "session_age_norm": 0.42,
    # Thời gian sống của session/IP, normalize theo max_window (vd: 10 phút)
    
    "interaction_rate_norm": 0.28,
    # HTTP: req/s | SSH/FTP/SMTP: command hoặc auth attempt / phút. Normalize theo ngưỡng bất thường
    
    "failed_attempts_norm": 0.64,
    # Số request/auth thất bại tích lũy. Quan trọng cho bruteforce & enumeration detection

    # PAYLOAD SIGNALS (2)
    "payload_complexity_norm": 0.73,
    # Mức bất thường/độ phức tạp payload, kết hợp size, ký tự nguy hiểm, encoding/obfuscation
    
    "target_diversity_norm": 0.52,
    # Số lượng path/command/user/endpoint khác nhau đã thử / tổng attempt. Phát hiện enumeration.
    # Với injection attack thần thuần → thường thấp

    # ROUTING / ENGAGEMENT STATE (2)
    "current_route": 0,
    # 0: Normal Service | 1: Honeypot — giúp RL tránh re-route thừa
    
    "engagement_depth_norm": 0.30,
    # Mức attacker đang tiếp tục tương tác sau route: dwell time, request count, command count, v.v.

    # TARGET / HONEYPOT SCORES (6)
    "target_sqli_score": 0.82,
    "target_cmdi_score": 0.05,
    "target_ssti_score": 0.07,
    "target_ssrf_score": 0.06,
    "target_credential_attack_score": 0.00,
    "target_enumeration_score": 0.00,
    # HTTP dùng 4 score đầu. SSH/FTP/SMTP dùng credential/enumeration score.

    # SEMANTIC MEMORY FEATURES (Do LLM tổng hợp từ quá khứ)
    "evasion_score": 0.45,
    # Mức né tránh/obfuscation, scale bởi llm_confidence trước khi đưa vào tensor
    
    "attack_progression_stage": 0.4, 
    # Giai đoạn tấn công: 0.2 (Recon), 0.5 (Exploit), 0.8 (Post-Exploit)
    
    "intent_stability_score": 0.74,
    # Tín hiệu tổng hợp từ historical_intent_consistency và intent_shift_velocity.
}
```

### Giải thích:
Để tương thích với thuật toán RL/BCQ, State Dictionary được flatten thành Tensor 1D 16 chiều. Các đặc trưng từ LLM được scale với `llm_confidence` trước khi ghép nối, nhưng `llm_confidence` không nằm trong tensor để tránh tăng chiều không cần thiết.

```python
# Tiền xử lý Graceful Degradation
effective_target_scores = target_scores * llm_confidence
effective_evasion = evasion_score * llm_confidence
effective_progression = attack_progression_stage * llm_confidence

# Tiền xử lý Memory
intent_stability_score = historical_intent_consistency * (1 - intent_shift_velocity) * llm_confidence

# 16 chiều
state_tensor = np.concatenate([
    [session_age_norm],                  # 1
    [interaction_rate_norm],             # 1
    [failed_attempts_norm],              # 1
    [payload_complexity_norm],           # 1
    [target_diversity_norm],             # 1
    [current_route],                     # 1
    [engagement_depth_norm],             # 1
    effective_target_scores,             # 6
    [effective_evasion],                 # 1
    [effective_progression],             # 1
    [intent_stability_score]             # 1
])
```

* **Protocol metadata:** Không encode dạng integer (0/1/2/3) vì gây quan hệ thứ tự giả tạo. Cũng không giữ one-hot trong tensor vì `/decide` đã nhận `protocol` riêng. Controller dùng `protocol` để action masking — gán các Q-values của action không thuộc protocol hiện tại thành $-\infty$ trước bước argmax.
* **Session Metrics (3 scalar):** Ba trường đo hành vi theo thời gian tích lũy, không phải snapshot tức thời. `session_age_norm` normalize theo max expected session window (e.g. 600s). `interaction_rate_norm` và `failed_attempts_norm` normalize theo ngưỡng anomaly của từng protocol riêng biệt (ngưỡng SSH brute khác HTTP flood) để tránh lệch scale.
* **Payload Signals (2 scalar):** `payload_complexity_norm` thay cho size-only anomaly để thực tế hơn với Web/L4; có thể lấy từ size, entropy, ký tự nguy hiểm, encoding. `target_diversity_norm` = `unique_targets / total_attempts`.
* **Target Scores (6 scalar):** Đây là lớp trừu tượng giữa LLM và RL. HTTP dùng SQLi/CMDi/SSTI/SSRF; SSH/FTP/SMTP dùng credential attack/enumeration. Khi thêm giao thức mới, ưu tiên map vào target score hiện có trước khi tăng chiều state.
* **Engagement State:** `engagement_depth_norm` là tín hiệu trực tiếp cho mục tiêu khóa luận: attacker có tiếp tục tương tác sau khi bị route sang honeypot hay không.
* **Semantic Memory:** `intent_stability_score` gộp `historical_intent_consistency`, `intent_shift_velocity`, và confidence. Nó thay cho `attack_vector_shift` + `memory_decay_weight` trong schema cũ, giảm chiều nhưng vẫn giữ tín hiệu attacker đang ổn định hay đổi chiến thuật.

### 8.2 Actions & Action Masking
Thay vì cho phép chọn tự do gây lỗi định tuyến chéo giao thức, hệ thống áp dụng **Action Masking**. Dựa vào `protocol` metadata của request `/decide`, Controller sẽ mask (đưa xác suất về 0) các action không hợp lệ.
Agent chỉ được chọn trong các tập con sau:
- Nếu HTTP: `[KEEP_NORMAL, SQLi_POT, SSTI_POT, SSRF_POT, CMDi_POT]`
- Nếu SSH: `[KEEP_NORMAL, SSH_POT]`
- Nếu FTP: `[KEEP_NORMAL, FTP_POT]`
- Nếu SMTP: `[KEEP_NORMAL, SMTP_POT]`

### 8.3 Reward
- Thưởng cho route đúng loại attack, thời gian tương tác lâu hơn, giữ API contract compatibility.
- Phạt false positive trên benign session, route sai honeypot, giữ normal quá lâu khi evidence mạnh, thời gian tương tác với honeypot ngắn, contract mismatch gây frontend lỗi.

Cụ thể:
$$R_t = (\alpha \cdot E_t) - (\beta \cdot FP_t) - (\gamma \cdot C_t) - (\delta \cdot D_t) $$

Trong đó:
* $E_t$ (Engagement): Điểm thưởng cho mỗi interaction độc hại mới trên Honeypot.
* $FP_t$ (False Positive): Trừ điểm nặng nếu định tuyến vào nhầm Honeypot.
* $C_t$ (Contract Mismatch): Trừ điểm nếu Honeypot web trả sai định dạng schema.
* $D_t$ (Delay penalty): Trừ điểm nếu attacker không tương tác với honeypot sau định tuyến.
* $\alpha, \beta, \gamma, \delta$: Các siêu tham số tinh chỉnh.


## 9. Evaluation Plan
### Metrics
- Honeypot engagement rate.
- Avg requests after adaptive rerouting.
- Session length.
- Correct honeypot routing rate (route đúng honeypot với đúng loại service và attack).
- False rerouting rate trên benign sessions.
- Normal-service continuity rate.

## 10. Tech Stack đề xuất
- **Unified Gateway (L4/L7)**: HAProxy
- **Frontend / Backend**: HTML5 + Vanilla JS
- **Honeypots**: Flask (Web), Cowrie (SSH), Dionaea (FTP), Mailoney (SMTP)
- **Control Plane API**: FastAPI
- **Data/Logging & Aggregation**: ELK Stack (Elasticsearch, Kibana), Filebeat
- **LLM Analyzer**: Groq API — Llama 3.3 70B (nhận pre-aggregated data)
- **RL Agent**: PyTorch
- **Infrastructure**: Docker Compose

## 11. Demo Plan
Benign session -> Phục vụ bình thường tại Normal API.

Single-attack session -> Định tuyến lại vào honeypot tương ứng (SQLI_POT, SSTI_POT...).

Multi-attack session: Cho phép định tuyến linh hoạt giữa nhiều loại honeypot web khác nhau trong cùng một session dựa trên TTPs đang thay đổi.

## Out of scope cho demo:
### L4 Protocols (SSH/FTP - Drop-and-Catch)
* Attacker bruteforce SSH -> Rớt kết nối -> Reconnect bị bẻ vào Cowrie.
* Attacker bruteforce FTP hoặc liệt kê file/path -> reconnect bị định tuyến vào Dionaea.
* Attacker thực hiện SMTP user enumeration hoặc AUTH bruteforce -> reconnect bị định tuyến vào Mailoney.

Lưu ý: Không thực hiện adaptive rerouting qua lại các honeypot khác nhau khi kết nối TCP L4 đã được chốt (pinned) vào Honeypot.

### Monitoring
Xây dựng Real-time Kibana Dashboard song song với frontend để visualize:

- Tỷ lệ traffic Normal vs Honeypot.
- Biểu đồ phân phối các attack (SQLi, SSTI...) theo thời gian.
- Route history và actions của RL agent (hiển thị trạng thái shift khi attacker đổi vector).
