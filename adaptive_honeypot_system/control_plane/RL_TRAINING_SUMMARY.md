# Tóm Tắt Quá Trình Huấn Luyện RL

## Phạm Vi

- Phạm vi hiện tại: Định tuyến thích nghi chỉ dành cho Web.
- Bộ điều khiển runtime không import torch.
- Torch chỉ được dùng cho huấn luyện offline, sau đó xuất ra JSON:

```text
control_plane/rl_agent/artifacts/rl_agent_linear.json
control_plane/rl_agent/artifacts/rl_agent_linear.metrics.json
```

## Hợp Đồng Trạng Thái và Hành Động

Lược đồ trạng thái:

```text
state_schema = web_state
STATE_DIM = 16
```

Các trường trạng thái:

```text
0  session_age_norm             (tuổi phiên chuẩn hóa)
1  interaction_rate_norm        (tốc độ tương tác chuẩn hóa)
2  failed_attempts_norm         (số lần thất bại chuẩn hóa)
3  payload_complexity_norm      (độ phức tạp payload chuẩn hóa)
4  target_diversity_norm        (độ đa dạng mục tiêu chuẩn hóa)
5  current_route                (tuyến hiện tại)
6  engagement_depth_norm        (độ sâu tương tác chuẩn hóa)
7  target_sqli_score            (điểm SQLi mục tiêu)
8  target_cmdi_score            (điểm CMDi mục tiêu)
9  target_ssti_score            (điểm SSTi mục tiêu)
10 target_ssrf_score            (điểm SSRF mục tiêu)
11 target_credential_attack_score (điểm tấn công thông tin xác thực)
12 target_enumeration_score     (điểm liệt kê mục tiêu)
13 evasion_score                (điểm né tránh)
14 attack_progression_stage     (giai đoạn tiến triển tấn công)
15 intent_stability_score       (điểm ổn định ý định)
```

Không gian hành động:

```text
0 KEEP_NORMAL -> normal_api   (giữ bình thường)
1 ROUTE_SQLI  -> sqli_api     (định tuyến SQLi)
2 ROUTE_SSTI  -> ssti_api     (định tuyến SSTi)
3 ROUTE_CMDI  -> cmdi_api     (định tuyến CMDi)
4 ROUTE_SSRF  -> ssrf_api     (định tuyến SSRF)
```

## Tập Dữ Liệu

Định dạng chuyển đổi là JSONL:

```json
{
  "session_id": "session_00001",
  "source": "generated",
  "step": 0,
  "protocol": "http",
  "attack_type": "sqli",
  "state_schema": "web_state",
  "state": [0.0, 0.2, 0.1, 0.8, 1.0, 0.0, 0.0, 0.9, 0.0, 0.0, 0.0, 0.0, 0.0, 0.4, 0.5, 0.8],
  "action": 1,
  "reward": 1.8,
  "next_state": [0.1, 0.3, 0.1, 0.8, 1.0, 1.0, 0.3, 0.9, 0.0, 0.0, 0.0, 0.0, 0.0, 0.4, 0.6, 0.8],
  "done": false,
  "optimal_action": 1
}
```

Nguồn dữ liệu:

```text
generated input -> control_plane/rl_agent/data/fake_transitions.jsonl
replay input    -> control_plane/rl_agent/data/replay_buffer.jsonl
training set    -> control_plane/rl_agent/data/training_dataset.jsonl
```

Tập dữ liệu huấn luyện hiện được chọn:

```text
tổng số chuyển đổi    = 243.417
hàng tổng hợp         = 200.117
hàng phát lại         = 43.300
phiên nguồn           = tổng hợp: 20.000, phát lại: 240
lần lặp phát lại      = 100
```

## Thuật Toán

Thuật toán chính: `CQL` trên mạng Q tuyến tính rời rạc.

Lý do chọn CQL:

- Tập dữ liệu là offline: `(state, action, reward, next_state, done)`.
- Không xây dựng môi trường động để khám phá RL trực tuyến.
- Hình phạt bảo thủ giảm thiểu việc định giá quá cao các hành động chưa thấy.
- Không gian hành động rời rạc nhỏ và cố định.

Baseline giữ lại để so sánh: `q_learning`.

Lưu ý điều chỉnh quan trọng:

```text
gamma = 0.96 khiến các trạng thái phát lại lành tính bị lệch về ROUTE_SSTI.
gamma = 0.0 khắc phục lỗi định tuyến sai khi phát lại và phù hợp với tính đúng đắn của định tuyến tức thì.
```

## Tham Số Khuyến Nghị

Mô hình tốt nhất hiện tại:

```text
algorithm                  = cql
epochs                     = 80
gamma                      = 0.0
batch_size                 = 512
learning_rate              = 0.003
l2                         = 0.0005
cql_alpha                  = 1.0
cql_temperature            = 1.0
behavior_cloning_weight    = 0.35
init_policy                = random
target_update_period       = 1
split_strategy             = grouped
val_ratio                  = 0.2
device                     = cpu
```

## Các Lệnh

Tạo dữ liệu tổng hợp:

```bash
cd adaptive_honeypot_system
make gen-fake-data PYTHON=../.venv/bin/python
```

Tạo bộ đệm phát lại thực qua stack Web đang chạy:

```bash
cd adaptive_honeypot_system
make mode-debug
make generate-replay-buffer PYTHON=../.venv/bin/python RL_REPLAY_SESSIONS=240 RL_REPLAY_SEED=20260527
```

Xây dựng training dataset thống nhất:

```bash
cd adaptive_honeypot_system
make build-training-dataset PYTHON=../.venv/bin/python RL_REPLAY_REPEAT=100
```

Huấn luyện mô hình khuyến nghị:

```bash
cd adaptive_honeypot_system
python3 -B control_plane/rl_agent/train_offline.py \
  --dataset control_plane/rl_agent/data/training_dataset.jsonl \
  --output control_plane/rl_agent/artifacts/rl_agent_linear.json \
  --algorithm cql \
  --epochs 80 \
  --gamma 0.0 \
  --batch-size 512 \
  --learning-rate 0.003 \
  --cql-alpha 1.0 \
  --cql-temperature 1.0 \
  --behavior-cloning-weight 0.35 \
  --init-policy random \
  --target-update-period 1 \
  --device cpu \
  --split-strategy grouped \
  --val-ratio 0.2 \
  --log-every 20
```

Tải lại mô hình đã huấn luyện vào runtime:

```bash
cd adaptive_honeypot_system
docker compose up -d --force-recreate routing_controller llm_analyzer
curl -s -X POST http://localhost:8001/model/reload | python -m json.tool
```

Kiểm tra nhanh quyết định runtime:

```bash
curl -s -X POST http://localhost:8001/decide \
  -H "Content-Type: application/json" \
  -d '{"state_schema":"web_state","protocol":"http","apply_route":false,"state":[0.0003,0.6,0.0,0.449,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.035,0.175]}' \
  | python -m json.tool
```

Kết quả mong đợi: `KEEP_NORMAL`.

Kiểm tra luồng đầy đủ:

```bash
cd adaptive_honeypot_system
make test-adaptive-attacks PYTHON=../.venv/bin/python
make test-adaptive-web PYTHON=../.venv/bin/python
```

## Phân Chia Tập Kiểm Tra

Mặc định kiểm tra xác thực là nghiêm ngặt:

```text
split_strategy = grouped   (phân nhóm)
group_by       = session_id
val_ratio      = 0.2
```

Quy tắc:

- Một `session_id` chỉ được xuất hiện trong một phân chia duy nhất.
- Phân chia được phân tầng theo `source + dominant attack_type`.
- Chỉ số tổng hợp và phát lại được báo cáo riêng biệt.

Các trường bắt buộc kiểm tra:

```text
split_summary.session_overlap_count
split_summary.transition_fingerprint_overlap_count
split_summary.transition_fingerprint_overlap_rate
split_summary.train.source_counts
split_summary.validation.source_counts
```

Tiêu chí chấp nhận:

```text
session_overlap_count = 0
fingerprint_overlap_rate phải rất thấp
tập xác thực phải chứa cả hàng tổng hợp lẫn hàng phát lại
```

## Chỉ Số Huấn Luyện

Đọc từ:

```text
control_plane/rl_agent/artifacts/rl_agent_linear.metrics.json
```

Các trường bắt buộc:

```text
initial_validation_metrics    (chỉ số xác thực ban đầu)
epoch_history                 (lịch sử epoch)
train_metrics                 (chỉ số huấn luyện)
validation_metrics            (chỉ số xác thực)
validation_metrics.by_source  (theo nguồn)
validation_metrics.by_attack_type  (theo loại tấn công)
validation_metrics.confusion_matrix (ma trận nhầm lẫn)
validation_metrics.per_action (theo từng hành động)
generalization                (khả năng tổng quát hóa)
```

Các chỉ số cần báo cáo:

```text
độ chính xác xác thực
macro_f1 xác thực
weighted_f1 xác thực
avg_proxy_reward xác thực
độ chính xác phát lại
macro_f1 phát lại
precision / recall / f1 của KEEP_NORMAL
precision / recall / f1 theo từng hành động
khoảng cách độ chính xác huấn luyện - xác thực
```

## Kết Quả Tốt Nhất Hiện Tại

Mô hình được chọn gần nhất:

```text
lần chạy VM         = vm_tune_gamma_20260527_145952/random_cql_gamma0_alpha1_bc035
thuật toán          = cql
init_policy         = random
gamma               = 0.0
epochs              = 80
```

Kết quả xác thực:

```text
số mẫu                   = 49.104
độ chính xác             = 1.0
macro_f1                 = 1.0
weighted_f1              = 1.0
avg_proxy_reward         = 1.2808447377
replay_accuracy          = 1.0
replay_macro_f1          = 1.0
KEEP_NORMAL precision    = 1.0
KEEP_NORMAL recall       = 1.0
session_overlap_count    = 0
fingerprint_overlap      = 9
fingerprint_overlap_rate = 0.0002239307
```

Kiểm tra runtime đã qua:

```text
trạng thái tín hiệu zero lành tính -> KEEP_NORMAL
trạng thái SQLi                    -> ROUTE_SQLI
make test-adaptive-attacks
make test-adaptive-web
Kiểm tra liên tục Markdown/Ping frontend bằng Playwright
```

## Chỉ Số Đề Xuất

Chỉ số huấn luyện là chỉ số mô hình. Chỉ số đề xuất là chỉ số runtime từ log được gắn với host:

```bash
cd adaptive_honeypot_system
make evaluate-metrics PYTHON=../.venv/bin/python
cat logs/metrics_report.json | python -m json.tool
```

Các chỉ số đề xuất:

```text
honeypot_engagement_rate                    (tỷ lệ tương tác honeypot)
avg_requests_after_adaptive_rerouting       (số yêu cầu trung bình sau định tuyến lại thích nghi)
session_length_seconds                      (độ dài phiên theo giây)
correct_honeypot_routing_rate               (tỷ lệ định tuyến honeypot đúng)
false_rerouting_rate_on_benign_sessions     (tỷ lệ định tuyến lại sai trên phiên lành tính)
normal_service_continuity_rate              (tỷ lệ liên tục dịch vụ bình thường)
```

Không đưa các trường báo cáo phụ này trở lại trạng thái RL trừ khi lược đồ trạng thái được thay đổi có chủ đích.
