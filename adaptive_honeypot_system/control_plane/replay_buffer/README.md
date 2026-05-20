# Replay Buffer Exporter

Component này biến log runtime thành transition JSONL để train offline RL.

Nguồn dữ liệu:

- `rl_state_decision` từ `llm_analyzer`: snapshot `state_t`, action thực tế, window metadata, semantic scores.
- `route_decision` từ `routing_controller`: quyết định `/decide`, backend, route applied, allowed actions.
- `gateway_request`, `request`, `honeypot_interaction`: outcome sau decision để tính reward engagement.

Output tương thích với `control_plane/rl_agent/train_offline.py`:

```json
{
  "session_id": "sid_demo",
  "decision_id": "abc123",
  "step": 0,
  "protocol": "http",
  "state_schema": "rl_state_v2_16",
  "state": [0.0, 0.1, "..."],
  "action": 1,
  "reward": 1.25,
  "next_state": [0.1, 0.2, "..."],
  "done": false,
  "optimal_action": 1
}
```

Reward hiện là heuristic/proxy reward từ log thật:

- Thưởng route đúng honeypot theo target score.
- Thưởng attacker tiếp tục tương tác với honeypot đúng loại.
- Thưởng dwell time, engagement gain, progression gain.
- Phạt false positive trên benign session.
- Phạt giữ normal khi evidence attack mạnh.
- Phạt route sai honeypot hoặc không có follow-up vào honeypot.

Chạy từ `adaptive_honeypot_system/` khi stack đang chạy:

```bash
make export-replay-buffer
```

Hoặc gọi trực tiếp:

```bash
python control_plane/replay_buffer/export_replay_buffer.py \
  --elasticsearch-url http://localhost:9200 \
  --index 'honeypot-logs-*' \
  --lookback-minutes 180 \
  --output control_plane/rl_agent/data/replay_buffer.jsonl
```

Test bằng file JSONL local:

```bash
python control_plane/replay_buffer/export_replay_buffer.py \
  --input-jsonl /path/to/events.jsonl \
  --output /tmp/replay_buffer.jsonl
```

Lưu ý:

- Cần deploy code mới để analyzer/controller gửi `rl_state_decision` và `route_decision` qua Filebeat UDP.
- Nếu output rỗng, kiểm tra Kibana/Elasticsearch có event `app.event_type: rl_state_decision` trong khoảng thời gian chọn hay chưa.
- Đây chưa phải reward chính thức cho khóa luận; nó là reward builder thực dụng để sinh replay buffer ban đầu cho Discrete CQL/offline RL.
