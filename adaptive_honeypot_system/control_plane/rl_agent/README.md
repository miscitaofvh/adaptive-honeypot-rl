# RL Agent

Thu muc nay chua phan RL offline, runtime JSON agent va Torch RL service rieng.

Chuc nang:

- `agent.py`: action space, action masking, runtime `LinearQAgent`.
- `service.py`: FastAPI Torch RL agent service cho debug/predict/export/one-epoch proxy train.
- `generate_fake_data.py`: tao synthetic transitions de bootstrap.
- `train_offline.py`: train offline Q-learning bang PyTorch local.
- `create_dummy_ssti_model.py`: dummy model route moi HTTP state sang SSTI.
- `create_dummy_web_policy_model.py`: dummy subtype-based web model cho SQLi/CMDI/SSTI/SSRF.
- `Dockerfile` + `requirements.txt`: image rieng cho Torch RL service.

Rang buoc quan trong:

- Khong cai `torch` trong `routing_controller`, real service, honeypots, gateway hoac analyzer.
- `rl_agent` container co `torch` co chu dich, nhung khong nam tren request path.
- `requirements-local.txt` chi dung cho train local.
- Runtime controller doc JSON weights hoac dung `RL_POLICY_MODE=heuristic`; controller khong import torch.
- `POST /train/one-epoch` chi la proxy epoch cuc nho de chung minh duong Torch hoat dong, khong phai full train.

Service endpoints:

- `GET /health`: generic trong attack mode, detailed trong debug mode.
- Debug-only `GET /model/info`.
- Debug-only `POST /predict`.
- Debug-only `POST /export`: ghi `artifacts/rl_agent_linear.json`.
- Debug-only `POST /train/one-epoch`: chay 1 proxy epoch nho va co the export artifact.

Make targets:

```bash
cd adaptive_honeypot_system
make rl-agent-export
make rl-agent-one-epoch
make logs-rl-agent
```

Manual predict example:

```bash
curl -s -X POST http://localhost:8003/predict \
  -H "Content-Type: application/json" \
  -d '{
    "state_schema": "rl_state_v2_16",
    "protocol": "http",
    "state": [0,0,0,0,0,0,0,0.9,0.05,0.05,0.05,0,0,0.2,0.4,0.8]
  }'
```

State/action:

- Runtime hien tai: `STATE_DIM = 16`.
- Schema: `rl_state_v2_16` voi 16 floats.
- Trong v2, `protocol` la metadata cua `/decide`, khong nam trong tensor.
- HTTP actions: keep normal, SQLI, SSTI, CMDI, SSRF.
- SSH/FTP/SMTP actions ton tai trong schema de giu alignment voi proposal, nhung L4 data plane chua implement.

`rl_state_v2_16` target order:

1. `session_age_norm`
2. `interaction_rate_norm`
3. `failed_attempts_norm`
4. `payload_complexity_norm`
5. `target_diversity_norm`
6. `current_route`
7. `engagement_depth_norm`
8. `target_sqli_score`
9. `target_cmdi_score`
10. `target_ssti_score`
11. `target_ssrf_score`
12. `target_credential_attack_score`
13. `target_enumeration_score`
14. `evasion_score`
15. `attack_progression_stage`
16. `intent_stability_score`
