# RL Agent

Thu muc nay chua phan RL offline va runtime agent.

Chuc nang:

- `agent.py`: action space, action masking, runtime `LinearQAgent`.
- `generate_fake_data.py`: tao synthetic transitions de bootstrap.
- `train_offline.py`: train offline Q-learning bang PyTorch local.
- `create_dummy_ssti_model.py`: dummy model route moi HTTP state sang SSTI.
- `create_dummy_web_policy_model.py`: dummy subtype-based web model cho SQLi/CMDI/SSTI/SSRF.

Rang buoc quan trong:

- Khong cai `torch` trong runtime containers.
- `requirements-local.txt` chi dung cho train local.
- Runtime controller doc JSON weights hoac dung `RL_POLICY_MODE=heuristic`.

State/action:

- Runtime hien tai: `STATE_DIM = 24`.
- Schema da chot de migrate: `rl_state_v2_16` voi 16 floats.
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
