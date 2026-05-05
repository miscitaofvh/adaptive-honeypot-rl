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

- `STATE_DIM = 24`.
- HTTP actions: keep normal, SQLI, SSTI, CMDI, SSRF.
- SSH/FTP/SMTP actions ton tai trong schema de giu alignment voi proposal, nhung L4 data plane chua implement.

