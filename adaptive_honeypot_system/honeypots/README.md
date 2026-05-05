# Web Honeypots

Thu muc nay chua 4 low/medium-interaction web honeypots dung Flask.

Muc tieu:

- Giu attacker tiep tuc tuong tac bang response gia lap hop ly.
- Thu thap payload va hanh vi sau khi route.
- Giu API contract gan voi real backend.

Honeypots:

- `cmdi_pot`: command injection, fake output nhu `whoami`, `id`, `/etc/passwd`.
- `sqli_pot`: SQL injection, fake database syntax error.
- `ssti_pot`: server-side template injection, fake template render/config leak.
- `ssrf_pot`: SSRF, fake metadata/internal service response.

Shared files:

- `base.py`: middleware structured JSON logging.
- `fake_data.py`: fake users/articles va token helper.

Logging:

- Log co `event_type=honeypot_interaction`.
- Ghi `session_id`, `x_forwarded_for`, `payload_size`, `body_preview`, `pot_type`, `status_code`.
- Sensitive fields duoc mask.

Luu y:

- Day khong phai high-interaction honeypot.
- Response co tinh "engagement" nhung khong thuc thi command, SQL, template, hay request noi bo that.

