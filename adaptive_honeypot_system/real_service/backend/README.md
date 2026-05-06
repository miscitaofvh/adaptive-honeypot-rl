# Real Backend

Component nay la Flask API that cua ung dung Meridian.

Chuc nang:

- Cung cap API benign cho frontend.
- Tao structured JSON logs de Filebeat/Elasticsearch va dummy analyzer doc.
- Giu API contract gan voi web honeypots de rerouting khong lam frontend vo.

Blueprints:

- `routes/auth.py`: login/register.
- `routes/articles.py`: list/detail/create/search article.
- `routes/tools.py`: markdown preview, ping, URL fetch.

Endpoints quan trong:

- `GET /api/health`
- `POST /api/auth/login`
- `POST /api/auth/register`
- `GET /api/articles`
- `GET /api/articles/<id>`
- `POST /api/articles`
- `POST /api/articles/search`
- `POST /api/tools/preview`
- `POST /api/tools/ping`
- `POST /api/tools/fetch`

Exposure modes:

- `EXPOSURE_MODE=debug`: `GET /api/health` tra ve `status` va `service` de test routing.
- `EXPOSURE_MODE=attack`: `GET /api/health` chi tra ve `{"status":"ok"}` de khong lo backend dang la real service hay honeypot.

Logging:

- `logging_utils.py` cai dat before/after request hooks.
- Log co `event_schema_version`, `event_type`, `session_id`, `x_forwarded_for`, `path`, `status_code`, `duration_ms`, `payload_size`, `body_preview`.
- Password/token/secret duoc mask trong log.

Luu y:

- Backend khong co muc tieu bao ve service.
- Endpoint search dung SQLAlchemy filter an toan; attack engagement duoc tao o honeypot sau khi route.
