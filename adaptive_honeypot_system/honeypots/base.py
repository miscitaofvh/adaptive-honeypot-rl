import os, json, logging, time, uuid
from datetime import datetime, timezone
from flask import request, g

POT_TYPE = os.environ.get('POT_TYPE','unknown')
SERVICE_NAME = os.environ.get('SERVICE_NAME','honeypot')
SENSITIVE_KEYS = {'password', 'token', 'access_token', 'authorization', 'secret'}
MAX_BODY_PREVIEW = 2048

logger = logging.getLogger('honeypot')
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = logging.StreamHandler(); h.setFormatter(logging.Formatter('%(message)s')); logger.addHandler(h)

def log_request(extra=None):
    body_preview, payload_size = _safe_body()
    record = {'event_schema_version':'1.0','event_type':'honeypot_interaction',
              'ts':datetime.now(timezone.utc).isoformat(),'service':SERVICE_NAME,'pot_type':POT_TYPE,
              'request_id':getattr(g,'request_id',''),'method':request.method,'path':request.path,
              'query':request.query_string.decode('utf-8', errors='replace'),
              'remote_addr':request.remote_addr,'x_forwarded_for':request.headers.get('X-Forwarded-For',''),
              'session_id':request.cookies.get('sid',''),'user_agent':request.headers.get('User-Agent',''),
              'payload_size':payload_size,'body_preview':body_preview,
              'duration_ms':round((time.monotonic()-g.start_time)*1000,2)}
    if extra: record.update(extra)
    logger.info(json.dumps(record, ensure_ascii=True))

def _safe_body():
    try:
        raw = request.get_data(cache=True) or b''
        payload_size = len(raw)
        if request.is_json:
            data = request.get_json(silent=True)
            if isinstance(data, dict):
                data = {str(k): _mask_value(str(k), v) for k, v in data.items()}
            return json.dumps(data, ensure_ascii=True)[:MAX_BODY_PREVIEW], payload_size
        return raw[:MAX_BODY_PREVIEW].decode('utf-8', errors='replace'), payload_size
    except Exception:
        return '', 0

def _mask_value(key, value):
    if key.lower() in SENSITIVE_KEYS:
        return '[redacted]'
    if isinstance(value, dict):
        return {str(k): _mask_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(key, item) for item in value]
    return value

def honeypot_middleware(app):
    @app.before_request
    def before():
        g.start_time = time.monotonic()
        g.request_id = request.headers.get('X-Request-ID') or uuid.uuid4().hex
    @app.after_request
    def after(response):
        response.headers['X-Request-ID'] = getattr(g,'request_id','')
        log_request({'status_code':response.status_code})
        return response
    return app
