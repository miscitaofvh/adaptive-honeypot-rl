import os, json, logging, time
from datetime import datetime, timezone
from flask import request, g

POT_TYPE = os.environ.get('POT_TYPE','unknown')
SERVICE_NAME = os.environ.get('SERVICE_NAME','honeypot')

logger = logging.getLogger('honeypot')
logger.setLevel(logging.INFO)
h = logging.StreamHandler(); h.setFormatter(logging.Formatter('%(message)s')); logger.addHandler(h)

def log_request(extra=None):
    record = {'ts':datetime.now(timezone.utc).isoformat(),'service':SERVICE_NAME,'pot_type':POT_TYPE,
              'method':request.method,'path':request.path,'query':request.query_string.decode(),
              'remote_addr':request.remote_addr,'session_id':request.cookies.get('sid',''),
              'user_agent':request.headers.get('User-Agent',''),'body':_safe_body(),
              'duration_ms':round((time.monotonic()-g.start_time)*1000,2)}
    if extra: record.update(extra)
    logger.info(json.dumps(record))

def _safe_body():
    try:
        if request.is_json: return json.dumps(request.get_json(silent=True))
        return request.get_data(as_text=True)[:2048]
    except: return ''

def honeypot_middleware(app):
    @app.before_request
    def before(): g.start_time = time.monotonic()
    @app.after_request
    def after(response): log_request({'status_code':response.status_code}); return response
    return app
