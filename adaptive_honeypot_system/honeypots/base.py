import os, json, logging, logging.handlers, socket, time, uuid
from datetime import datetime, timezone
from flask import request, g

POT_TYPE = os.environ.get('POT_TYPE','unknown')
SERVICE_NAME = os.environ.get('SERVICE_NAME','honeypot')
EXPOSURE_MODE = os.environ.get('EXPOSURE_MODE', 'debug').strip().lower()
DEBUG_EXPOSURE_VALUES = {'debug', 'dev', 'development', 'operator', 'test'}
SENSITIVE_KEYS = {'password', 'token', 'access_token', 'authorization', 'secret'}
MAX_BODY_PREVIEW = 2048
FILEBEAT_HOST = os.environ.get('FILEBEAT_HOST', 'filebeat')
FILEBEAT_SERVICE_PORT = int(os.environ.get('FILEBEAT_SERVICE_PORT', '5141'))
HOST_DEBUG_LOG_ENABLED = os.environ.get('HOST_DEBUG_LOG_ENABLED', 'true').strip().lower() in {'1', 'true', 'yes'}
HOST_SERVICE_LOG_PATH = os.environ.get('HOST_SERVICE_LOG_PATH', '/var/log/adaptive-honeypot/service_requests.jsonl')
SERVICE_TO_BACKEND = {
    'sqli-honeypot': 'sqli_api',
    'ssti-honeypot': 'ssti_api',
    'cmdi-honeypot': 'cmdi_api',
    'ssrf-honeypot': 'ssrf_api',
}
SURFACE_TO_EXPECTED_HONEYPOT_BACKEND = {
    'articles_search': 'sqli_api',
    'tools_ping': 'cmdi_api',
    'tools_preview': 'ssti_api',
    'tools_fetch': 'ssrf_api',
}

logger = logging.getLogger('honeypot')
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = logging.StreamHandler(); h.setFormatter(logging.Formatter('%(message)s')); logger.addHandler(h)
    try:
        sh = logging.handlers.SysLogHandler(address=(FILEBEAT_HOST, FILEBEAT_SERVICE_PORT), socktype=socket.SOCK_DGRAM)
        sh.setFormatter(logging.Formatter('%(message)s')); logger.addHandler(sh)
    except Exception:
        pass
logger.propagate = False

def is_debug_exposure():
    return EXPOSURE_MODE in DEBUG_EXPOSURE_VALUES

def health_payload(service_name=None):
    payload = {'status': 'ok'}
    if is_debug_exposure():
        payload['service'] = service_name or SERVICE_NAME
    return payload

def log_request(extra=None):
    body_preview, payload_size = _safe_body()
    record = {'event_schema_version':'1.0','event_type':'honeypot_interaction',
              'ts':datetime.now(timezone.utc).timestamp(),'service':SERVICE_NAME,'pot_type':POT_TYPE,
              'request_id':getattr(g,'request_id',''),'method':request.method,'path':request.path,
              'query':request.query_string.decode('utf-8', errors='replace'),
              'remote_addr':request.remote_addr,'x_forwarded_for':request.headers.get('X-Forwarded-For',''),
              'session_id':request.cookies.get('sid',''),'user_agent':request.headers.get('User-Agent',''),
              'payload_size':payload_size,'body_preview':body_preview,
              'duration_ms':round((time.monotonic()-g.start_time)*1000,2),
              'metric_source':'host_service_log','service_role':'honeypot','is_honeypot':True,
              'observed_backend':SERVICE_TO_BACKEND.get(SERVICE_NAME, ''),
              'api_surface':_api_surface(request.path),
              'expected_honeypot_backend':SURFACE_TO_EXPECTED_HONEYPOT_BACKEND.get(_api_surface(request.path), '')}
    if extra: record.update(extra)
    record['status_class'] = f"{int(record.get('status_code', 0)) // 100}xx" if record.get('status_code') else ''
    expected_backend = record.get('expected_honeypot_backend') or ''
    observed_backend = record.get('observed_backend') or ''
    record['route_matches_api_surface'] = bool(expected_backend and observed_backend == expected_backend)
    _write_host_debug_log(record)
    logger.info(json.dumps(record, ensure_ascii=True))

def _write_host_debug_log(record):
    if not HOST_DEBUG_LOG_ENABLED or not HOST_SERVICE_LOG_PATH:
        return
    try:
        log_path = os.path.abspath(HOST_SERVICE_LOG_PATH)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=True) + '\n')
    except Exception:
        pass

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

def _api_surface(path):
    if path == '/api/health':
        return 'health'
    if path == '/api/articles/search':
        return 'articles_search'
    if path.startswith('/api/articles'):
        return 'articles'
    if path == '/api/tools/ping':
        return 'tools_ping'
    if path == '/api/tools/preview':
        return 'tools_preview'
    if path == '/api/tools/fetch':
        return 'tools_fetch'
    if path.startswith('/api/auth'):
        return 'auth'
    return 'other'

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
