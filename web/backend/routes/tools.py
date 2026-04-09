import re, time, subprocess, requests as req_lib, markdown, bleach
from flask import Blueprint, request, jsonify
tools_bp = Blueprint('tools', __name__)

ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + ['h1','h2','h3','h4','h5','h6','p','pre','code','blockquote','ul','ol','li','hr','br','table','thead','tbody','tr','th','td']
ALLOWED_ATTRS = {**bleach.sanitizer.ALLOWED_ATTRIBUTES, 'code':['class'], 'pre':['class']}

@tools_bp.post('/preview')
def preview():
    data = request.get_json(silent=True) or {}; content = (data.get('content') or '')[:32_000]
    rendered = markdown.markdown(content, extensions=['fenced_code','tables','nl2br'])
    safe = bleach.clean(rendered, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
    word_count = len(re.findall(r'\w+', content))
    return jsonify(rendered=safe, word_count=word_count, read_time=max(1,round(word_count/200)))

@tools_bp.post('/ping')
def ping():
    data = request.get_json(silent=True) or {}; host = (data.get('host') or '').strip(); count = min(max(1,int(data.get('count',4))),10)
    if not host: return jsonify(message='host is required'), 400
    if not re.fullmatch(r'[A-Za-z0-9.\-]{1,253}', host): return jsonify(message='Invalid host.'), 400
    try:
        r = subprocess.run(['ping','-c',str(count),'-W','2',host], capture_output=True, text=True, timeout=20)
        output = r.stdout or r.stderr; reachable = r.returncode==0
        latency = None; m = re.search(r'min/avg/max[^=]+=\s*[\d.]+/([\d.]+)/', output)
        if m: latency = float(m.group(1))
        return jsonify(host=host, reachable=reachable, latency_ms=latency, output=output)
    except subprocess.TimeoutExpired: return jsonify(message='Ping timed out.'), 504
    except Exception as e: return jsonify(message=str(e)), 500

@tools_bp.post('/fetch')
def fetch():
    data = request.get_json(silent=True) or {}; url = (data.get('url') or '').strip()
    if not url: return jsonify(message='url is required'), 400
    if not re.match(r'^https?://', url): return jsonify(message='Only HTTP/HTTPS URLs are supported.'), 400
    try:
        start = time.monotonic(); resp = req_lib.get(url, timeout=10, allow_redirects=True, headers={'User-Agent':'Meridian-Inspector/1.0'})
        ct = resp.headers.get('content-type',''); body = resp.text[:8_000] if 'text' in ct else '[binary]'
        return jsonify(status_code=resp.status_code, content_type=ct, size_bytes=len(resp.content), time_ms=round((time.monotonic()-start)*1000), final_url=resp.url, content=body)
    except req_lib.exceptions.Timeout: return jsonify(message='Request timed out.'), 504
    except Exception as e: return jsonify(message=str(e)), 500
