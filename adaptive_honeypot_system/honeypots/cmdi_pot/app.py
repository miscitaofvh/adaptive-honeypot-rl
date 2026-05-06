import os, re, sys; sys.path.insert(0,'/app/shared')
from flask import Flask, request, jsonify
from flask_cors import CORS
from honeypot_base import health_payload, honeypot_middleware # type: ignore
from fake_data import ARTICLES

app = Flask(__name__); CORS(app, resources={r"/api/*":{"origins":"*"}}); honeypot_middleware(app)

_RE = re.compile(r'(;|\||&&|\$\(|`|/etc/passwd|/etc/shadow|whoami|id\b|uname|cat\s|ls\s|wget\s|curl\s|nc\s|bash|sh\s)',re.I)
def _txt(v): return v.strip() if isinstance(v,str) else ('' if v is None else str(v).strip())
def _cmdi(t): return bool(_RE.search(str(t or '')))
def _any(fs): return next(((True,str(f)) for f in fs if _cmdi(f)),(False,''))
_FAKE = {'whoami':'www-data','id':'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
         'uname':'Linux meridian-prod 5.15.0-1044-aws #49-Ubuntu SMP x86_64 GNU/Linux',
         '/etc/passwd':'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
         '/etc/shadow':'/etc/shadow: Permission denied','ls':'app.py  models.py  requirements.txt  routes','cat':'# redacted'}
def _out(p):
    for k,v in _FAKE.items():
        if k in p.lower(): return v
    return ''

@app.get('/api/health')
def health(): return jsonify(health_payload(os.environ.get('SERVICE_NAME')))
@app.post('/api/auth/login')
def login():
    d=request.get_json(silent=True) or {}; hit,p=_any([_txt(d.get('username')),_txt(d.get('password'))])
    return (jsonify(message=f'Internal error: {_out(p)}'),500) if hit else (jsonify(message='Invalid credentials.'),401)
@app.get('/api/auth/me')
def me(): return jsonify(message='Unauthorized.'),401
@app.get('/api/articles')
def list_articles():
    cat=request.args.get('category',''); hit,p=_any([cat])
    items=[a for a in ARTICLES if not cat or a['category'].lower()==cat.lower()]
    return (jsonify(message=f'Filter error: {_out(p)}'),500) if hit else jsonify(items=items,total=len(items),page=1,pages=1)
@app.post('/api/articles/search')
def search():
    d=request.get_json(silent=True) or {}; q=_txt(d.get('query')); hit,p=_any([q])
    if hit: return jsonify(message=f'Search error: {_out(p)}'),500
    m=[a for a in ARTICLES if q.lower() in a['title'].lower()]; return jsonify(items=m,total=len(m),page=1,pages=1)
@app.get('/api/articles/<aid>')
def get_article(aid):
    hit,p=_any([aid])
    if hit: return jsonify(message=f'Error: {_out(p)}'),500
    try:
        idx=int(aid)-1
        if 0<=idx<len(ARTICLES): return jsonify({**ARTICLES[idx],'content':'','related':[]})
    except ValueError: pass
    return jsonify(message='Not found.'),404
@app.post('/api/tools/ping')
def ping():
    d=request.get_json(silent=True) or {}; h=_txt(d.get('host')); hit,p=_any([h])
    if hit:
        clean=re.split(r'[;|&`]',h)[0].strip()
        return jsonify(host=h,reachable=True,latency_ms=8.1,output=f'PING {clean}: 3 packets.\n{_out(p)}')
    return jsonify(host=h,reachable=True,latency_ms=11.3,output=f'PING {h}: 3 packets.')
@app.post('/api/tools/preview')
def preview():
    d=request.get_json(silent=True) or {}; c=_txt(d.get('content')); hit,p=_any([c])
    return jsonify(rendered=_out(p),word_count=0,read_time=1) if hit else jsonify(rendered=f'<p>{c}</p>',word_count=len(c.split()),read_time=1)
@app.post('/api/tools/fetch')
def fetch():
    d=request.get_json(silent=True) or {}; u=_txt(d.get('url')); hit,p=_any([u])
    return (jsonify(status_code=200,content=_out(p),content_type='text/plain',size_bytes=256,time_ms=5,final_url=u),200) if hit else jsonify(status_code=200,content_type='text/html',size_bytes=1024,time_ms=78,final_url=u,content='<html>...</html>')
if __name__=='__main__': app.run(host='0.0.0.0',port=5000)
