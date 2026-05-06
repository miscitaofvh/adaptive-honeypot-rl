import os, re, sys; sys.path.insert(0,'/app/shared')
from flask import Flask, request, jsonify
from flask_cors import CORS
from honeypot_base import health_payload, honeypot_middleware # type: ignore
from fake_data import ARTICLES

app = Flask(__name__); CORS(app, resources={r"/api/*":{"origins":"*"}}); honeypot_middleware(app)

_RE = re.compile(r'(localhost|127\.0\.0\.|0\.0\.0\.0|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.|file://|dict://|gopher://|/etc/|/proc/)',re.I)
def _txt(v): return v.strip() if isinstance(v,str) else ('' if v is None else str(v).strip())
def _ssrf(t): return bool(_RE.search(str(t or '')))
def _any(fs): return next(((True,str(f)) for f in fs if _ssrf(f)),(False,''))
_RESP = {
    '169.254.169.254': {'content':'{"instanceId":"i-0a1b2c3d4e5f67890","instanceType":"t3.medium","region":"ap-southeast-1","privateIp":"10.0.1.42","iamInfo":{"InstanceProfileArn":"arn:aws:iam::123456789012:instance-profile/meridian-prod"}}','content_type':'application/json','status_code':200},
    'localhost':   {'content':'{"status":"ok","service":"internal-metrics","uptime":1209600}','content_type':'application/json','status_code':200},
    '127.0.0.1':  {'content':'{"status":"ok","service":"internal-metrics","uptime":1209600}','content_type':'application/json','status_code':200},
    '10.':        {'content':'{"db":"meridian","version":"14.5","tables":["users","articles","sessions"]}','content_type':'application/json','status_code':200},
    'file://':    {'content':'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin','content_type':'text/plain','status_code':200},
    'default':    {'content':'{"error":"connection refused"}','content_type':'application/json','status_code':502},
}
def _fake(url):
    for k,v in _RESP.items():
        if k in url: return v
    return _RESP['default']

@app.get('/api/health')
def health(): return jsonify(health_payload(os.environ.get('SERVICE_NAME')))
@app.post('/api/auth/login')
def login():
    d=request.get_json(silent=True) or {}; hit,p=_any([_txt(d.get('username')),_txt(d.get('password'))])
    return (jsonify(message=_fake(p)['content']),500) if hit else (jsonify(message='Invalid credentials.'),401)
@app.get('/api/auth/me')
def me(): return jsonify(message='Unauthorized.'),401
@app.get('/api/articles')
def list_articles():
    cat=request.args.get('category','')
    items=[a for a in ARTICLES if not cat or a['category'].lower()==cat.lower()]
    return jsonify(items=items,total=len(items),page=1,pages=1)
@app.post('/api/articles/search')
def search():
    d=request.get_json(silent=True) or {}; q=_txt(d.get('query'))
    m=[a for a in ARTICLES if q.lower() in a['title'].lower()]; return jsonify(items=m,total=len(m),page=1,pages=1)
@app.get('/api/articles/<aid>')
def get_article(aid):
    try:
        idx=int(aid)-1
        if 0<=idx<len(ARTICLES): return jsonify({**ARTICLES[idx],'content':'','related':[]})
    except ValueError: pass
    return jsonify(message='Not found.'),404
@app.post('/api/tools/fetch')
def fetch():
    d=request.get_json(silent=True) or {}; u=_txt(d.get('url')); hit,p=_any([u])
    if hit: r=_fake(p); return jsonify(status_code=r['status_code'],content_type=r['content_type'],size_bytes=len(r['content']),time_ms=4,final_url=u,content=r['content'])
    return jsonify(status_code=200,content_type='text/html',size_bytes=2048,time_ms=112,final_url=u,content='<html>...</html>')
@app.post('/api/tools/ping')
def ping():
    d=request.get_json(silent=True) or {}; h=_txt(d.get('host')); hit,p=_any([h])
    return jsonify(host=h,reachable=True,latency_ms=0.3,output=_fake(p)['content']) if hit else jsonify(host=h,reachable=True,latency_ms=9.7,output=f'PING {h}: 3 packets.')
@app.post('/api/tools/preview')
def preview():
    d=request.get_json(silent=True) or {}; c=_txt(d.get('content'))
    return jsonify(rendered=f'<p>{c}</p>',word_count=len(c.split()),read_time=1)
if __name__=='__main__': app.run(host='0.0.0.0',port=5000)
