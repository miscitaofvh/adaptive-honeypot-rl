import os, re, sys; sys.path.insert(0,'/app/shared')
from flask import Flask, request, jsonify
from flask_cors import CORS
from honeypot_base import honeypot_middleware # type: ignore
from fake_data import ARTICLES

app = Flask(__name__); CORS(app, resources={r"/api/*":{"origins":"*"}}); honeypot_middleware(app)

_RE = re.compile(r'(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\})',re.DOTALL)
def _ssti(t): return bool(_RE.search(str(t or '')))
def _any(fs): return next(((True,str(f)) for f in fs if _ssti(f)),(False,''))
def _resp(p):
    a=re.search(r'(\d+)\s*\*\s*(\d+)',p)
    if a: return {"rendered":str(int(a.group(1))*int(a.group(2)))}
    if re.search(r'config|__class__|__mro__',p,re.I): return {"rendered":"<Config {'ENV':'production','DEBUG':False,'SECRET_KEY':'...','SQLALCHEMY_DATABASE_URI':'sqlite:////data/meridian.db'}>"}
    return {"rendered":re.sub(r'[\{\}\$\#\[\]%]','',p).strip() or 'None'}

@app.get('/api/health')
def health(): return jsonify(status='ok',service=os.environ.get('SERVICE_NAME'))
@app.post('/api/auth/login')
def login():
    d=request.get_json(silent=True) or {}; hit,p=_any([d.get('username',''),d.get('password','')])
    return (jsonify(_resp(p)),200) if hit else (jsonify(message='Invalid credentials.'),401)
@app.get('/api/auth/me')
def me(): return jsonify(message='Unauthorized.'),401
@app.get('/api/articles')
def list_articles():
    cat=request.args.get('category',''); hit,p=_any([cat])
    return (jsonify(_resp(p)),200) if hit else jsonify(articles=ARTICLES,total=len(ARTICLES),page=1,pages=1)
@app.post('/api/articles/search')
def search():
    d=request.get_json(silent=True) or {}; q=d.get('query',''); hit,p=_any([q])
    if hit: return jsonify(_resp(p)),200
    m=[a for a in ARTICLES if q.lower() in a['title'].lower()]; return jsonify(articles=m,total=len(m),page=1,pages=1)
@app.get('/api/articles/<aid>')
def get_article(aid):
    hit,p=_any([aid])
    if hit: return jsonify(_resp(p)),200
    try:
        idx=int(aid)-1
        if 0<=idx<len(ARTICLES): return jsonify({**ARTICLES[idx],'content':'','related':[]})
    except ValueError: pass
    return jsonify(message='Not found.'),404
@app.post('/api/tools/preview')
def preview():
    d=request.get_json(silent=True) or {}; c=d.get('content',''); hit,p=_any([c])
    if hit: r=_resp(p); return jsonify(rendered=r.get('rendered',''),word_count=len(c.split()),read_time=1)
    return jsonify(rendered=f'<p>{c}</p>',word_count=len(c.split()),read_time=1)
@app.post('/api/tools/ping')
def ping():
    d=request.get_json(silent=True) or {}; h=d.get('host',''); hit,p=_any([h])
    return jsonify(output=_resp(p).get('rendered',''),reachable=True,latency_ms=0) if hit else jsonify(host=h,reachable=True,latency_ms=14.2,output=f'PING {h}: 3 packets.')
@app.post('/api/tools/fetch')
def fetch():
    d=request.get_json(silent=True) or {}; u=d.get('url',''); hit,p=_any([u])
    return (jsonify(status_code=200,content=_resp(p).get('rendered',''),content_type='text/html',size_bytes=512,time_ms=55),200) if hit else jsonify(status_code=200,content_type='text/html',size_bytes=1024,time_ms=91,content='<html>...</html>')
if __name__=='__main__': app.run(host='0.0.0.0',port=5002)
