import os, re, sys; sys.path.insert(0,'/app/shared')
import bleach
import markdown
from flask import Flask, request, jsonify
from flask_cors import CORS
from honeypot_base import health_payload, honeypot_middleware # type: ignore
from fake_data import ARTICLES

app = Flask(__name__); CORS(app, resources={r"/api/*":{"origins":"*"}}); honeypot_middleware(app)

_RE = re.compile(r'(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\})',re.DOTALL)
ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + ['h1','h2','h3','h4','h5','h6','p','pre','code','blockquote','ul','ol','li','hr','br','table','thead','tbody','tr','th','td']
ALLOWED_ATTRS = {**bleach.sanitizer.ALLOWED_ATTRIBUTES, 'code':['class'], 'pre':['class']}

def _txt(v): return v.strip() if isinstance(v,str) else ('' if v is None else str(v).strip())
def _ssti(t): return bool(_RE.search(str(t or '')))
def _any(fs): return next(((True,str(f)) for f in fs if _ssti(f)),(False,''))

def _eval_template_token(token):
    inner=token.strip()
    if inner.startswith('{{') and inner.endswith('}}'): inner=inner[2:-2].strip()
    elif inner.startswith('{%') and inner.endswith('%}'): inner=inner[2:-2].strip()
    elif inner.startswith('${') and inner.endswith('}'): inner=inner[2:-1].strip()
    elif inner.startswith('#{') and inner.endswith('}'): inner=inner[2:-1].strip()
    if re.search(r'config|__class__|__mro__|__subclasses__',inner,re.I):
        return "<Config {'ENV':'production','DEBUG':False,'SECRET_KEY':'...','SQLALCHEMY_DATABASE_URI':'sqlite:////data/meridian.db'}>"
    m=re.fullmatch(r'(\d+)\s*([*+\-/])\s*(\d+)',inner)
    if m:
        left=int(m.group(1)); op=m.group(2); right=int(m.group(3))
        if op=='*': return str(left*right)
        if op=='+': return str(left+right)
        if op=='-': return str(left-right)
        if op=='/' and right: return str(left/right).rstrip('0').rstrip('.')
    cleaned=re.sub(r'[\{\}\$\#\[\]%]','',inner).strip()
    return cleaned or 'None'

def _render_markdown(content):
    evaluated=_RE.sub(lambda m: _eval_template_token(m.group(0)),content)
    rendered=markdown.markdown(evaluated,extensions=['fenced_code','tables','nl2br'])
    return bleach.clean(rendered,tags=ALLOWED_TAGS,attributes=ALLOWED_ATTRS)

def _resp(p):
    a=re.search(r'(\d+)\s*\*\s*(\d+)',p)
    if a: return {"rendered":str(int(a.group(1))*int(a.group(2)))}
    if re.search(r'config|__class__|__mro__',p,re.I): return {"rendered":"<Config {'ENV':'production','DEBUG':False,'SECRET_KEY':'...','SQLALCHEMY_DATABASE_URI':'sqlite:////data/meridian.db'}>"}
    return {"rendered":re.sub(r'[\{\}\$\#\[\]%]','',p).strip() or 'None'}

@app.get('/api/health')
def health(): return jsonify(health_payload(os.environ.get('SERVICE_NAME')))
@app.post('/api/auth/login')
def login():
    d=request.get_json(silent=True) or {}; hit,p=_any([_txt(d.get('username')),_txt(d.get('password'))])
    return (jsonify(_resp(p)),200) if hit else (jsonify(message='Invalid credentials.'),401)
@app.get('/api/auth/me')
def me(): return jsonify(message='Unauthorized.'),401
@app.get('/api/articles')
def list_articles():
    cat=request.args.get('category',''); hit,p=_any([cat])
    items=[a for a in ARTICLES if not cat or a['category'].lower()==cat.lower()]
    return (jsonify(_resp(p)),200) if hit else jsonify(items=items,total=len(items),page=1,pages=1)
@app.post('/api/articles/search')
def search():
    d=request.get_json(silent=True) or {}; q=_txt(d.get('query')); hit,p=_any([q])
    if hit: return jsonify(_resp(p)),200
    m=[a for a in ARTICLES if q.lower() in a['title'].lower()]; return jsonify(items=m,total=len(m),page=1,pages=1)
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
    d=request.get_json(silent=True) or {}; c=_txt(d.get('content'))[:32000]
    return jsonify(rendered=_render_markdown(c),word_count=len(re.findall(r'\w+',c)),read_time=max(1,round(len(re.findall(r'\w+',c))/200)))
@app.post('/api/tools/ping')
def ping():
    d=request.get_json(silent=True) or {}; h=_txt(d.get('host')); hit,p=_any([h])
    return jsonify(host=h,output=_resp(p).get('rendered',''),reachable=True,latency_ms=0) if hit else jsonify(host=h,reachable=True,latency_ms=14.2,output=f'PING {h}: 3 packets.')
@app.post('/api/tools/fetch')
def fetch():
    d=request.get_json(silent=True) or {}; u=_txt(d.get('url')); hit,p=_any([u])
    return (jsonify(status_code=200,content=_resp(p).get('rendered',''),content_type='text/html',size_bytes=512,time_ms=55,final_url=u),200) if hit else jsonify(status_code=200,content_type='text/html',size_bytes=1024,time_ms=91,final_url=u,content='<html>...</html>')
if __name__=='__main__': app.run(host='0.0.0.0',port=5000)
