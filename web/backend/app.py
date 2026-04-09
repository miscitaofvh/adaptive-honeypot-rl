import os
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from models import db, User, Article
from routes.auth import auth_bp
from routes.articles import articles_bp
from routes.tools import tools_bp

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY','dev-secret')
    app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL','sqlite:////data/meridian.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    CORS(app, resources={r"/api/*":{"origins":"*"}}); db.init_app(app); JWTManager(app)
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(articles_bp, url_prefix='/api/articles')
    app.register_blueprint(tools_bp, url_prefix='/api/tools')

    @app.get('/api/health')
    def health(): return {'status':'ok','service':os.environ.get('SERVICE_NAME','backend')}

    with app.app_context():
        db.create_all(); _seed()
    return app

def _seed():
    if User.query.first(): return
    from werkzeug.security import generate_password_hash
    admin = User(username='admin', password_hash=generate_password_hash('admin123'), bio='Editor-in-chief at Meridian.')
    alice = User(username='alice', password_hash=generate_password_hash('alice123'), bio='Software engineer.')
    db.session.add_all([admin, alice]); db.session.flush()
    ARTICLES = [
        {'title':'Understanding TCP Congestion Control','summary':'A practical walkthrough of how TCP manages network congestion — from slow start to CUBIC.','category':'Infrastructure','tags':'tcp,networking,performance','read_time':8,'author_id':admin.id,'content':'''## What is Congestion Control?\n\nTCP congestion control prevents any single connection from flooding the network. Without it, a single misbehaving sender could cause congestion collapse.\n\n## The Four Algorithms\n\n**Slow Start** begins each connection by doubling the congestion window every RTT.\n\n**Congestion Avoidance** grows the window by +1 MSS per RTT after the threshold.\n\n**Fast Retransmit** treats three duplicate ACKs as loss and retransmits immediately.\n\n**Fast Recovery** halves the window on triple-duplicate-ACK loss rather than restarting slow start.\n\n## CUBIC\n\nLinux defaults to CUBIC, which replaces linear growth with a cubic function of time:\n\n```\nW(t) = C(t - K)³ + Wmax\n```\n\n> BBR estimates bottleneck bandwidth directly, making it resilient to shallow buffers and random loss.'''},
        {'title':'PostgreSQL Index Types: When to Use What','summary':'B-tree, Hash, GIN, BRIN — each index type solves a different class of query.','category':'Performance','tags':'postgres,database,indexing','read_time':6,'author_id':alice.id,'content':'''## B-tree (Default)\n\nB-tree supports equality, range queries, and sorting. If in doubt, start here.\n\n## Hash\n\nHash indexes only support equality (`=`) but are faster for pure lookup workloads.\n\n## GIN\n\nGIN excels at multi-valued columns: full-text search, arrays, JSONB containment.\n\n```sql\nCREATE INDEX idx_articles_tags ON articles USING GIN(to_tsvector(\'english\', content));\n```\n\n## BRIN\n\nBRIN stores min/max per page range. Tiny footprint, ideal for append-only time-series tables.\n\n> Indexes are not free. Audit unused indexes with `pg_stat_user_indexes`.'''},
        {'title':'Container Networking from First Principles','summary':'How Docker\'s bridge networking actually works — veth pairs, network namespaces, and iptables NAT.','category':'Infrastructure','tags':'docker,networking,linux','read_time':10,'author_id':admin.id,'content':'''## Network Namespaces\n\nLinux network namespaces give each container its own isolated network stack.\n\n```bash\nip netns add demo\nip netns exec demo ip link list\n```\n\n## veth Pairs\n\nVirtual Ethernet pairs connect two namespaces. Whatever enters one end exits the other.\n\n## The docker0 Bridge\n\n`docker0` is a virtual L2 switch. All container-side veth peers plug into it.\n\n## iptables NAT\n\nDocker adds a MASQUERADE rule so outbound container traffic appears to originate from the host IP.\n\n> Prefer user-defined bridge networks over the default docker0 in production.'''},
        {'title':'Designing for Observability: Structured Logging','summary':'Logs are your primary debugging interface in production. These patterns make them queryable and actionable.','category':'Architecture','tags':'observability,logging,architecture','read_time':7,'author_id':alice.id,'content':'''## Why Structured Logging\n\nFree-form text logs are for humans. Structured logs — typically JSON — are for machines.\n\n```json\n{\n  "ts": "2024-03-15T09:42:01Z",\n  "level": "info",\n  "service": "articles-api",\n  "trace_id": "4bf92f3577b34da6",\n  "msg": "article fetched",\n  "duration_ms": 12\n}\n```\n\n## Log Levels as Semantic Contracts\n\n- **ERROR**: A human needs to look at this soon.\n- **WARN**: Degraded but still serving.\n- **INFO**: Normal operational events. Keep sparse.\n- **DEBUG**: Off in production.\n\n> The goal of observability is to answer arbitrary questions about system behavior without deploying new code.'''},
        {'title':'Consistent Hashing: The Algorithm Behind Distributed Caches','summary':'How consistent hashing minimises cache invalidation when nodes join or leave a cluster.','category':'Architecture','tags':'distributed-systems,caching,algorithms','read_time':9,'author_id':admin.id,'content':'''## The Naive Approach and Its Problem\n\nSimple cache sharding is `node = hash(key) % N`. When N changes, nearly every key remaps — a cache stampede.\n\n## The Ring\n\nConsistent hashing places both nodes and keys on a virtual ring. A key maps to the first node clockwise from its hash position.\n\n## Virtual Nodes\n\nA single physical node maps to many points on the ring:\n\n```python\nfor i in range(vnodes_per_server):\n    point = hash(f"{server_id}:{i}") % RING_SIZE\n    ring[point] = server_id\n```\n\n> Virtual nodes are the implementation detail that makes consistent hashing practical for small cluster sizes.'''},
        {'title':'Git Internals: What Happens on git commit','summary':'Blobs, trees, commits, and refs — a tour of Git\'s content-addressable storage model.','category':'Development','tags':'git,vcs,internals','read_time':7,'author_id':alice.id,'content':'''## Content-Addressable Storage\n\nGit stores all content in `.git/objects` keyed by SHA-1 of the content itself.\n\n## Blobs\n\nA blob stores raw file content — no filename, no permissions. Identical files share one blob.\n\n## Trees\n\nA tree maps names and modes to blob or tree SHA-1s.\n\n## Commits\n\nA commit stores: root tree SHA-1, parent SHA-1s, author, committer, timestamp, and message.\n\n## What git commit Does\n\n1. Hashes and writes a blob for each modified file.\n2. Recursively writes tree objects bottom-up.\n3. Creates a commit object referencing the root tree.\n4. Updates the current branch ref.\n\n> Every commit is an immutable snapshot, not a diff. Git computes diffs on demand by comparing blobs.'''},
    ]
    for d in ARTICLES: db.session.add(Article(**d))
    db.session.commit()

app = create_app()
if __name__ == '__main__': app.run(host='0.0.0.0', port=5000, debug=False)
