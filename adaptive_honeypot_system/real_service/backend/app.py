import os
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from sqlalchemy import inspect
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
    app.config['JSON_SORT_KEYS'] = False
    
    CORS(app, resources={r"/api/*":{"origins":"*"}})
    db.init_app(app)
    JWTManager(app)
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(articles_bp, url_prefix='/api/articles')
    app.register_blueprint(tools_bp, url_prefix='/api/tools')

    @app.get('/api/health')
    def health():
        return {'status':'ok','service':os.environ.get('SERVICE_NAME','real-backend')}

    with app.app_context():
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()
        if 'users' not in existing_tables:
            db.create_all()
        _seed()
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
    ]
    for d in ARTICLES: db.session.add(Article(**d))
    db.session.commit()

app = create_app()
if __name__ == '__main__': app.run(host='0.0.0.0', port=5000, debug=False)
