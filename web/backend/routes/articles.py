from flask import Blueprint, request, jsonify
from models import db, Article
articles_bp = Blueprint('articles', __name__)
PAGE_SIZE = 10

@articles_bp.get('')
def list_articles():
    page = max(1, request.args.get('page',1,type=int)); category = request.args.get('category','').strip()
    q = Article.query
    if category: q = q.filter(Article.category.ilike(category))
    q = q.order_by(Article.created_at.desc())
    total = q.count(); articles = q.offset((page-1)*PAGE_SIZE).limit(PAGE_SIZE).all()
    return jsonify(articles=[a.to_dict() for a in articles], total=total, page=page, pages=(total+PAGE_SIZE-1)//PAGE_SIZE)

@articles_bp.post('/search')
def search_articles():
    data = request.get_json(silent=True) or {}; query = (data.get('query') or '').strip(); page = max(1,data.get('page',1))
    if not query: return jsonify(articles=[], total=0, page=1, pages=0)
    like = f'%{query}%'
    q = Article.query.filter(db.or_(Article.title.ilike(like),Article.summary.ilike(like),Article.content.ilike(like),Article.tags.ilike(like))).order_by(Article.created_at.desc())
    total = q.count(); articles = q.offset((page-1)*PAGE_SIZE).limit(PAGE_SIZE).all()
    return jsonify(articles=[a.to_dict() for a in articles], total=total, page=page, pages=(total+PAGE_SIZE-1)//PAGE_SIZE)

@articles_bp.get('/<int:article_id>')
def get_article(article_id):
    article = Article.query.get_or_404(article_id)
    related = Article.query.filter(Article.category==article.category,Article.id!=article.id).order_by(Article.created_at.desc()).limit(3).all()
    return jsonify(article.to_dict(include_content=True, related=related))
