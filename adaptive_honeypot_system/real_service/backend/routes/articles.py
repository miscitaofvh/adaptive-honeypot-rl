from flask import Blueprint, request, jsonify
from models import Article, User, db

articles_bp = Blueprint('articles', __name__)

@articles_bp.get('')
def list_articles():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    category = request.args.get('category', '', type=str)
    
    query = Article.query.order_by(Article.created_at.desc())
    if category:
        query = query.filter_by(category=category)
    
    items = query.paginate(page=page, per_page=limit)
    return jsonify(
        total=items.total,
        page=page,
        pages=items.pages,
        items=[a.to_dict() for a in items.items]
    )

@articles_bp.get('/<int:article_id>')
def get_article(article_id):
    article = Article.query.get(article_id)
    if not article:
        return jsonify(message='Article not found'), 404
    return jsonify(article.to_dict(include_content=True))

@articles_bp.post('')
def create_article():
    from flask_jwt_extended import jwt_required, get_jwt_identity
    
    @jwt_required()
    def _create():
        user_id = get_jwt_identity()
        data = request.get_json(silent=True) or {}
        
        article = Article(
            title=data.get('title','').strip(),
            summary=data.get('summary','').strip(),
            content=data.get('content','').strip(),
            category=data.get('category','General'),
            tags=data.get('tags',''),
            read_time=data.get('read_time',5),
            author_id=user_id
        )
        db.session.add(article)
        db.session.commit()
        return jsonify(article.to_dict(include_content=True)), 201
    
    return _create()
