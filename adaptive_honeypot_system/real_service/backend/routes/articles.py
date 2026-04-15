from flask import Blueprint, request, jsonify
from models import Article, db

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

        title = (data.get('title') or '').strip()
        summary = (data.get('summary') or '').strip()
        content = (data.get('content') or '').strip()

        if not title:
            return jsonify(message='title is required'), 400
        if not summary:
            return jsonify(message='summary is required'), 400
        if not content:
            return jsonify(message='content is required'), 400

        tags = data.get('tags', '')
        if isinstance(tags, list):
            tags = ','.join(str(tag).strip() for tag in tags if str(tag).strip())

        try:
            read_time = int(data.get('read_time', 5))
        except (TypeError, ValueError):
            read_time = 5

        read_time = max(1, min(read_time, 120))
        
        article = Article(
            title=title,
            summary=summary,
            content=content,
            category=data.get('category','General'),
            tags=tags,
            read_time=read_time,
            author_id=user_id
        )
        db.session.add(article)
        db.session.commit()
        return jsonify(article.to_dict(include_content=True)), 201
    
    return _create()
