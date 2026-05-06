from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import or_
from models import Article, db

articles_bp = Blueprint('articles', __name__)


def _bounded_int(value, default, minimum=1, maximum=50):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, minimum), maximum)


def _text(value, default=''):
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()

@articles_bp.get('')
def list_articles():
    page = _bounded_int(request.args.get('page'), 1, 1, 10_000)
    limit = _bounded_int(request.args.get('limit'), 10, 1, 50)
    category = (request.args.get('category', '', type=str) or '').strip()

    query = Article.query.order_by(Article.created_at.desc())
    if category:
        query = query.filter_by(category=category)

    items = query.paginate(page=page, per_page=limit, error_out=False)
    return jsonify(
        total=items.total,
        page=items.page,
        pages=max(1, items.pages),
        items=[a.to_dict() for a in items.items]
    )

@articles_bp.post('/search')
def search_articles():
    data = request.get_json(silent=True) or {}
    query_text = _text(data.get('query'))
    try:
        page = max(1, int(data.get('page') or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        limit = min(max(1, int(data.get('limit') or 10)), 50)
    except (TypeError, ValueError):
        limit = 10

    query = Article.query.order_by(Article.created_at.desc())
    if query_text:
        pattern = f'%{query_text}%'
        query = query.filter(
            or_(
                Article.title.ilike(pattern),
                Article.summary.ilike(pattern),
                Article.content.ilike(pattern),
                Article.category.ilike(pattern),
                Article.tags.ilike(pattern),
            )
        )

    items = query.paginate(page=page, per_page=limit, error_out=False)
    return jsonify(
        total=items.total,
        page=page,
        pages=max(1, items.pages),
        items=[a.to_dict() for a in items.items],
    )

@articles_bp.get('/<int:article_id>')
def get_article(article_id):
    article = Article.query.get(article_id)
    if not article:
        return jsonify(message='Article not found'), 404
    return jsonify(article.to_dict(include_content=True))

@articles_bp.post('')
@jwt_required()
def create_article():
    try:
        user_id = int(get_jwt_identity())
    except (TypeError, ValueError):
        return jsonify(message='Invalid token subject'), 401

    data = request.get_json(silent=True) or {}

    title = _text(data.get('title'))
    summary = _text(data.get('summary'))
    content = _text(data.get('content'))

    if not title:
        return jsonify(message='title is required'), 400
    if not summary:
        return jsonify(message='summary is required'), 400
    if not content:
        return jsonify(message='content is required'), 400

    tags = data.get('tags', '')
    if isinstance(tags, list):
        tags = ','.join(str(tag).strip() for tag in tags if str(tag).strip())
    elif tags is None:
        tags = ''
    else:
        tags = str(tags).strip()

    try:
        read_time = int(data.get('read_time', 5))
    except (TypeError, ValueError):
        read_time = 5

    read_time = max(1, min(read_time, 120))
    category = _text(data.get('category'), 'General') or 'General'

    article = Article(
        title=title,
        summary=summary,
        content=content,
        category=category,
        tags=tags,
        read_time=read_time,
        author_id=user_id
    )
    db.session.add(article)
    db.session.commit()
    return jsonify(article.to_dict(include_content=True)), 201
