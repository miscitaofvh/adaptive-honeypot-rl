from flask import Blueprint

auth_bp = Blueprint('auth', __name__)


def _text(value):
    return value.strip() if isinstance(value, str) else ''

@auth_bp.post('/login')
def login():
    from flask import request, jsonify
    from werkzeug.security import check_password_hash
    from models import User
    from flask_jwt_extended import create_access_token
    
    data = request.get_json(silent=True) or {}
    username = _text(data.get('username'))
    password = _text(data.get('password'))
    
    if not username or not password:
        return jsonify(message='Username and password required'), 400
    
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify(message='Invalid credentials'), 401
    
    token = create_access_token(identity=str(user.id))
    return jsonify(access_token=token, user=user.to_dict())

@auth_bp.post('/register')
def register():
    from flask import request, jsonify
    from werkzeug.security import generate_password_hash
    from models import User, db
    
    data = request.get_json(silent=True) or {}
    username = _text(data.get('username'))
    password = _text(data.get('password'))
    
    if not username or not password:
        return jsonify(message='Username and password required'), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify(message='User already exists'), 409
    
    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    
    return jsonify(message='User created',user=user.to_dict()), 201
