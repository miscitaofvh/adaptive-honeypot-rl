from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash
from models import User
auth_bp = Blueprint('auth', __name__)

@auth_bp.post('/login')
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip(); password = data.get('password') or ''
    if not username or not password: return jsonify(message='Username and password are required.'), 400
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password): return jsonify(message='Invalid credentials.'), 401
    return jsonify(token=create_access_token(identity=str(user.id)), user=user.to_dict())

@auth_bp.get('/me')
@jwt_required()
def me():
    return jsonify(User.query.get_or_404(int(get_jwt_identity())).to_dict())
