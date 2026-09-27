from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, current_app
from backend.auth import current_user, login_user, logout_user, require_auth, require_role
from backend.extensions import db
from backend.models import User

auth_bp=Blueprint('auth',__name__)

def _safe_user(u): return {'id':u.id,'username':u.username,'role':u.role,'active':u.active}

@auth_bp.post('/api/auth/login')
def login():
    data=request.get_json(silent=True) or {}; username=str(data.get('username') or '').strip(); password=str(data.get('password') or '')
    user=User.query.filter_by(username=username).one_or_none()
    if not user or not user.active or not user.check_password(password): return jsonify({'success':False,'error':'Invalid username or password'}),401
    user.last_login_at=datetime.now(timezone.utc); db.session.commit(); login_user(user)
    return jsonify({'success':True,'user':_safe_user(user)})

@auth_bp.post('/api/auth/logout')
def logout(): logout_user(); return jsonify({'success':True})

@auth_bp.get('/api/auth/me')
def me():
    u=current_user()
    if not u: return jsonify({'success':False,'authenticated':False}),401
    return jsonify({'success':True,'authenticated':True,'user':_safe_user(u)})

@auth_bp.get('/api/users')
@require_role('admin')
def users(): return jsonify({'success':True,'users':[_safe_user(u) for u in User.query.order_by(User.username).all()]})

@auth_bp.post('/api/users')
@require_role('admin')
def create_user():
    data=request.get_json(silent=True) or {}; username=str(data.get('username') or '').strip(); password=str(data.get('password') or ''); role=str(data.get('role') or 'analyst').strip().lower()
    if not username or len(password)<8 or role not in {'admin','analyst'}: return jsonify({'success':False,'error':'username, password (8+ chars), and role are required'}),400
    if User.query.filter_by(username=username).first(): return jsonify({'success':False,'error':'Username already exists'}),409
    u=User(username=username,role=role); u.set_password(password); db.session.add(u); db.session.commit(); return jsonify({'success':True,'user':_safe_user(u)}),201
