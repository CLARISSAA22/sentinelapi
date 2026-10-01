import json
from functools import wraps
from flask import session, request, redirect, url_for, jsonify, current_app
from database.database import get_db
from database.models import User, AuditLog
from auth.security import hash_password, verify_password

# Role hierarchy: Owner (full) > Administrator (manage team, settings, APIs, scans) > Security Analyst (run scans, findings, reports) > Viewer (read-only)
ROLE_PERMISSIONS = {
    'Owner': {'all', 'admin', 'manage_users', 'manage_apis', 'run_scans', 'modify_findings', 'view_reports', 'view_all'},
    'Administrator': {'admin', 'manage_users', 'manage_apis', 'run_scans', 'modify_findings', 'view_reports', 'view_all'},
    'Security Analyst': {'manage_apis', 'run_scans', 'modify_findings', 'view_reports', 'view_all'},
    'Viewer': {'view_all', 'view_reports'}
}

def get_current_user():
    """Retrieve currently authenticated user from session or None."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    db = get_db()
    return db.query(User).filter_by(id=user_id).first()

def login_required(f):
    """Enforce login requirement on routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required. Please login.'}), 401
            return redirect(url_for('auth.login_page', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    """Enforce role based access control."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'error': 'Authentication required.'}), 401
                return redirect(url_for('auth.login_page'))
            
            if user.role not in allowed_roles:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'error': f'Forbidden: Role {user.role} is not permitted to perform this action.'}), 403
                return render_unauthorized_error()
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def render_unauthorized_error():
    from flask import render_template
    return render_template('base.html', error="403 Forbidden: Insufficient Permissions"), 403

def log_audit_event(action: str, target_type: str = None, target_id: str = None, details: dict = None):
    """Record an audit log entry for security traceability."""
    try:
        db = get_db()
        user = get_current_user()
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr) if request else '127.0.0.1'
        
        audit_entry = AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else 'System/Anonymous',
            action=action,
            target_type=target_type,
            target_id=target_id,
            details_json=json.dumps(details or {}),
            ip_address=client_ip
        )
        db.add(audit_entry)
        db.commit()
    except Exception as e:
        # Avoid crashing app if audit log write encounters issue
        print(f"[AuditLog Error] {e}")

from sqlalchemy import func, or_

def register_user(username: str, email: str, password: str, role: str = 'Security Analyst'):
    """Register a new user account with validation."""
    db = get_db()
    
    # Input validation
    username = username.strip()
    email = email.strip().lower()
    
    if len(username) < 3 or len(username) > 50:
        return None, "Username must be between 3 and 50 characters."
    if '@' not in email or '.' not in email:
        return None, "Invalid email address format."
    if len(password) < 8:
        return None, "Password must be at least 8 characters long."
    
    # Check if this is the very first user in the system -> make them Owner automatically
    user_count = db.query(User).count()
    if user_count == 0:
        role = 'Owner'
    elif role not in ROLE_PERMISSIONS:
        role = 'Security Analyst'

    # Check collision case-insensitively
    if db.query(User).filter(
        or_(
            func.lower(User.username) == username.lower(),
            func.lower(User.email) == email.lower()
        )
    ).first():
        return None, "Username or email already registered."
    
    pwd_hash = hash_password(password)
    new_user = User(
        username=username,
        email=email,
        password_hash=pwd_hash,
        role=role
    )
    db.add(new_user)
    db.commit()
    
    log_audit_event('USER_REGISTERED', 'User', new_user.id, {'username': username, 'role': role})
    return new_user, None

def authenticate_user(username_or_email: str, password: str):
    """Authenticate user credentials supporting either username or email."""
    db = get_db()
    identifier = (username_or_email or '').strip()
    if not identifier:
        return None, "Invalid username/email or password."
        
    user = db.query(User).filter(
        or_(
            func.lower(User.username) == identifier.lower(),
            func.lower(User.email) == identifier.lower()
        )
    ).first()
    
    if not user:
        return None, "Invalid username/email or password."
    
    if not verify_password(password, user.password_hash):
        log_audit_event('LOGIN_FAILED', 'User', user.id, {'identifier': identifier})
        return None, "Invalid username/email or password."
    
    log_audit_event('LOGIN_SUCCESS', 'User', user.id, {'username': user.username})
    return user, None
