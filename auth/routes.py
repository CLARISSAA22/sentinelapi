from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash
from auth.services import authenticate_user, register_user, get_current_user, log_audit_event, login_required
from auth.security import generate_csrf_token, hash_password
from database.database import get_db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET' and get_current_user():
        return redirect(url_for('dashboard_page'))
        
    error = None
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json() or {}
            identifier = data.get('username', '')
            password = data.get('password', '')
        else:
            identifier = request.form.get('username', '')
            password = request.form.get('password', '')
            
        user, err_msg = authenticate_user(identifier, password)
        if user:
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['csrf_token'] = generate_csrf_token()
            
            if request.is_json:
                return jsonify({'success': True, 'redirect': url_for('dashboard_page'), 'user': user.to_dict()})
            next_url = request.args.get('next') or url_for('dashboard_page')
            return redirect(next_url)
        else:
            error = err_msg
            if request.is_json:
                return jsonify({'error': error}), 401
                
    return render_template('login.html', error=error)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'GET' and get_current_user():
        return redirect(url_for('dashboard_page'))
        
    error = None
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json() or {}
            username = data.get('username', '')
            email = data.get('email', '')
            password = data.get('password', '')
            role = data.get('role', 'Security Analyst')
        else:
            username = request.form.get('username', '')
            email = request.form.get('email', '')
            password = request.form.get('password', '')
            role = request.form.get('role', 'Security Analyst')
            
        user, err_msg = register_user(username, email, password, role)
        if user:
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['csrf_token'] = generate_csrf_token()
            
            if request.is_json:
                return jsonify({'success': True, 'redirect': url_for('dashboard_page'), 'user': user.to_dict()})
            return redirect(url_for('dashboard_page'))
        else:
            error = err_msg
            if request.is_json:
                return jsonify({'error': error}), 400
                
    return render_template('register.html', error=error)

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    user = get_current_user()
    if user:
        log_audit_event('LOGOUT', 'User', user.id, {'username': user.username})
    session.clear()
    if request.is_json:
        return jsonify({'success': True, 'redirect': url_for('landing_page')})
    return redirect(url_for('landing_page'))

@auth_bp.route('/api/auth/me', methods=['GET'])
def get_me():
    user = get_current_user()
    if not user:
        return jsonify({'authenticated': False, 'user': None}), 401
    return jsonify({
        'authenticated': True,
        'user': user.to_dict(),
        'csrf_token': session.get('csrf_token')
    })

@auth_bp.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json() or {}
    current_pwd = data.get('current_password', '')
    new_pwd = data.get('new_password', '')
    
    if len(new_pwd) < 8:
        return jsonify({'error': 'New password must be at least 8 characters long.'}), 400
        
    user = get_current_user()
    from auth.security import verify_password
    if not verify_password(current_pwd, user.password_hash):
        return jsonify({'error': 'Current password is incorrect.'}), 400
        
    db = get_db()
    user.password_hash = hash_password(new_pwd)
    db.commit()
    
    log_audit_event('PASSWORD_CHANGED', 'User', user.id)
    return jsonify({'success': True, 'message': 'Password updated successfully.'})
