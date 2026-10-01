import json
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, jsonify
from auth.services import login_required, role_required, get_current_user, log_audit_event
from database.database import get_db
from database.models import IntegrationConfig, AuditLog, User

settings_bp = Blueprint('settings', __name__)

DEFAULT_SERVICES = ['jira', 'slack', 'pagerduty']

@settings_bp.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html', active_page='settings')

@settings_bp.route('/api/integrations/list', methods=['GET'])
@login_required
def list_integrations():
    db = get_db()
    configs = {ic.service_name: ic for ic in db.query(IntegrationConfig).all()}
    
    result = []
    for s_name in DEFAULT_SERVICES:
        if s_name in configs:
            ic = configs[s_name]
            result.append(ic.to_dict())
        else:
            result.append({
                'service_name': s_name,
                'is_enabled': False,
                'config': {},
                'status': 'Not configured',
                'last_synced_at': None
            })
    return jsonify({'success': True, 'integrations': result})

@settings_bp.route('/api/integrations/<service_name>', methods=['POST'])
@login_required
@role_required(['Owner', 'Administrator', 'Security Analyst'])
def configure_integration(service_name):
    service_name = service_name.lower().strip()
    if service_name not in DEFAULT_SERVICES:
        return jsonify({'success': False, 'error': f"Unsupported integration: {service_name}"}), 400

    data = request.get_json() or {}
    is_enabled = bool(data.get('is_enabled', False))
    cfg_data = data.get('config', {})

    db = get_db()
    ic = db.query(IntegrationConfig).filter_by(service_name=service_name).first()
    if not ic:
        ic = IntegrationConfig(service_name=service_name)
        db.add(ic)

    ic.is_enabled = is_enabled
    ic.config_json = json.dumps(cfg_data)
    ic.last_synced_at = datetime.now(timezone.utc)
    db.commit()

    log_audit_event('INTEGRATION_UPDATED', 'Integration', ic.id, {'service': service_name, 'enabled': is_enabled})

    return jsonify({
        'success': True,
        'message': f"Integration '{service_name}' configured successfully.",
        'integration': ic.to_dict()
    })

@settings_bp.route('/api/settings/audit-logs', methods=['GET'])
@login_required
@role_required(['Owner', 'Administrator', 'Security Analyst'])
def get_audit_logs():
    db = get_db()
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify({
        'success': True,
        'count': len(logs),
        'logs': [l.to_dict() for l in logs]
    })

@settings_bp.route('/api/settings/users', methods=['GET'])
@login_required
def list_team_users():
    db = get_db()
    users = db.query(User).order_by(User.created_at.asc()).all()
    return jsonify({
        'success': True,
        'users': [u.to_dict() for u in users]
    })

@settings_bp.route('/api/settings/users/<user_id>/role', methods=['POST'])
@login_required
@role_required(['Owner', 'Administrator'])
def update_user_role(user_id):
    data = request.get_json() or {}
    new_role = data.get('role')
    
    valid_roles = ['Owner', 'Administrator', 'Security Analyst', 'Viewer']
    if new_role not in valid_roles:
        return jsonify({'success': False, 'error': 'Invalid role specified.'}), 400

    db = get_db()
    target_user = db.query(User).filter_by(id=user_id).first()
    if not target_user:
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    target_user.role = new_role
    db.commit()

    log_audit_event('USER_ROLE_UPDATED', 'User', target_user.id, {'username': target_user.username, 'new_role': new_role})
    return jsonify({
        'success': True,
        'message': f"User role updated to {new_role}."
    })
