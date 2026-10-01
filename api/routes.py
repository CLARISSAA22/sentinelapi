import os
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from auth.services import login_required, role_required, get_current_user, log_audit_event
from api.validators import safe_parse_spec_content, fetch_remote_spec_safely, validate_remote_url_ssrf
from api.importer import OpenAPIImporter
from api.discovery import APIDiscoveryManager
from database.database import get_db
from database.models import API, APIEndpoint, APIDriftEvent, APIDependency, Finding, Scan

api_bp = Blueprint('api', __name__)

@api_bp.route('/api-inventory')
@login_required
def inventory_page():
    return render_template('api_inventory.html', active_page='inventory')

@api_bp.route('/api-import')
@login_required
def import_page():
    return render_template('api_import.html', active_page='import')

@api_bp.route('/drift')
@login_required
def drift_page():
    return render_template('drift.html', active_page='drift')

@api_bp.route('/dependencies')
@login_required
def dependencies_page():
    return render_template('dependencies.html', active_page='dependencies')

@api_bp.route('/apis/preview', methods=['POST'])
@login_required
def preview_spec():
    """Validates OpenAPI/Swagger spec and returns a parsed preview before committing."""
    source_type = request.form.get('source_type') or request.json.get('source_type') if request.is_json else None
    raw_content = None
    
    if request.is_json:
        data = request.get_json() or {}
        source_type = data.get('source_type')
        if source_type == 'remote_url':
            url = data.get('url', '').strip()
            fetched_text, err = fetch_remote_spec_safely(url)
            if err:
                return jsonify({'success': False, 'error': f"SSRF/Network Error: {err}"}), 400
            raw_content = fetched_text
        else:
            raw_content = data.get('raw_spec', '')
    elif 'spec_file' in request.files:
        file = request.files['spec_file']
        if not file.filename:
            return jsonify({'success': False, 'error': 'No file selected.'}), 400
        raw_content = file.read().decode('utf-8', errors='replace')
        filename_lower = file.filename.lower()
        if filename_lower.endswith('.json'):
            source_type = 'upload_json'
        elif filename_lower.endswith(('.yaml', '.yml')):
            source_type = 'upload_yaml'
        else:
            source_type = 'upload_json'
    else:
        # Form submission with raw text or remote URL
        source_type = request.form.get('source_type')
        if source_type == 'remote_url':
            url = request.form.get('url', '').strip()
            fetched_text, err = fetch_remote_spec_safely(url)
            if err:
                return jsonify({'success': False, 'error': f"SSRF/Network Error: {err}"}), 400
            raw_content = fetched_text
        else:
            raw_content = request.form.get('raw_spec', '')

    if not raw_content or not raw_content.strip():
        return jsonify({'success': False, 'error': 'Specification content is empty.'}), 400

    parsed_dict, format_detected, parse_err = safe_parse_spec_content(raw_content)
    if parse_err:
        return jsonify({'success': False, 'error': f"Parse error: {parse_err}"}), 400

    extracted_data, val_err = OpenAPIImporter.validate_and_extract(parsed_dict)
    if val_err:
        return jsonify({'success': False, 'error': f"Validation error: {val_err}"}), 400

    return jsonify({
        'success': True,
        'format': format_detected,
        'source_type': source_type,
        'raw_spec': raw_content,
        'preview': extracted_data
    })

@api_bp.route('/apis/import', methods=['POST'])
@login_required
@role_required(['Owner', 'Administrator', 'Security Analyst'])
def import_api():
    """Commit the parsed spec and generate API, endpoints, and drift records."""
    data = request.get_json() or {}
    raw_spec = data.get('raw_spec', '')
    source_type = data.get('source_type', 'upload_json')
    custom_name = data.get('name')
    custom_base_url = data.get('base_url')
    environment = data.get('environment', 'production')
    owner = data.get('owner')

    if not raw_spec:
        return jsonify({'success': False, 'error': 'Missing specification data.'}), 400

    parsed_dict, _, parse_err = safe_parse_spec_content(raw_spec)
    if parse_err:
        return jsonify({'success': False, 'error': parse_err}), 400

    extracted_data, val_err = OpenAPIImporter.validate_and_extract(parsed_dict)
    if val_err:
        return jsonify({'success': False, 'error': val_err}), 400

    user = get_current_user()
    api_obj, drift_events = APIDiscoveryManager.save_api_and_endpoints(
        user_id=user.id,
        spec_data=extracted_data,
        raw_spec=raw_spec,
        source_type=source_type,
        environment=environment,
        owner=owner,
        custom_name=custom_name,
        custom_base_url=custom_base_url
    )

    log_audit_event('API_IMPORTED', 'API', api_obj.id, {
        'name': api_obj.name,
        'endpoints_count': len(api_obj.endpoints),
        'drift_count': len(drift_events)
    })

    return jsonify({
        'success': True,
        'message': f"API '{api_obj.name}' successfully imported with {len(api_obj.endpoints)} endpoints.",
        'api': api_obj.to_dict(),
        'drift_events_count': len(drift_events)
    })

@api_bp.route('/apis/list', methods=['GET'])
@login_required
def list_apis():
    db = get_db()
    apis = db.query(API).order_by(API.created_at.desc()).all()
    return jsonify({
        'success': True,
        'count': len(apis),
        'apis': [a.to_dict() for a in apis]
    })

@api_bp.route('/apis/<api_id>', methods=['GET'])
@login_required
def get_api_detail(api_id):
    db = get_db()
    api = db.query(API).filter_by(id=api_id).first()
    if not api:
        return jsonify({'success': False, 'error': 'API not found.'}), 404

    return jsonify({
        'success': True,
        'api': api.to_dict(),
        'endpoints': [ep.to_dict() for ep in api.endpoints],
        'dependencies': [dep.to_dict() for dep in api.dependencies],
        'drift_events': [d.to_dict() for d in api.drift_events]
    })

@api_bp.route('/apis/<api_id>', methods=['DELETE'])
@login_required
@role_required(['Owner', 'Administrator'])
def delete_api(api_id):
    db = get_db()
    api = db.query(API).filter_by(id=api_id).first()
    if not api:
        return jsonify({'success': False, 'error': 'API not found.'}), 404

    api_name = api.name
    db.delete(api)
    db.commit()

    log_audit_event('API_DELETED', 'API', api_id, {'name': api_name})
    return jsonify({'success': True, 'message': f"API '{api_name}' deleted successfully."})

@api_bp.route('/apis/drift/events', methods=['GET'])
@login_required
def list_drift_events():
    db = get_db()
    api_id = request.args.get('api_id')
    query = db.query(APIDriftEvent).order_by(APIDriftEvent.detected_at.desc())
    if api_id:
        query = query.filter_by(api_id=api_id)
    events = query.all()
    return jsonify({
        'success': True,
        'count': len(events),
        'events': [e.to_dict() for e in events]
    })

@api_bp.route('/apis/drift/<drift_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_drift(drift_id):
    db = get_db()
    drift = db.query(APIDriftEvent).filter_by(id=drift_id).first()
    if not drift:
        return jsonify({'success': False, 'error': 'Drift event not found.'}), 404
    drift.acknowledged = True
    db.commit()
    return jsonify({'success': True, 'message': 'Drift event acknowledged.'})

@api_bp.route('/apis/dependencies/graph', methods=['GET'])
@login_required
def list_dependencies():
    db = get_db()
    deps = db.query(APIDependency).all()
    apis = db.query(API).all()
    
    # Build a clean graph structure: nodes and edges
    nodes = []
    edges = []
    
    api_nodes = {a.id: {'id': a.id, 'label': a.name, 'type': 'api', 'environment': a.environment} for a in apis}
    nodes.extend(api_nodes.values())
    
    for dep in deps:
        service_node_id = f"ext_{dep.service_name}"
        if not any(n['id'] == service_node_id for n in nodes):
            nodes.append({
                'id': service_node_id,
                'label': dep.service_name,
                'type': dep.dependency_type.lower(),
                'target_url': dep.target_url
            })
        edges.append({
            'source': dep.api_id,
            'target': service_node_id,
            'label': dep.description or dep.dependency_type
        })
        
    return jsonify({
        'success': True,
        'dependencies': [d.to_dict() for d in deps],
        'graph': {
            'nodes': nodes,
            'edges': edges
        }
    })
