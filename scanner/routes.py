import threading
import json
from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from auth.services import login_required, role_required, get_current_user, log_audit_event
from database.database import get_db
from database.models import Scan, API, Finding, ScanTest, FindingHistory
from scanner.scanner_engine import ScannerEngine
from scanner.risk_engine import RiskEngine

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scans')
@login_required
def scans_page():
    return render_template('scan.html', active_page='scans')

@scan_bp.route('/findings')
@login_required
def findings_page():
    return render_template('findings.html', active_page='findings')

@scan_bp.route('/findings/<finding_id>')
@login_required
def finding_details_page(finding_id):
    db = get_db()
    finding = db.query(Finding).filter_by(id=finding_id).first()
    if not finding:
        return render_template('base.html', error="404 - Finding Not Found"), 404
    return render_template('finding_details.html', finding=finding, active_page='findings')

# API Endpoints for Scans
@scan_bp.route('/api/scans/list', methods=['GET'])
@login_required
def list_scans():
    db = get_db()
    api_id = request.args.get('api_id')
    query = db.query(Scan).order_by(Scan.created_at.desc())
    if api_id:
        query = query.filter_by(api_id=api_id)
    scans = query.all()
    return jsonify({
        'success': True,
        'count': len(scans),
        'scans': [s.to_dict() for s in scans]
    })

@scan_bp.route('/api/scans/create', methods=['POST'])
@login_required
@role_required(['Owner', 'Administrator', 'Security Analyst'])
def create_scan():
    data = request.get_json() or {}
    api_id = data.get('api_id')
    name = data.get('name', '').strip()
    profile = data.get('profile', 'standard')

    if not api_id:
        return jsonify({'success': False, 'error': 'Target API must be selected.'}), 400
    if not name:
        name = f"Security Audit - {profile.capitalize()}"

    db = get_db()
    api = db.query(API).filter_by(id=api_id).first()
    if not api:
        return jsonify({'success': False, 'error': 'API target not found.'}), 404

    user = get_current_user()
    new_scan = Scan(
        api_id=api.id,
        user_id=user.id,
        name=name,
        scan_profile=profile,
        status='queued',
        total_endpoints=len(api.endpoints)
    )
    db.add(new_scan)
    db.commit()

    log_audit_event('SCAN_CREATED', 'Scan', new_scan.id, {'api_name': api.name, 'profile': profile})

    # Run scan synchronously or asynchronously
    # Running synchronously for quick responsiveness or thread
    ScannerEngine.execute_scan(new_scan.id)
    
    # Reload scan
    db.refresh(new_scan)

    return jsonify({
        'success': True,
        'message': f"Scan '{new_scan.name}' started successfully.",
        'scan': new_scan.to_dict()
    })

@scan_bp.route('/api/scans/<scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id):
    db = get_db()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({'success': False, 'error': 'Scan not found.'}), 404

    tests = [t.to_dict() for t in scan.tests]
    findings = [f.to_dict() for f in scan.findings]

    return jsonify({
        'success': True,
        'scan': scan.to_dict(),
        'tests': tests,
        'findings': findings
    })

# API Endpoints for Findings
@scan_bp.route('/api/findings/list', methods=['GET'])
@login_required
def list_findings():
    try:
        db = get_db()
        api_id = request.args.get('api_id')
        severity = request.args.get('severity')
        status = request.args.get('status')
        lifecycle = request.args.get('lifecycle')

        query = db.query(Finding).order_by(Finding.last_detected_at.desc())

        if api_id and api_id.strip():
            query = query.filter_by(api_id=api_id.strip())
        if severity and severity.strip():
            query = query.filter_by(severity=severity.strip().upper())
        if status and status.strip():
            query = query.filter_by(status=status.strip().upper())
        if lifecycle and lifecycle.strip():
            query = query.filter_by(lifecycle_state=lifecycle.strip())

        findings = query.all()
        posture = RiskEngine.calculate_api_posture(findings)

        return jsonify({
            'success': True,
            'count': len(findings),
            'posture': posture,
            'findings': [f.to_dict() for f in findings]
        })
    except Exception as e:
        print(f"[List Findings Error] {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'count': 0,
            'findings': []
        }), 500

@scan_bp.route('/api/findings/<finding_id>', methods=['GET'])
@login_required
def get_finding(finding_id):
    db = get_db()
    finding = db.query(Finding).filter_by(id=finding_id).first()
    if not finding:
        return jsonify({'success': False, 'error': 'Finding not found.'}), 404

    histories = [h.to_dict() for h in finding.history]
    return jsonify({
        'success': True,
        'finding': finding.to_dict(),
        'history': histories
    })

@scan_bp.route('/api/findings/<finding_id>/status', methods=['POST'])
@login_required
@role_required(['Owner', 'Administrator', 'Security Analyst'])
def update_finding_status(finding_id):
    db = get_db()
    finding = db.query(Finding).filter_by(id=finding_id).first()
    if not finding:
        return jsonify({'success': False, 'error': 'Finding not found.'}), 404

    data = request.get_json() or {}
    new_state = data.get('lifecycle_state')
    comment = data.get('comment', '').strip()

    valid_states = ['New', 'Detected', 'Verified', 'Acknowledged', 'Remediated', 'Resolved']
    if new_state not in valid_states:
        return jsonify({'success': False, 'error': f"Invalid lifecycle state. Permitted: {valid_states}"}), 400

    old_state = finding.lifecycle_state
    finding.lifecycle_state = new_state

    user = get_current_user()
    history_entry = FindingHistory(
        finding_id=finding.id,
        user_id=user.id,
        action='StatusChange',
        old_state=old_state,
        new_state=new_state,
        comment=comment or f"Status transitioned from {old_state} to {new_state}"
    )
    db.add(history_entry)
    db.commit()

    log_audit_event('FINDING_STATUS_UPDATED', 'Finding', finding.id, {
        'finding_ref': finding.finding_ref,
        'old_state': old_state,
        'new_state': new_state
    })

    return jsonify({
        'success': True,
        'message': f"Finding status updated to '{new_state}'.",
        'finding': finding.to_dict()
    })
