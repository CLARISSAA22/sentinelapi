from flask import Blueprint, render_template, request, jsonify, Response
from auth.services import login_required, role_required, get_current_user, log_audit_event
from database.database import get_db
from database.models import Report, Scan, API, Finding
from reports.generator import ReportGenerator

report_bp = Blueprint('report', __name__)

@report_bp.route('/reports')
@login_required
def reports_page():
    return render_template('reports.html', active_page='reports')

@report_bp.route('/api/reports/list', methods=['GET'])
@login_required
def list_reports():
    db = get_db()
    reports = db.query(Report).order_by(Report.generated_at.desc()).all()
    return jsonify({
        'success': True,
        'count': len(reports),
        'reports': [r.to_dict() for r in reports]
    })

@report_bp.route('/api/reports/<report_id>', methods=['GET'])
@login_required
def get_report(report_id):
    db = get_db()
    report = db.query(Report).filter_by(id=report_id).first()
    if not report:
        return jsonify({'success': False, 'error': 'Report not found.'}), 404
    return jsonify({
        'success': True,
        'report': report.to_dict()
    })

@report_bp.route('/api/reports/<report_id>/export', methods=['GET'])
@login_required
def export_report(report_id):
    db = get_db()
    report = db.query(Report).filter_by(id=report_id).first()
    if not report:
        return jsonify({'success': False, 'error': 'Report not found.'}), 404

    scan = db.query(Scan).filter_by(id=report.scan_id).first()
    api = db.query(API).filter_by(id=report.api_id).first()
    findings = db.query(Finding).filter_by(api_id=report.api_id).all() if api else []

    fmt = request.args.get('format', 'markdown').lower()
    
    if fmt == 'json':
        export_data = {
            'report': report.to_dict(),
            'api': api.to_dict() if api else None,
            'findings': [f.to_dict() for f in findings]
        }
        return jsonify(export_data)
    else:
        # Default markdown export
        md_text = ReportGenerator.generate_markdown_report(scan, api, findings)
        return Response(
            md_text,
            mimetype='text/markdown',
            headers={'Content-Disposition': f'attachment;filename=sentinelapi_report_{report.id[:8]}.md'}
        )
