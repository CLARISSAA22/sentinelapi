import os
import json
from flask import Flask, render_template, redirect, url_for, jsonify, request
from config import config_by_name
from database.database import init_db, get_db
from database.models import User, API, APIEndpoint, Scan, Finding, APIDriftEvent, Report, AuditLog
from auth.services import get_current_user, login_required
from scanner.risk_engine import RiskEngine

def create_app(config_name=None):
    if not config_name:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name['default']))

    # Initialize Database
    init_db(app.config['SQLALCHEMY_DATABASE_URI'])

    # Context processor to make current user & app info available in all templates
    @app.context_processor
    def inject_global_context():
        user = get_current_user()
        return {
            'current_user': user,
            'app_name': app.config.get('APP_NAME', 'SentinelAPI'),
            'app_version': app.config.get('APP_VERSION', '2.4.0-enterprise'),
            'platform_status': app.config.get('PLATFORM_STATUS', 'OPERATIONAL')
        }

    # Register Blueprints
    from auth.routes import auth_bp
    from api.routes import api_bp
    from scanner.routes import scan_bp
    from monitoring.routes import monitoring_bp
    from reports.routes import report_bp
    from integrations.routes import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(settings_bp)

    # Core Routes
    @app.route('/')
    def landing_page():
        return render_template('index.html')

    @app.route('/favicon.ico')
    def favicon():
        return ('', 204)

    @app.route('/dashboard')
    @login_required
    def dashboard_page():
        return render_template('dashboard.html', active_page='dashboard')

    @app.route('/api/dashboard/stats', methods=['GET'])
    @login_required
    def get_dashboard_stats():
        """Retrieve real metrics directly from the database (No fake/hardcoded numbers)."""
        db = get_db()
        
        apis = db.query(API).all()
        total_apis = len(apis)
        
        endpoints = db.query(APIEndpoint).all()
        total_endpoints = len(endpoints)
        tested_endpoints = len([ep for ep in endpoints if ep.last_tested_at is not None])
        
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
        total_scans = len(scans)
        
        findings = db.query(Finding).order_by(Finding.last_detected_at.desc()).all()
        posture = RiskEngine.calculate_api_posture(findings)
        
        drift_events = db.query(APIDriftEvent).order_by(APIDriftEvent.detected_at.desc()).all()
        unacknowledged_drift = len([d for d in drift_events if not d.acknowledged])
        
        recent_scans = [s.to_dict() for s in scans[:5]]
        recent_findings = [f.to_dict() for f in findings[:6]]
        recent_drifts = [d.to_dict() for d in drift_events[:5]]

        return jsonify({
            'success': True,
            'metrics': {
                'total_apis': total_apis,
                'total_endpoints': total_endpoints,
                'tested_endpoints': tested_endpoints,
                'unscanned_endpoints': max(0, total_endpoints - tested_endpoints),
                'total_scans': total_scans,
                'total_findings': len(findings),
                'active_findings': posture['total_active'],
                'resolved_findings': posture['total_resolved'],
                'drift_events_count': len(drift_events),
                'unacknowledged_drift': unacknowledged_drift,
                'posture_score': posture['score'],
                'posture_grade': posture['grade'],
                'posture_status': posture['status'],
                'severity_counts': posture['counts']
            },
            'recent_scans': recent_scans,
            'recent_findings': recent_findings,
            'recent_drifts': recent_drifts
        })

    # Error Handlers
    @app.errorhandler(404)
    def handle_404(e):
        if request.is_json or request.path.startswith('/api/'):
            return jsonify({'error': 'Resource not found', 'status': 404}), 404
        return render_template('base.html', error="404 - Page Not Found"), 404

    @app.errorhandler(403)
    def handle_403(e):
        if request.is_json or request.path.startswith('/api/'):
            return jsonify({'error': 'Forbidden - Insufficient permissions', 'status': 403}), 403
        return render_template('base.html', error="403 - Forbidden"), 403

    @app.errorhandler(500)
    def handle_500(e):
        if request.is_json or request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error', 'status': 500}), 500
        return render_template('base.html', error="500 - Internal Server Error"), 500

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
