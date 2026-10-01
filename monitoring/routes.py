import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, jsonify
from auth.services import login_required, role_required, get_current_user, log_audit_event
from database.database import get_db
from database.models import MonitoringJob, API, Scan
from scanner.scanner_engine import ScannerEngine

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/monitoring')
@login_required
def monitoring_page():
    return render_template('monitoring.html', active_page='monitoring')

@monitoring_bp.route('/api/monitoring/jobs', methods=['GET'])
@login_required
def list_monitoring_jobs():
    db = get_db()
    jobs = db.query(MonitoringJob).order_by(MonitoringJob.created_at.desc()).all()
    return jsonify({
        'success': True,
        'count': len(jobs),
        'jobs': [j.to_dict() for j in jobs]
    })

@monitoring_bp.route('/api/monitoring/jobs', methods=['POST'])
@login_required
@role_required(['Owner', 'Administrator', 'Security Analyst'])
def create_monitoring_job():
    data = request.get_json() or {}
    api_id = data.get('api_id')
    name = data.get('name', '').strip()
    interval_minutes = int(data.get('interval_minutes', 1440))
    profile = data.get('scan_profile', 'standard')

    if not api_id:
        return jsonify({'success': False, 'error': 'API target required.'}), 400
    if not name:
        name = f"Continuous Security Monitor ({interval_minutes}m)"

    db = get_db()
    api = db.query(API).filter_by(id=api_id).first()
    if not api:
        return jsonify({'success': False, 'error': 'Target API not found.'}), 404

    user = get_current_user()
    next_run = datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)

    job = MonitoringJob(
        api_id=api.id,
        user_id=user.id,
        name=name,
        interval_minutes=interval_minutes,
        scan_profile=profile,
        is_active=True,
        next_run_at=next_run
    )
    db.add(job)
    db.commit()

    log_audit_event('MONITORING_JOB_CREATED', 'MonitoringJob', job.id, {'api_name': api.name, 'interval': interval_minutes})

    return jsonify({
        'success': True,
        'message': f"Monitoring schedule '{job.name}' created.",
        'job': job.to_dict()
    })

@monitoring_bp.route('/api/monitoring/jobs/<job_id>/toggle', methods=['POST'])
@login_required
@role_required(['Owner', 'Administrator', 'Security Analyst'])
def toggle_monitoring_job(job_id):
    db = get_db()
    job = db.query(MonitoringJob).filter_by(id=job_id).first()
    if not job:
        return jsonify({'success': False, 'error': 'Job not found.'}), 404

    job.is_active = not job.is_active
    db.commit()

    return jsonify({
        'success': True,
        'is_active': job.is_active,
        'message': f"Job '{job.name}' is now {'active' if job.is_active else 'paused'}."
    })

@monitoring_bp.route('/api/monitoring/jobs/<job_id>/run-now', methods=['POST'])
@login_required
@role_required(['Owner', 'Administrator', 'Security Analyst'])
def run_monitoring_job_now(job_id):
    db = get_db()
    job = db.query(MonitoringJob).filter_by(id=job_id).first()
    if not job:
        return jsonify({'success': False, 'error': 'Job not found.'}), 404

    user = get_current_user()
    scan = Scan(
        api_id=job.api_id,
        user_id=user.id,
        name=f"Scheduled Monitor Scan - {job.name}",
        scan_profile=job.scan_profile,
        status='queued'
    )
    db.add(scan)
    db.commit()

    ScannerEngine.execute_scan(scan.id)
    
    now = datetime.now(timezone.utc)
    job.last_run_at = now
    job.next_run_at = now + timedelta(minutes=job.interval_minutes)
    db.commit()

    return jsonify({
        'success': True,
        'message': f"Monitoring scan executed for job '{job.name}'.",
        'scan_id': scan.id
    })

@monitoring_bp.route('/api/monitoring/cron-trigger', methods=['GET', 'POST'])
def cron_trigger_jobs():
    """Trigger due monitoring jobs. Designed for Vercel Cron Jobs and external schedulers."""
    db = get_db()
    now = datetime.now(timezone.utc)
    
    # Query all active jobs that are due
    due_jobs = db.query(MonitoringJob).filter(
        MonitoringJob.is_active == True,
        MonitoringJob.next_run_at <= now
    ).all()
    
    executed = []
    for job in due_jobs:
        try:
            scan = Scan(
                api_id=job.api_id,
                user_id=job.user_id,
                name=f"Cron Scheduled Scan - {job.name}",
                scan_profile=job.scan_profile,
                status='queued'
            )
            db.add(scan)
            db.commit()
            
            ScannerEngine.execute_scan(scan.id)
            
            job.last_run_at = now
            job.next_run_at = now + timedelta(minutes=job.interval_minutes)
            db.commit()
            executed.append(job.id)
        except Exception as e:
            print(f"Error executing cron job {job.id}: {e}")
            
    return jsonify({
        'success': True,
        'triggered_count': len(executed),
        'executed_job_ids': executed,
        'timestamp': now.isoformat()
    })

