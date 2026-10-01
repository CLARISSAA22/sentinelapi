import json
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Float, Index
)
from sqlalchemy.orm import relationship
from database.database import Base

def generate_uuid():
    return str(uuid.uuid4())

def get_utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = 'users'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default='Security Analyst')  # Owner, Administrator, Security Analyst, Viewer
    created_at = Column(DateTime, default=get_utc_now)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)
    
    apis = relationship('API', back_populates='creator', cascade='all, delete-orphan')
    scans = relationship('Scan', back_populates='user', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class API(Base):
    __tablename__ = 'apis'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    name = Column(String(150), nullable=False)
    version = Column(String(50), nullable=False, default='1.0.0')
    base_url = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False)  # upload_json, upload_yaml, raw_json, raw_yaml, remote_url
    spec_hash = Column(String(64), nullable=True)
    raw_spec = Column(Text, nullable=True)
    owner = Column(String(100), nullable=True)
    environment = Column(String(50), nullable=False, default='production')  # production, staging, development
    status = Column(String(50), nullable=False, default='Active')  # Active, Deprecated, Testing
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)
    
    creator = relationship('User', back_populates='apis')
    endpoints = relationship('APIEndpoint', back_populates='api', cascade='all, delete-orphan')
    scans = relationship('Scan', back_populates='api', cascade='all, delete-orphan')
    findings = relationship('Finding', back_populates='api', cascade='all, delete-orphan')
    drift_events = relationship('APIDriftEvent', back_populates='api', cascade='all, delete-orphan')
    dependencies = relationship('APIDependency', back_populates='api', cascade='all, delete-orphan')
    credentials = relationship('ManagedCredential', back_populates='api', cascade='all, delete-orphan')
    monitoring_jobs = relationship('MonitoringJob', back_populates='api', cascade='all, delete-orphan')
    reports = relationship('Report', back_populates='api', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'base_url': self.base_url,
            'source_type': self.source_type,
            'owner': self.owner or 'Unassigned',
            'environment': self.environment,
            'status': self.status,
            'description': self.description or '',
            'endpoint_count': len(self.endpoints) if self.endpoints else 0,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class APIEndpoint(Base):
    __tablename__ = 'api_endpoints'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey('apis.id'), nullable=False, index=True)
    method = Column(String(10), nullable=False)  # GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
    path = Column(String(255), nullable=False)
    summary = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    parameters_json = Column(Text, default='[]')
    request_body_json = Column(Text, default='{}')
    response_schemas_json = Column(Text, default='{}')
    auth_required = Column(Boolean, default=False)
    auth_types_json = Column(Text, default='[]')
    tags_json = Column(Text, default='[]')
    risk_status = Column(String(50), default='UNTESTED')  # UNTESTED, LOW, MEDIUM, HIGH, CRITICAL, SECURE
    last_tested_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now)
    
    api = relationship('API', back_populates='endpoints')
    findings = relationship('Finding', back_populates='endpoint', cascade='all, delete-orphan')

    __table_args__ = (
        Index('idx_endpoint_api_method_path', 'api_id', 'method', 'path'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'api_id': self.api_id,
            'method': (self.method or 'GET').upper(),
            'path': self.path,
            'summary': self.summary or '',
            'description': self.description or '',
            'parameters': json.loads(self.parameters_json or '[]'),
            'request_body': json.loads(self.request_body_json or '{}'),
            'response_schemas': json.loads(self.response_schemas_json or '{}'),
            'auth_required': self.auth_required,
            'auth_types': json.loads(self.auth_types_json or '[]'),
            'tags': json.loads(self.tags_json or '[]'),
            'risk_status': self.risk_status,
            'last_tested_at': self.last_tested_at.isoformat() if self.last_tested_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class APIDependency(Base):
    __tablename__ = 'api_dependencies'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey('apis.id'), nullable=False, index=True)
    endpoint_id = Column(String(36), ForeignKey('api_endpoints.id'), nullable=True)
    service_name = Column(String(100), nullable=False)
    target_url = Column(String(255), nullable=True)
    dependency_type = Column(String(50), nullable=False, default='EXTERNAL_API')  # EXTERNAL_API, DATABASE, AUTH_SERVICE, INTERNAL_SERVICE
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now)
    
    api = relationship('API', back_populates='dependencies')
    endpoint = relationship('APIEndpoint')

    def to_dict(self):
        return {
            'id': self.id,
            'api_id': self.api_id,
            'api_name': self.api.name if self.api else 'Unknown API',
            'endpoint_id': self.endpoint_id,
            'service_name': self.service_name,
            'target_url': self.target_url or '',
            'dependency_type': self.dependency_type,
            'description': self.description or '',
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class APIDriftEvent(Base):
    __tablename__ = 'api_drift_events'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey('apis.id'), nullable=False, index=True)
    change_type = Column(String(50), nullable=False)  # ENDPOINT_ADDED, ENDPOINT_REMOVED, METHOD_CHANGED, PARAMETER_CHANGED, SCHEMA_CHANGED, AUTH_CHANGED
    change_scope = Column(String(50), nullable=False, default='ENDPOINT')  # GLOBAL, ENDPOINT, SCHEMA, AUTH
    path = Column(String(255), nullable=True)
    method = Column(String(10), nullable=True)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=get_utc_now)
    acknowledged = Column(Boolean, default=False)
    
    api = relationship('API', back_populates='drift_events')

    def to_dict(self):
        return {
            'id': self.id,
            'api_id': self.api_id,
            'api_name': self.api.name if self.api else 'Unknown',
            'change_type': self.change_type,
            'change_scope': self.change_scope,
            'path': self.path or '-',
            'method': self.method or '-',
            'old_value': self.old_value or '',
            'new_value': self.new_value or '',
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'acknowledged': self.acknowledged
        }

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey('apis.id'), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    name = Column(String(150), nullable=False)
    scan_profile = Column(String(50), nullable=False, default='standard')  # safe, standard, authenticated, advanced
    status = Column(String(50), nullable=False, default='created')  # created, queued, preparing, discovery, authentication, test_planning, testing, verification, correlation, risk_calculation, report_generation, completed, failed, cancelled
    total_endpoints = Column(Integer, default=0)
    tested_endpoints = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    config_json = Column(Text, default='{}')
    created_at = Column(DateTime, default=get_utc_now)
    
    api = relationship('API', back_populates='scans')
    user = relationship('User', back_populates='scans')
    tests = relationship('ScanTest', back_populates='scan', cascade='all, delete-orphan')
    findings = relationship('Finding', back_populates='scan', cascade='all, delete-orphan')
    reports = relationship('Report', back_populates='scan', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'api_id': self.api_id,
            'api_name': self.api.name if self.api else 'Unknown',
            'user_id': self.user_id,
            'user_name': self.user.username if self.user else 'System',
            'name': self.name,
            'scan_profile': self.scan_profile,
            'status': self.status,
            'total_endpoints': self.total_endpoints,
            'tested_endpoints': self.tested_endpoints,
            'findings_count': self.findings_count,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
            'config': json.loads(self.config_json or '{}'),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ScanTest(Base):
    __tablename__ = 'scan_tests'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False, index=True)
    endpoint_id = Column(String(36), ForeignKey('api_endpoints.id'), nullable=True)
    check_id = Column(String(80), nullable=False)
    check_name = Column(String(150), nullable=False)
    category = Column(String(80), nullable=False)
    status = Column(String(30), nullable=False, default='executed')  # executed, not_applicable, skipped, failed
    executed_at = Column(DateTime, default=get_utc_now)
    duration_ms = Column(Float, default=0.0)
    details = Column(Text, nullable=True)
    
    scan = relationship('Scan', back_populates='tests')
    endpoint = relationship('APIEndpoint')

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'endpoint_id': self.endpoint_id,
            'endpoint_path': self.endpoint.path if self.endpoint else 'Global',
            'endpoint_method': self.endpoint.method if self.endpoint else '-',
            'check_id': self.check_id,
            'check_name': self.check_name,
            'category': self.category,
            'status': self.status,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'duration_ms': self.duration_ms,
            'details': self.details or ''
        }

class Finding(Base):
    __tablename__ = 'findings'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_ref = Column(String(30), unique=True, nullable=False, index=True)  # SEC-001, etc.
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=True, index=True)
    api_id = Column(String(36), ForeignKey('apis.id'), nullable=False, index=True)
    endpoint_id = Column(String(36), ForeignKey('api_endpoints.id'), nullable=True, index=True)
    title = Column(String(200), nullable=False)
    category = Column(String(100), nullable=False)  # Authentication, Authorization, Injection, Misconfiguration, etc.
    method = Column(String(10), nullable=True)
    path = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    cvss_score = Column(Float, nullable=False, default=5.0)
    confidence = Column(String(20), nullable=False, default='HIGH')  # HIGH, MEDIUM, LOW
    description = Column(Text, nullable=False)
    evidence_json = Column(Text, default='{}')
    request_data = Column(Text, nullable=True)
    response_data = Column(Text, nullable=True)
    verification_result = Column(Text, nullable=True)
    remediation = Column(Text, nullable=False)
    references_json = Column(Text, default='[]')
    status = Column(String(30), nullable=False, default='CONFIRMED')  # CONFIRMED, POTENTIAL, NOT_VULNERABLE, NOT_TESTED, NOT_APPLICABLE, ERROR
    lifecycle_state = Column(String(30), nullable=False, default='New')  # New, Detected, Verified, Acknowledged, Remediated, Resolved, Reopened
    first_detected_at = Column(DateTime, default=get_utc_now)
    last_detected_at = Column(DateTime, default=get_utc_now)
    
    scan = relationship('Scan', back_populates='findings')
    api = relationship('API', back_populates='findings')
    endpoint = relationship('APIEndpoint', back_populates='findings')
    history = relationship('FindingHistory', back_populates='finding', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'finding_ref': self.finding_ref,
            'scan_id': self.scan_id,
            'api_id': self.api_id,
            'api_name': self.api.name if self.api else 'Unknown API',
            'endpoint_id': self.endpoint_id,
            'method': self.method or (self.endpoint.method if self.endpoint else '-'),
            'path': self.path or (self.endpoint.path if self.endpoint else '-'),
            'title': self.title,
            'category': self.category,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'confidence': self.confidence,
            'description': self.description,
            'evidence': json.loads(self.evidence_json) if (self.evidence_json and self.evidence_json.startswith('{')) else {},
            'request_data': self.request_data or '',
            'response_data': self.response_data or '',
            'verification_result': self.verification_result or '',
            'remediation': self.remediation,
            'references': json.loads(self.references_json) if (self.references_json and self.references_json.startswith('[')) else [],
            'status': self.status,
            'lifecycle_state': self.lifecycle_state,
            'first_detected_at': self.first_detected_at.isoformat() if self.first_detected_at else None,
            'last_detected_at': self.last_detected_at.isoformat() if self.last_detected_at else None
        }

class FindingHistory(Base):
    __tablename__ = 'finding_histories'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey('findings.id'), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=True)
    action = Column(String(80), nullable=False)  # StatusChange, Comment, Reopened, Verified, Resolved
    old_state = Column(String(50), nullable=True)
    new_state = Column(String(50), nullable=True)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now)
    
    finding = relationship('Finding', back_populates='history')
    user = relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'user_name': self.user.username if self.user else 'System Engine',
            'action': self.action,
            'old_state': self.old_state,
            'new_state': self.new_state,
            'comment': self.comment or '',
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ManagedCredential(Base):
    __tablename__ = 'managed_credentials'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey('apis.id'), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    name = Column(String(100), nullable=False)
    auth_type = Column(String(50), nullable=False)  # api_key, bearer, basic, header, custom
    masked_value = Column(String(100), nullable=False)
    encrypted_value = Column(Text, nullable=False)
    config_json = Column(Text, default='{}')
    created_at = Column(DateTime, default=get_utc_now)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)
    
    api = relationship('API', back_populates='credentials')
    user = relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'api_id': self.api_id,
            'name': self.name,
            'auth_type': self.auth_type,
            'masked_value': self.masked_value,
            'config': json.loads(self.config_json or '{}'),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class MonitoringJob(Base):
    __tablename__ = 'monitoring_jobs'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey('apis.id'), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    name = Column(String(150), nullable=False)
    interval_minutes = Column(Integer, nullable=False, default=1440)  # default daily (1440m)
    scan_profile = Column(String(50), default='standard')
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now)
    
    api = relationship('API', back_populates='monitoring_jobs')
    user = relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'api_id': self.api_id,
            'api_name': self.api.name if self.api else 'Unknown',
            'name': self.name,
            'interval_minutes': self.interval_minutes,
            'scan_profile': self.scan_profile,
            'is_active': self.is_active,
            'last_run_at': self.last_run_at.isoformat() if self.last_run_at else None,
            'next_run_at': self.next_run_at.isoformat() if self.next_run_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Report(Base):
    __tablename__ = 'reports'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=True, index=True)
    api_id = Column(String(36), ForeignKey('apis.id'), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    title = Column(String(200), nullable=False)
    report_format = Column(String(20), default='html')  # html, json, markdown
    summary_json = Column(Text, default='{}')
    generated_at = Column(DateTime, default=get_utc_now)
    
    scan = relationship('Scan', back_populates='reports')
    api = relationship('API', back_populates='reports')
    user = relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'api_id': self.api_id,
            'api_name': self.api.name if self.api else 'Unknown',
            'user_name': self.user.username if self.user else 'System',
            'title': self.title,
            'report_format': self.report_format,
            'summary': json.loads(self.summary_json or '{}'),
            'generated_at': self.generated_at.isoformat() if self.generated_at else None
        }

class IntegrationConfig(Base):
    __tablename__ = 'integration_configs'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    service_name = Column(String(50), unique=True, nullable=False)  # jira, slack, pagerduty
    is_enabled = Column(Boolean, default=False)
    config_json = Column(Text, default='{}')
    last_synced_at = Column(DateTime, nullable=True)

    def to_dict(self):
        cfg = json.loads(self.config_json or '{}')
        # Mask sensitive keys
        masked_cfg = {}
        for k, v in cfg.items():
            if any(secret_term in k.lower() for secret_term in ['token', 'secret', 'key', 'password']):
                masked_cfg[k] = '••••••••' if v else ''
            else:
                masked_cfg[k] = v
        return {
            'id': self.id,
            'service_name': self.service_name,
            'is_enabled': self.is_enabled,
            'config': masked_cfg,
            'last_synced_at': self.last_synced_at.isoformat() if self.last_synced_at else None
        }

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=True)
    username = Column(String(80), nullable=True)
    action = Column(String(80), nullable=False, index=True)
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(100), nullable=True)
    details_json = Column(Text, default='{}')
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username or 'System',
            'action': self.action,
            'target_type': self.target_type or '-',
            'target_id': self.target_id or '-',
            'details': json.loads(self.details_json or '{}'),
            'ip_address': self.ip_address or '-',
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
