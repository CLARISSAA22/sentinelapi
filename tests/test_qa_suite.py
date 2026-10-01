import pytest
import json
import os
import tempfile
from pathlib import Path
from app import create_app
from database.database import get_db, init_db, close_db
from database.models import (
    User, API, APIEndpoint, Scan, ScanTest, Finding, FindingHistory,
    APIDriftEvent, APIDependency, MonitoringJob, Report, AuditLog
)
from api.validators import validate_remote_url_ssrf, safe_parse_spec_content
from api.importer import OpenAPIImporter
from api.discovery import APIDiscoveryManager
from scanner.scanner_engine import ScannerEngine
from scanner.risk_engine import RiskEngine
from scanner.scan_context import ScanContext
from checks import get_all_checks

VALID_OAS3_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Enterprise Banking API",
        "version": "1.0.0",
        "description": "Core Banking Microservices"
    },
    "servers": [{"url": "https://api.bank.enterprise.com/v1"}],
    "components": {
        "securitySchemes": {
            "BearerAuth": {"type": "http", "scheme": "bearer"}
        }
    },
    "security": [{"BearerAuth": []}],
    "paths": {
        "/accounts/{accountId}": {
            "get": {
                "summary": "Retrieve account details",
                "parameters": [
                    {"name": "accountId", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "Account details"}}
            }
        },
        "/transfers/execute": {
            "post": {
                "summary": "Transfer funds",
                "parameters": [
                    {"name": "recipient_id", "in": "query", "schema": {"type": "string"}},
                    {"name": "sort", "in": "query", "schema": {"type": "string"}}
                ],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"type": "object"}}}
                },
                "responses": {"200": {"description": "Transfer confirmed"}}
            }
        },
        "/admin/system-logs": {
            "get": {
                "summary": "Internal administrative system logs",
                "tags": ["admin"],
                "security": [],
                "responses": {"200": {"description": "Logs"}}
            }
        }
    }
}

@pytest.fixture
def qa_client():
    app = create_app('testing')
    with app.test_client() as client:
        with app.app_context():
            init_db('sqlite:///:memory:')
            yield client
            close_db()

# 1. PUBLIC AREA TESTS
def test_public_area_routes(qa_client):
    """Test public routes load successfully with proper status codes and headers."""
    # Landing page
    res_landing = qa_client.get('/')
    assert res_landing.status_code == 200
    assert b"SentinelAPI" in res_landing.data
    assert b"ENTERPRISE API DEFENSE" in res_landing.data

    # Login page
    res_login = qa_client.get('/login')
    assert res_login.status_code == 200
    assert b"Sign In to SentinelAPI" in res_login.data

    # Register page
    res_register = qa_client.get('/register')
    assert res_register.status_code == 200
    assert b"Create SentinelAPI Account" in res_register.data

# 2. AUTHENTICATION & ACCESS CONTROL TESTS
def test_auth_full_lifecycle(qa_client):
    """Test registration, duplicate check, bad login, authorization, and logout."""
    # 1. Register User 1 (should automatically become Owner)
    res_reg1 = qa_client.post('/register', json={
        'username': 'alpha_owner',
        'email': 'owner@bank.com',
        'password': 'Password123!',
        'role': 'Owner'
    })
    assert res_reg1.status_code == 200
    user1_data = res_reg1.get_json()['user']
    assert user1_data['role'] == 'Owner'

    # 2. Reject duplicate registration
    res_dup = qa_client.post('/register', json={
        'username': 'alpha_owner',
        'email': 'different@bank.com',
        'password': 'Password123!'
    })
    assert res_dup.status_code == 400
    assert "already registered" in res_dup.get_json()['error']

    # 3. Logout
    qa_client.get('/logout')

    # 4. Failed login with wrong password
    res_bad_login = qa_client.post('/login', json={
        'username': 'alpha_owner',
        'password': 'WrongPassword999!'
    })
    assert res_bad_login.status_code == 401

    # 5. Successful login
    res_good_login = qa_client.post('/login', json={
        'username': 'alpha_owner',
        'password': 'Password123!'
    })
    assert res_good_login.status_code == 200
    assert res_good_login.get_json()['success'] is True

    # 6. Verify protected access while logged in
    res_dash = qa_client.get('/dashboard')
    assert res_dash.status_code == 200

    # 7. Logout and verify protected routes redirect to /login
    qa_client.get('/logout')
    for protected_url in ['/dashboard', '/api-inventory', '/api-import', '/scans', '/findings', '/drift', '/dependencies', '/monitoring', '/reports', '/settings']:
        res_prot = qa_client.get(protected_url)
        assert res_prot.status_code == 302, f"Expected 302 redirect for unauthenticated {protected_url}"
        assert '/login' in res_prot.headers['Location']

# 3. REMOTE URL SECURITY & SSRF VALIDATION TESTS
def test_ssrf_blocking_vectors():
    """Verify that all dangerous SSRF IP formats, cloud metadata, and invalid protocols are blocked."""
    dangerous_urls = [
        "http://localhost:5000/spec.json",
        "http://127.0.0.1:8080/spec.json",
        "http://127.0.0.2/api.json",
        "http://0.0.0.0/spec.json",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/internal/spec.json",
        "http://172.16.1.100/spec.json",
        "http://192.168.1.1/router.json",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_flushall",
        "ftp://internal-server/spec.json"
    ]
    for url in dangerous_urls:
        is_safe, error = validate_remote_url_ssrf(url)
        assert not is_safe, f"SSRF Validator failed to block: {url}"
        assert error is not None

# 4. API IMPORT & SPECIFICATION VALIDATION TESTS
def test_spec_parser_valid_and_invalid():
    """Test JSON/YAML parsing on valid, invalid, empty, and malformed structures."""
    # Valid JSON
    p_json, fmt, err = safe_parse_spec_content(json.dumps(VALID_OAS3_SPEC))
    assert err is None
    assert fmt == 'json'

    # Valid YAML
    yaml_text = """
    openapi: "3.0.1"
    info:
      title: "Microservice YAML"
      version: "1.0.0"
    paths:
      /ping:
        get:
          summary: "Health Ping"
    """
    p_yaml, fmt_y, err_y = safe_parse_spec_content(yaml_text)
    assert err_y is None
    assert fmt_y == 'yaml'

    # Empty content
    _, _, err_empty = safe_parse_spec_content("")
    assert "empty" in err_empty.lower()

    # Malformed JSON
    _, _, err_malformed = safe_parse_spec_content("{openapi: 3.0, broken json")
    assert err_malformed is not None

# 5. API DISCOVERY & DATABASE PERSISTENCE
def test_api_discovery_and_inventory(qa_client):
    """Test importing an OpenAPI spec and ensuring API and Endpoint records are saved in DB."""
    # Login
    qa_client.post('/register', json={
        'username': 'devops_sec',
        'email': 'devops@bank.com',
        'password': 'Password123!'
    })

    # Preview Spec first
    res_prev = qa_client.post('/apis/preview', json={
        'source_type': 'raw_json',
        'raw_spec': json.dumps(VALID_OAS3_SPEC)
    })
    assert res_prev.status_code == 200
    prev_data = res_prev.get_json()['preview']
    assert prev_data['title'] == "Enterprise Banking API"
    assert prev_data['total_endpoints'] == 3

    # Import Spec
    res_import = qa_client.post('/apis/import', json={
        'raw_spec': json.dumps(VALID_OAS3_SPEC),
        'source_type': 'raw_json',
        'environment': 'production',
        'owner': 'Core Banking Team'
    })
    assert res_import.status_code == 200
    api_id = res_import.get_json()['api']['id']

    # Query API detail
    res_detail = qa_client.get(f'/apis/{api_id}')
    assert res_detail.status_code == 200
    detail = res_detail.get_json()
    assert detail['api']['name'] == "Enterprise Banking API"
    assert len(detail['endpoints']) == 3

# 6. SCAN LIFECYCLE & SECURITY TESTING ENGINE
def test_scan_execution_and_findings(qa_client):
    """Test launching a security scan, transitioning states, generating findings, and computing posture."""
    qa_client.post('/register', json={
        'username': 'auditor_lead',
        'email': 'auditor@bank.com',
        'password': 'Password123!'
    })

    # Import API
    import_res = qa_client.post('/apis/import', json={
        'raw_spec': json.dumps(VALID_OAS3_SPEC),
        'source_type': 'raw_json'
    })
    api_id = import_res.get_json()['api']['id']

    # Launch Scan
    scan_res = qa_client.post('/api/scans/create', json={
        'api_id': api_id,
        'name': 'Q3 Production Security Probe',
        'profile': 'standard'
    })
    assert scan_res.status_code == 200
    scan_id = scan_res.get_json()['scan']['id']

    # Verify Scan Details & Test Traces
    res_scan = qa_client.get(f'/api/scans/{scan_id}')
    assert res_scan.status_code == 200
    scan_info = res_scan.get_json()
    assert scan_info['scan']['status'] == 'completed'
    assert len(scan_info['tests']) > 0
    assert len(scan_info['findings']) > 0

    # Verify Findings List
    res_findings = qa_client.get('/api/findings/list')
    assert res_findings.status_code == 200
    findings_data = res_findings.get_json()
    assert findings_data['count'] > 0
    
    first_finding = findings_data['findings'][0]
    finding_id = first_finding['id']

    # Inspect Individual Finding Details
    res_f_detail = qa_client.get(f'/api/findings/{finding_id}')
    assert res_f_detail.status_code == 200
    f_detail = res_f_detail.get_json()
    assert f_detail['finding']['cvss_score'] > 0
    assert f_detail['finding']['remediation'] != ""

    # Test Finding Lifecycle Status Transition (e.g. mark Verified -> Resolved)
    res_trans = qa_client.post(f'/api/findings/{finding_id}/status', json={
        'lifecycle_state': 'Resolved',
        'comment': 'Validated fix applied in commit #892f3a'
    })
    assert res_trans.status_code == 200
    assert res_trans.get_json()['finding']['lifecycle_state'] == 'Resolved'

# 7. REGRESSION DETECTION TEST
def test_regression_detection(qa_client):
    """Test that resolving a finding and re-running a scan marks the finding as Reopened."""
    qa_client.post('/register', json={
        'username': 'regression_tester',
        'email': 'reg@bank.com',
        'password': 'Password123!'
    })

    # 1. Import API
    import_res = qa_client.post('/apis/import', json={
        'raw_spec': json.dumps(VALID_OAS3_SPEC),
        'source_type': 'raw_json'
    })
    api_id = import_res.get_json()['api']['id']

    # 2. Run initial scan
    s1 = qa_client.post('/api/scans/create', json={'api_id': api_id, 'name': 'Scan 1'}).get_json()['scan']

    # 3. Mark all findings as Resolved
    findings = qa_client.get('/api/findings/list').get_json()['findings']
    for f in findings:
        qa_client.post(f'/api/findings/{f["id"]}/status', json={
            'lifecycle_state': 'Resolved',
            'comment': 'Marked resolved for regression test'
        })

    # Verify resolved
    resolved_count = len([f for f in qa_client.get('/api/findings/list').get_json()['findings'] if f['lifecycle_state'] == 'Resolved'])
    assert resolved_count == len(findings)

    # 4. Re-run scan against the same API
    s2 = qa_client.post('/api/scans/create', json={'api_id': api_id, 'name': 'Scan 2'}).get_json()['scan']

    # 5. Check if previously resolved findings are now marked Reopened (Regression!)
    findings_after = qa_client.get('/api/findings/list').get_json()['findings']
    reopened = [f for f in findings_after if f['lifecycle_state'] == 'Reopened']
    assert len(reopened) > 0, "Expected regression detection to reopen previously resolved findings"

# 8. API DRIFT DETECTION TEST
def test_drift_detection(qa_client):
    """Test drift detection on endpoint additions, removals, and auth requirement changes."""
    qa_client.post('/register', json={
        'username': 'drift_officer',
        'email': 'drift_officer@bank.com',
        'password': 'Password123!'
    })

    # Baseline Spec
    qa_client.post('/apis/import', json={
        'name': 'Drift Test API',
        'raw_spec': json.dumps(VALID_OAS3_SPEC),
        'source_type': 'raw_json',
        'environment': 'staging'
    })

    # Modified Spec
    MODIFIED_SPEC = {
        "openapi": "3.0.0",
        "info": {"title": "Drift Test API", "version": "1.2.0"},
        "servers": [{"url": "https://api.bank.enterprise.com/v1"}],
        "paths": {
            "/accounts/{accountId}": {
                "get": {
                    "summary": "Retrieve account details",
                    "parameters": [{"name": "accountId", "in": "path"}],
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/new-billing-webhook": {
                "post": {
                    "summary": "Undocumented payment webhook",
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    }

    reimport_res = qa_client.post('/apis/import', json={
        'name': 'Drift Test API',
        'raw_spec': json.dumps(MODIFIED_SPEC),
        'source_type': 'raw_json',
        'environment': 'staging'
    })
    assert reimport_res.status_code == 200
    assert reimport_res.get_json()['drift_events_count'] > 0

    drift_res = qa_client.get('/apis/drift/events')
    assert drift_res.status_code == 200
    events = drift_res.get_json()['events']
    assert any(e['change_type'] == 'ENDPOINT_ADDED' for e in events)
    assert any(e['change_type'] == 'ENDPOINT_REMOVED' for e in events)

# 9. CONTINUOUS MONITORING & REPORTS
def test_monitoring_and_reports(qa_client):
    """Test creating monitoring schedules and generating exportable reports."""
    qa_client.post('/register', json={
        'username': 'compliance_lead',
        'email': 'comp@bank.com',
        'password': 'Password123!'
    })

    import_res = qa_client.post('/apis/import', json={
        'raw_spec': json.dumps(VALID_OAS3_SPEC),
        'source_type': 'raw_json'
    })
    api_id = import_res.get_json()['api']['id']

    # Create Monitoring Job
    job_res = qa_client.post('/api/monitoring/jobs', json={
        'api_id': api_id,
        'name': 'Daily Automated Probe',
        'interval_minutes': 1440,
        'scan_profile': 'standard'
    })
    assert job_res.status_code == 200
    job_id = job_res.get_json()['job']['id']

    # Trigger Run-Now
    run_res = qa_client.post(f'/api/monitoring/jobs/{job_id}/run-now')
    assert run_res.status_code == 200

    # Verify Report was generated
    rep_list = qa_client.get('/api/reports/list')
    assert rep_list.status_code == 200
    reports = rep_list.get_json()['reports']
    assert len(reports) > 0
    report_id = reports[0]['id']

    # Export Markdown
    exp_md = qa_client.get(f'/api/reports/{report_id}/export?format=markdown')
    assert exp_md.status_code == 200
    assert b"SentinelAPI Security Assessment Report" in exp_md.data

    # Export JSON
    exp_json = qa_client.get(f'/api/reports/{report_id}/export?format=json')
    assert exp_json.status_code == 200
    assert 'report' in exp_json.get_json()

# 10. DATABASE PERSISTENCE ACROSS RESTARTS
def test_database_persistence_across_restarts():
    """Verify that writing data, closing DB connection, and reopening preserves all records."""
    temp_dir = tempfile.mkdtemp()
    db_path = Path(temp_dir) / "persistent_test.db"
    db_uri = f"sqlite:///{db_path}"

    try:
        # 1. Initialize DB and insert records
        init_db(db_uri)
        db1 = get_db()
        user = User(username='persist_user', email='persist@test.com', password_hash='hash123', role='Owner')
        db1.add(user)
        db1.commit()
        saved_user_id = user.id

        api = API(user_id=saved_user_id, name='Persisted API', version='1.0.0', base_url='https://persist.test', source_type='raw_json')
        db1.add(api)
        db1.commit()
        saved_api_id = api.id

        # 2. Close first connection session
        close_db()

        # 3. Simulate Application Restart (re-initializing engine & scoped session)
        init_db(db_uri)
        db2 = get_db()

        loaded_user = db2.query(User).filter_by(id=saved_user_id).first()
        assert loaded_user is not None
        assert loaded_user.username == 'persist_user'

        loaded_api = db2.query(API).filter_by(id=saved_api_id).first()
        assert loaded_api is not None
        assert loaded_api.name == 'Persisted API'

        close_db()
    finally:
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
            os.rmdir(temp_dir)
        except Exception:
            pass
