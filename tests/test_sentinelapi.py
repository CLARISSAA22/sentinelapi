import pytest
import json
from app import create_app
from database.database import get_db, init_db
from database.models import User, API, APIEndpoint, Scan, Finding, APIDriftEvent
from api.validators import validate_remote_url_ssrf, safe_parse_spec_content
from api.importer import OpenAPIImporter
from api.discovery import APIDiscoveryManager
from scanner.scanner_engine import ScannerEngine
from scanner.risk_engine import RiskEngine
from scanner.scan_context import ScanContext
from checks.authentication import MissingAuthCheck, WeakAuthSchemeCheck
from checks.authorization import BOLAIdorCheck
from checks.injection import SQLInjectionCheck
from checks.secrets import SecretExposureCheck

SAMPLE_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Core Payment API",
        "version": "1.0.0",
        "description": "Production Payment and Account Management API"
    },
    "servers": [{"url": "https://api.payments.enterprise.com/v1"}],
    "paths": {
        "/users/{userId}": {
            "get": {
                "summary": "Get user profile",
                "parameters": [
                    {"name": "userId", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "User profile data"}}
            }
        },
        "/payments/checkout": {
            "post": {
                "summary": "Process customer checkout",
                "parameters": [
                    {"name": "search_query", "in": "query", "schema": {"type": "string"}}
                ],
                "requestBody": {
                    "content": {"application/json": {"schema": {"type": "object"}}}
                },
                "responses": {"200": {"description": "Payment receipt"}}
            }
        }
    }
}

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        with app.app_context():
            init_db('sqlite:///:memory:')
            yield client

def test_ssrf_protection():
    """Verify SSRF validator blocks localhost, private IPs, cloud metadata, and invalid schemes."""
    # Localhost & Loopback
    is_safe, err = validate_remote_url_ssrf("http://127.0.0.1/api.json")
    assert not is_safe
    assert "local or internal address" in err or "private/internal" in err

    # Cloud metadata (AWS / GCP / Azure)
    is_safe, err = validate_remote_url_ssrf("http://169.254.169.254/latest/meta-data/")
    assert not is_safe

    # Non-HTTP schemes
    is_safe, err = validate_remote_url_ssrf("file:///etc/passwd")
    assert not is_safe
    assert "Unsupported scheme" in err

def test_safe_spec_parser():
    """Verify safe parsing of JSON and YAML strings."""
    json_str = json.dumps(SAMPLE_OPENAPI_SPEC)
    parsed, fmt, err = safe_parse_spec_content(json_str)
    assert err is None
    assert fmt == 'json'
    assert parsed['info']['title'] == "Core Payment API"

    yaml_str = """
    openapi: 3.0.0
    info:
      title: YAML API
      version: 2.0.0
    paths:
      /ping:
        get:
          summary: Health check
    """
    parsed_y, fmt_y, err_y = safe_parse_spec_content(yaml_str)
    assert err_y is None
    assert fmt_y == 'yaml'
    assert parsed_y['info']['title'] == "YAML API"

def test_user_registration_and_login(client):
    """Test full authentication workflow: registration, login, session verification."""
    # Register
    res = client.post('/register', json={
        'username': 'sec_lead',
        'email': 'lead@sentinelapi.local',
        'password': 'StrongPassword123!',
        'role': 'Administrator'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True

    # Check authenticated session
    me_res = client.get('/api/auth/me')
    assert me_res.status_code == 200
    assert me_res.get_json()['user']['username'] == 'sec_lead'

    # Logout
    logout_res = client.get('/logout')
    assert logout_res.status_code in [200, 302]

    # Attempt opening dashboard after logout -> redirect to login
    dash_res = client.get('/dashboard')
    assert dash_res.status_code == 302
    assert '/login' in dash_res.headers['Location']

def test_openapi_import_and_discovery(client):
    """Test importing OpenAPI spec and discovering endpoints in database."""
    # Register and log in
    client.post('/register', json={
        'username': 'analyst1',
        'email': 'analyst1@sentinelapi.local',
        'password': 'Password123!',
        'role': 'Security Analyst'
    })

    # Import spec
    import_res = client.post('/apis/import', json={
        'raw_spec': json.dumps(SAMPLE_OPENAPI_SPEC),
        'source_type': 'upload_json',
        'environment': 'production',
        'owner': 'SecOps'
    })
    assert import_res.status_code == 200
    data = import_res.get_json()
    assert data['success'] is True
    api_id = data['api']['id']

    # Verify inventory
    list_res = client.get(f'/apis/{api_id}')
    assert list_res.status_code == 200
    api_detail = list_res.get_json()
    assert len(api_detail['endpoints']) == 2

def test_modular_security_checks():
    """Verify that modular security checks detect vulnerabilities accurately."""
    context = ScanContext(api_id="test-api", scan_id="test-scan", base_url="https://api.payments.enterprise.com")

    # Missing Auth Check
    auth_check = MissingAuthCheck()
    sensitive_ep = {
        'method': 'POST',
        'path': '/payments/checkout',
        'auth_required': False,
        'auth_types': []
    }
    assert auth_check.can_run(sensitive_ep, context) is True
    res = auth_check.run(sensitive_ep, context)
    assert res is not None
    assert res.is_vulnerable is True
    assert res.category == "Authentication"

    # BOLA / IDOR Check
    bola_check = BOLAIdorCheck()
    bola_ep = {
        'method': 'GET',
        'path': '/users/{userId}',
        'parameters': [{'name': 'userId', 'in': 'path'}]
    }
    assert bola_check.can_run(bola_ep, context) is True
    bola_res = bola_check.run(bola_ep, context)
    assert bola_res is not None
    assert bola_res.is_vulnerable is True

def test_full_scan_lifecycle_and_findings(client):
    """Test complete scanning execution, finding generation, and dashboard statistics."""
    # Register & Login
    client.post('/register', json={
        'username': 'sec_auditor',
        'email': 'auditor@sentinelapi.local',
        'password': 'Password123!',
        'role': 'Security Analyst'
    })

    # Import API
    import_res = client.post('/apis/import', json={
        'raw_spec': json.dumps(SAMPLE_OPENAPI_SPEC),
        'source_type': 'upload_json',
        'environment': 'production'
    })
    api_id = import_res.get_json()['api']['id']

    # Execute Scan
    scan_res = client.post('/api/scans/create', json={
        'api_id': api_id,
        'name': 'Full Regression Scan',
        'profile': 'standard'
    })
    assert scan_res.status_code == 200
    scan_data = scan_res.get_json()
    assert scan_data['success'] is True
    scan_id = scan_data['scan']['id']

    # Inspect Scan Details
    details_res = client.get(f'/api/scans/{scan_id}')
    assert details_res.status_code == 200
    scan_details = details_res.get_json()
    assert scan_details['scan']['status'] == 'completed'
    assert len(scan_details['findings']) > 0

    # Verify Findings API
    findings_res = client.get('/api/findings/list')
    assert findings_res.status_code == 200
    f_data = findings_res.get_json()
    assert f_data['count'] > 0
    assert f_data['posture']['score'] < 100.0

    # Verify Dashboard Metrics
    dash_res = client.get('/api/dashboard/stats')
    assert dash_res.status_code == 200
    m = dash_res.get_json()['metrics']
    assert m['total_apis'] == 1
    assert m['total_endpoints'] == 2
    assert m['total_scans'] == 1
    assert m['active_findings'] > 0

def test_api_drift_detection(client):
    """Test detecting API drift when spec changes on re-import."""
    client.post('/register', json={
        'username': 'drift_tester',
        'email': 'drift@sentinelapi.local',
        'password': 'Password123!',
        'role': 'Security Analyst'
    })

    # Initial Import
    client.post('/apis/import', json={
        'raw_spec': json.dumps(SAMPLE_OPENAPI_SPEC),
        'source_type': 'upload_json',
        'environment': 'production'
    })

    # Updated Spec with added and removed endpoints
    UPDATED_SPEC = {
        "openapi": "3.0.0",
        "info": {"title": "Core Payment API", "version": "1.1.0"},
        "servers": [{"url": "https://api.payments.enterprise.com/v1"}],
        "paths": {
            "/users/{userId}": {
                "get": {
                    "summary": "Get user profile",
                    "parameters": [{"name": "userId", "in": "path", "required": True}],
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/new-admin-route": {
                "delete": {
                    "summary": "New Admin Purge",
                    "responses": {"200": {"description": "Deleted"}}
                }
            }
        }
    }

    reimport_res = client.post('/apis/import', json={
        'raw_spec': json.dumps(UPDATED_SPEC),
        'source_type': 'upload_json',
        'environment': 'production'
    })
    assert reimport_res.status_code == 200
    assert reimport_res.get_json()['drift_events_count'] > 0

    # Verify drift events API
    drift_res = client.get('/apis/drift/events')
    assert drift_res.status_code == 200
    events = drift_res.get_json()['events']
    assert any(e['change_type'] == 'ENDPOINT_ADDED' for e in events)
    assert any(e['change_type'] == 'ENDPOINT_REMOVED' for e in events)
