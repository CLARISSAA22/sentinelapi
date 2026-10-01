import os
import re
import sys
import json

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath('.'))

import app

def run_comprehensive_audit():
    print("============================================================")
    print("SENTINELAPI UI/UX & FUNCTIONAL INSPECTION AUDIT")
    print("============================================================")
    
    app_instance = app.create_app('testing')
    client = app_instance.test_client()
    
    # 1. Register & Login
    client.post('/register', data={
        'username': 'sec_auditor',
        'email': 'auditor@sentinel.io',
        'password': 'Password123!',
        'role': 'Administrator'
    }, follow_redirects=True)
    
    # 2. Check all 20 required pages
    required_pages = [
        ('1. Landing Page', '/'),
        ('2. Login', '/login'),
        ('3. Registration', '/register'),
        ('4. Dashboard', '/dashboard'),
        ('5. API Inventory', '/api-inventory'),
        ('6. API Discovery', '/api-import'),
        ('7. API Import', '/api-import'),
        ('8. Security Scans', '/scans'),
        ('9. Scan Details', '/scans/audit-scan-id-placeholder'),
        ('10. Findings', '/findings'),
        ('11. Finding Details', '/findings/audit-finding-id-placeholder'),
        ('12. Reports', '/reports'),
        ('13. Monitoring', '/monitoring'),
        ('14. API Dependencies', '/dependencies'),
        ('15. Drift Detection', '/drift'),
        ('16. Team', '/team'),
        ('17. Integrations', '/integrations'),
        ('18. Settings', '/settings'),
        ('19. Profile', '/profile'),
        ('20. Logout', '/logout')
    ]
    
    print("\n--- 1. 20 REQUIRED PAGES AUDIT ---")
    page_results = {}
    for name, path in required_pages:
        res = client.get(path, follow_redirects=False)
        status = res.status_code
        loc = res.headers.get('Location', '')
        page_results[name] = (path, status, loc)
        status_str = "OK (200)" if status == 200 else ("REDIRECT (302)" if status == 302 else f"HTTP {status}")
        print(f"{name:25} | Path: {path:35} | {status_str} {('-> ' + loc) if loc else ''}")

    # 3. Check Icon System Consistency
    print("\n--- 2. ICON SYSTEM AUDIT ---")
    with open('static/js/icons.js', 'r', encoding='utf-8') as f:
        icons_js = f.read()
    defined_icons = set(re.findall(r"'([a-z0-9\-]+)':", icons_js))
    
    used_icons = {}
    template_files = []
    for root, _, files in os.walk('templates'):
        for file in files:
            if file.endswith('.html'):
                p = os.path.join(root, file)
                template_files.append(p)
                with open(p, 'r', encoding='utf-8') as f:
                    c = f.read()
                    icons_found = re.findall(r'data-icon=["\']([a-z0-9\-]+)["\']', c)
                    for ic in icons_found:
                        used_icons.setdefault(ic, []).append(file)
    
    for root, _, files in os.walk('static/js'):
        for file in files:
            if file.endswith('.js'):
                p = os.path.join(root, file)
                with open(p, 'r', encoding='utf-8') as f:
                    c = f.read()
                    icons_found = re.findall(r'getIconSvg\(["\']([a-z0-9\-]+)["\']', c)
                    for ic in icons_found:
                        used_icons.setdefault(ic, []).append(file)
                    sev_icons = re.findall(r'sevIcon\s*=\s*["\']([a-z0-9\-]+)["\']', c)
                    for ic in sev_icons:
                        used_icons.setdefault(ic, []).append(file)

    missing_icons = set(used_icons.keys()) - defined_icons
    print(f"Total Unique Icons Defined in icons.js: {len(defined_icons)}")
    print(f"Total Unique Icons Used Across UI: {len(used_icons)}")
    print(f"Missing / Undefined Icons Used in UI: {missing_icons if missing_icons else 'None (0 missing)'}")
    if missing_icons:
        for mi in missing_icons:
            print(f"  -> Undefined icon '{mi}' referenced in: {set(used_icons[mi])}")

    # 4. Check Navigation and Sidebar Links
    print("\n--- 3. NAVIGATION & SIDEBAR AUDIT ---")
    with open('templates/base.html', 'r', encoding='utf-8') as f:
        base_html = f.read()
    sidebar_links = re.findall(r'href="([^"]+)"\s+class="nav-item', base_html)
    print(f"Sidebar Navigation Items: {len(sidebar_links)} links")

    # 5. Check Modals, Form Inputs & Buttons across templates
    print("\n--- 4. MODALS & FORMS AUDIT ---")
    for tf in template_files:
        with open(tf, 'r', encoding='utf-8') as f:
            c = f.read()
            modals = re.findall(r'id=["\']([a-z0-9\-_]*modal[a-z0-9\-_]*)["\']', c, re.IGNORECASE)
            forms = re.findall(r'<form[^>]*>', c)
            buttons = re.findall(r'<button[^>]*>', c)
            textareas = re.findall(r'<textarea[^>]*>', c)
            inputs = re.findall(r'<input[^>]*>', c)
            if modals or forms or textareas:
                print(f"File: {os.path.basename(tf):20} | Modals: {len(modals):2} | Forms: {len(forms):2} | Inputs: {len(inputs):2} | Textareas: {len(textareas):2} | Buttons: {len(buttons):2}")

    # 6. Check End-to-End Workflow with Realistic API Spec
    print("\n--- 5. WORKFLOW & DATA INGESTION AUDIT ---")
    sample_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Core Banking Gateway", "version": "2.1.0"},
        "paths": {
            "/api/v2/accounts/{account_id}/balance": {
                "get": {
                    "summary": "Retrieve customer account balance",
                    "parameters": [{"name": "account_id", "in": "path", "required": True}],
                    "responses": {"200": {"description": "Balance response"}}
                }
            },
            "/api/v2/transfer": {
                "post": {
                    "summary": "Execute financial transfer",
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    "responses": {"200": {"description": "Transfer completed"}}
                }
            },
            "/api/v2/admin/debug-dump": {
                "get": {
                    "summary": "Internal memory dump and database config",
                    "responses": {"200": {"description": "Debug logs"}}
                }
            }
        }
    }
    
    # Ingest
    imp_res = client.post('/apis/import', json={
        'name': 'Core Banking Gateway',
        'source_type': 'raw_json',
        'raw_spec': json.dumps(sample_spec),
        'environment': 'Production',
        'base_url': 'https://bank.internal',
        'owner': 'Core FinTech Team'
    })
    print(f"API Import Response Status: {imp_res.status_code}")
    api_id = imp_res.json.get('api', {}).get('id') if imp_res.status_code == 200 else None
    
    if api_id:
        scan_res = client.post('/api/scans/create', json={
            'api_id': api_id,
            'name': 'Pre-Production Security Baseline',
            'profile': 'standard'
        })
        print(f"Scan Trigger Status: {scan_res.status_code}")
        scan_id = scan_res.json.get('scan', {}).get('id') if scan_res.status_code == 200 else None
        
        # Check scan details
        if scan_id:
            s_det = client.get(f'/api/scans/{scan_id}')
            print(f"Scan Details JSON Status: {s_det.status_code} | Tests Run: {len(s_det.json.get('tests', []))}")
            
        findings_res = client.get('/api/findings/list')
        findings_list = findings_res.json.get('findings', [])
        print(f"Findings Ingested & Calculated: {len(findings_list)}")
        
        # Test Report Generation
        rep_res = client.post('/api/reports/create', json={
            'api_id': api_id,
            'title': 'Executive Security Posture Audit',
            'format': 'JSON'
        }) if hasattr(client, 'post') else None
        
        # Check finding details page
        if findings_list:
            fid = findings_list[0]['id']
            f_page = client.get(f'/findings/{fid}')
            print(f"Finding Details Page HTML Status: {f_page.status_code}")

    print("\n============================================================")
    print("AUDIT EXECUTION COMPLETE")
    print("============================================================")

if __name__ == '__main__':
    run_comprehensive_audit()
