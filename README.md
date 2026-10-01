# SentinelAPI — Production-Grade API Security & Vulnerability Management Platform

SentinelAPI is an enterprise-grade API Security Assessment, Vulnerability Detection, Risk Quantification, and Continuous Security Monitoring platform built with Python, Flask, SQLite, and vanilla HTML5/CSS3/JavaScript.

---

## Key Capabilities

1. **API Ingestion & Multi-Method Discovery**
   - Ingest OpenAPI 3.x and Swagger 2.0 specifications via JSON file upload, YAML file upload, raw JSON/YAML pasting, or remote spec URLs.
   - Built-in multi-layered **SSRF Protection** blocking loopbacks, RFC1918 private subnets, link-local addresses, and cloud metadata instances (`169.254.169.254`).
   - Interactive visual specification preview before committing into inventory.

2. **Unified API Asset Inventory**
   - Track microservices, routes, parameters, HTTP methods, headers, schemas, and authentication declarations.
   - Endpoint catalog with risk ratings and last-tested timestamps.

3. **Modular Security Testing Engine**
   - **OWASP API Security Top 10** test coverage:
     - Broken Object Level Authorization (BOLA / IDOR)
     - Broken Function Level Authorization (BFLA)
     - Missing Authentication & Weak Schemes (Token in URL Query)
     - Mass Assignment & Broken Property Level Authorization
     - SQL Injection, OS Command Injection & NoSQL Operator Injection
     - Missing Security Headers (HSTS, CSP, X-Content-Type-Options)
     - Cross-Origin Resource Sharing (CORS) Misconfigurations
     - Sensitive Secret & Token Leaks (AWS, JWT, DB URIs)
     - PII & Privacy Leaks (SSN, Passwords, Card Numbers)
     - Rate Limiting & Resource Exhaustion / Unbounded Pagination
   - **Verification Engine**: Compares baseline responses against test mutations to reduce false positives.
   - **Profiles**: Safe Mode, Standard Scan, Authenticated Scan, and Advanced Scan.

4. **Vulnerability & Finding Lifecycle Management**
   - Human-readable unique finding identifiers (`SEC-0001`, `SEC-0002`).
   - CVSS v3.1 scoring, confidence ratings, and full request/response evidence capture.
   - Lifecycle progression: `New` &rarr; `Detected` &rarr; `Verified` &rarr; `Acknowledged` &rarr; `Remediated` &rarr; `Resolved`.
   - **Regression Detection**: Automatically reopens previously resolved findings if rediscovered during new scans.

5. **Schema Drift Detection**
   - Track additions, deletions, method adjustments, and authentication drift between specification revisions.

6. **Executive Security Dashboard & Reporting**
   - Real metrics pulled directly from SQLite database without mock or fake statistics.
   - Security Posture Grade (A–F) and score calculation (0–100).
   - Export executive summaries and technical audit findings in Markdown (.md) and JSON formats.

7. **Enterprise Role-Based Access Control (RBAC) & Audit Logs**
   - Granular roles: `Owner`, `Administrator`, `Security Analyst`, `Viewer`.
   - Tamper-resistant immutable audit logs tracking logins, imports, scans, finding state updates, and configuration changes.

---

## Directory Architecture

```
SentinelAPI/
├── app.py                      # Application entrypoint & dashboard API
├── config.py                   # Centralized configuration & environment bindings
├── requirements.txt            # Python dependencies
├── .env.example                # Example environment variables
├── .gitignore                  # Git ignore rules
│
├── database/
│   ├── database.py             # Database engine & scoped session initialization
│   └── models.py               # Complete SQLAlchemy relational models
│
├── auth/
│   ├── routes.py               # Login, register, logout, and password management
│   ├── security.py             # Scrypt hashing, secret masking, CSRF protection
│   └── services.py             # RBAC enforcement, session checks, audit logger
│
├── api/
│   ├── routes.py               # Inventory, import, drift, and dependencies routes
│   ├── importer.py             # OpenAPI 3.x and Swagger 2.0 parser & extractor
│   ├── discovery.py            # API asset persistence & drift detection
│   └── validators.py           # Multi-layered SSRF protection & safe YAML loader
│
├── scanner/
│   ├── scanner_engine.py       # Full scan lifecycle orchestrator
│   ├── scan_context.py         # Scan runtime state & profile definitions
│   ├── test_planner.py         # Intelligent check execution matrix builder
│   ├── verification.py         # Response comparison & false-positive reduction
│   ├── finding_engine.py       # Finding deduplication, evidence & regression tracker
│   └── risk_engine.py          # Posture grade, score & CVSS calculator
│
├── checks/
│   ├── __init__.py             # Security check registry
│   ├── base_check.py           # BaseSecurityCheck abstract class
│   ├── authentication.py       # Missing auth & weak parameter scheme checks
│   ├── authorization.py        # BOLA/IDOR, BFLA, and Mass Assignment checks
│   ├── injection.py            # SQLi, Command Injection, and NoSQL checks
│   ├── misconfiguration.py     # Security headers, CORS, and debug endpoint checks
│   ├── secrets.py              # Leaked API keys, AWS tokens & credentials
│   ├── pii.py                  # PII, SSN, and sensitive data checks
│   ├── rate_limiting.py        # Missing rate limiting & brute-force resistance
│   └── resource_consumption.py # Unbounded pagination & memory exhaustion checks
│
├── monitoring/
│   └── routes.py               # Continuous scheduled scanning & monitor triggers
│
├── reports/
│   ├── generator.py            # Markdown and JSON report generator
│   └── routes.py               # Report archive & export routes
│
├── integrations/
│   └── routes.py               # Settings, team RBAC, audit log viewer & integrations
│
├── templates/
│   ├── base.html               # Shared dark cybersecurity application shell
│   ├── index.html              # Marketing & product landing page
│   ├── login.html              # Secure login form
│   ├── register.html           # Account registration
│   ├── dashboard.html          # SOC posture dashboard with live DB metrics
│   ├── api_inventory.html      # Asset inventory & endpoint catalog
│   ├── api_import.html         # 5-method specification importer & previewer
│   ├── scan.html               # Scan launcher, active trace & history
│   ├── findings.html           # Filterable vulnerability findings table
│   ├── finding_details.html    # Deep-dive finding view with evidence & lifecycle updater
│   ├── drift.html              # API drift event timeline
│   ├── dependencies.html       # Dependency matrix & external integrations
│   ├── monitoring.html         # Continuous monitoring schedules
│   ├── reports.html            # Report archive & markdown export
│   └── settings.html           # RBAC, audit logs & ecosystem integrations
│
├── static/
│   ├── css/
│   │   ├── style.css           # Core dark theme, grid, typography & layout
│   │   ├── components.css      # Reusable buttons, cards, modals, tables & badges
│   │   └── responsive.css      # Mobile & tablet media queries
│   └── js/
│       └── main.js             # Modals, toasts, and unified API request handler
│
└── tests/
    └── test_sentinelapi.py     # Automated pytest test suite
```

---

## Getting Started

### 1. Installation

Ensure Python 3.10+ is installed on your system.

```bash
cd SentinelAPI
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

### 3. Run Automated Tests

```bash
python -m pytest tests/test_sentinelapi.py -v
```

---

## User Workflow Guide

1. **Create First Account:**
   - Click **Create Account** on the landing page.
   - Enter your username, email, and password (minimum 8 characters).
   - The first account registered automatically receives the `Owner` administrative role.

2. **Import an API:**
   - Navigate to **Import & Discovery** from the sidebar.
   - Choose your preferred method (Upload JSON/YAML, Paste Raw Spec, or Remote URL).
   - Click **Analyze & Preview Spec**. Inspect the discovered endpoints, base URL, and methods.
   - Click **Confirm & Import into Inventory**.

3. **Execute a Security Scan:**
   - Navigate to **Security Scans** and click **+ Launch Security Scan**.
   - Select your target API and preferred profile (e.g. Standard Scan or Safe Mode).
   - Click **Begin Security Scan**.
   - The system executes applicable checks, records test execution latencies, verifies findings, and computes risk scores.

4. **Investigate Findings:**
   - Navigate to **Findings & Risk**.
   - Click **Investigate** on any finding to review the attack evidence, raw request/response captures, verification notes, and remediation guidance.
   - Update the finding's lifecycle state (e.g. `Verified`, `Remediated`, `Resolved`) with analyst notes.

5. **Generate & Export Reports:**
   - Navigate to **Reports**.
   - View the synthesized executive summary or click **.MD** / **.JSON** to export the audit findings.

---

## Security Architecture & Defenses

- **Strict SSRF Defense**: Remote URLs are validated against private, link-local, loopback, multicast, and cloud metadata ranges before opening connections. Manual redirect inspection prevents bypass through redirect chaining.
- **Parameterized SQL**: All database operations utilize SQLAlchemy ORM with bound parameters.
- **Scrypt Password Hashing**: PBKDF2/Scrypt cryptographic salt & hashing protects user credentials.
- **Safe YAML Parser**: Enforces `yaml.safe_load` to prevent arbitrary code execution and object deserialization.
- **Tamper-Evident Audit Logging**: System-wide operations write to immutable audit log records.
- **Role-Based Access Control**: Backend authorization gates verify user roles on protected operations.

---

## Known Limitations

- **Protocol Scope**: Currently focuses on REST and OpenAPI/Swagger JSON and YAML specifications (gRPC and GraphQL introspection adapters can be plugged in via future protocol modules).
- **Automated Depth**: Dynamic fuzzing checks in Safe mode avoid destructive mutations to protect production systems; destructive testing requires explicit administrative authorization.
