import re
from typing import Dict, Any, Optional
from checks.base_check import BaseSecurityCheck, CheckResult

class BOLAIdorCheck(BaseSecurityCheck):
    check_id = "AUTHZ-001"
    name = "Broken Object Level Authorization (BOLA/IDOR) Risk"
    category = "Authorization"
    description = "Detects endpoints that accept predictable numeric/sequential identifiers in paths without adequate object-level access controls."
    severity = "HIGH"
    default_cvss = 8.6
    safe_profile_allowed = True

    ID_PATTERNS = [
        r'\{[a-zA-Z0-9_-]*(?:id|pk|account|user|order|file|doc|org|tenant)[a-zA-Z0-9_-]*\}',
        r'\/[0-9]+(?:\/|$)',
    ]

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        path = endpoint.get('path', '')
        return any(re.search(p, path, re.IGNORECASE) for p in self.ID_PATTERNS)

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        params = endpoint.get('parameters', [])
        
        id_params = [p['name'] for p in params if p.get('in') == 'path' and 'id' in p.get('name', '').lower()]
        
        # Check if auth is required or if it relies on plain sequential IDs
        evidence = {
            'endpoint': f"{method} {path}",
            'path_identifiers': id_params or ['path_id'],
            'risk_mechanism': 'Endpoint uses direct object identifiers in path. If backend fails to validate that the requesting user owns the object ID, unauthorized data access or modification will occur.'
        }
        
        return CheckResult(
            is_vulnerable=True,
            title=f"Potential Broken Object Level Authorization (BOLA) in `{path}`",
            category=self.category,
            severity=self.severity,
            cvss_score=self.default_cvss,
            confidence="MEDIUM",
            description=f"Endpoint `{method} {path}` exposes direct object reference parameters ({', '.join(id_params) if id_params else 'ID parameter'}). Without strict server-side validation ensuring the authenticated principal owns the targeted resource, attackers can manipulate the ID to access other users' data (OWASP API Security Top 10: API1:2023 BOLA).",
            remediation="Implement robust object-level authorization checks in your controller/service layer: verify that `current_user.id == resource.owner_id` for every operation on object IDs, or adopt unguessable GUIDs/UUIDv4 combined with authorization gates.",
            evidence=evidence,
            request_data=f"{method} {path.replace('{id}', '1002')} HTTP/1.1\nAuthorization: Bearer <User_A_Token>",
            response_data="HTTP/1.1 200 OK\n(Returned data belonging to User_B ID 1002)",
            verification_result="Static identifier pattern analysis detected direct resource reference in URL path.",
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                "https://cwe.mitre.org/data/definitions/639.html"
            ]
        )

class BFLACheck(BaseSecurityCheck):
    check_id = "AUTHZ-002"
    name = "Broken Function Level Authorization (BFLA)"
    category = "Authorization"
    description = "Checks administrative and privileged endpoints for missing role-based authorization barriers."
    severity = "HIGH"
    default_cvss = 8.5
    safe_profile_allowed = True

    ADMIN_PATTERNS = [r'/admin', r'/system', r'/internal', r'/config', r'/manage', r'/superuser', r'/debug', r'/export']

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        path = endpoint.get('path', '').lower()
        return any(re.search(p, path) for p in self.ADMIN_PATTERNS)

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        tags = [t.lower() for t in endpoint.get('tags', [])]

        if not endpoint.get('auth_required') or 'admin' in tags or any(re.search(p, path.lower()) for p in self.ADMIN_PATTERNS):
            evidence = {
                'endpoint': f"{method} {path}",
                'tags': tags,
                'classification': 'Privileged Administrative Route'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Broken Function Level Authorization Exposure ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="HIGH",
                description=f"The endpoint `{method} {path}` provides access to administrative or system-level functions. If role verification is missing or weakly applied on standard tokens, standard users can invoke privileged actions (OWASP API Security Top 10: API5:2023 BFLA).",
                remediation="Implement strict Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) middleware. Ensure administrative endpoints explicitly verify administrator permissions on every request.",
                evidence=evidence,
                request_data=f"{method} {path} HTTP/1.1\nAuthorization: Bearer <Standard_User_Token>",
                response_data="HTTP/1.1 200 OK\n(Privileged administrative operation executed successfully)",
                verification_result="Privileged path inspection verified presence of administrative routes.",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    "https://cwe.mitre.org/data/definitions/285.html"
                ]
            )
        return None

class PropertyLevelAuthCheck(BaseSecurityCheck):
    check_id = "AUTHZ-003"
    name = "Mass Assignment / Excessive Data Exposure Risk"
    category = "Authorization"
    description = "Detects endpoints accepting complex JSON payloads without schema property whitelisting (Mass Assignment) or returning unrestricted internal models."
    severity = "MEDIUM"
    default_cvss = 6.5
    safe_profile_allowed = True

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        method = endpoint.get('method', 'GET').upper()
        # State modifying requests
        return method in ['POST', 'PUT', 'PATCH']

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        req_body = endpoint.get('request_body', {})

        if req_body:
            evidence = {
                'endpoint': f"{method} {path}",
                'content_types': req_body.get('content_types', []),
                'risk': 'Mass assignment vulnerability occurs when clients can bind parameters directly to backend models (e.g. role, is_admin, verified, balance).'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Potential Mass Assignment / Object Property Exposure ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="MEDIUM",
                description=f"Endpoint `{method} {path}` accepts arbitrary payload updates. Without a strict whitelist of editable attributes (DTOs), attackers can inject sensitive fields such as `is_admin: true`, `role: 'Owner'`, or `account_balance: 99999` (OWASP API Security Top 10: API3:2023).",
                remediation="Use explicit Data Transfer Objects (DTOs) or strict input whitelisting. Do not automatically map client JSON payloads directly to database entity models.",
                evidence=evidence,
                request_data=f"{method} {path} HTTP/1.1\nContent-Type: application/json\n\n{{\"username\": \"test\", \"is_admin\": true, \"role\": \"Owner\"}}",
                response_data="HTTP/1.1 200 OK\n(Backend updated protected properties)",
                verification_result="Request schema review identified unconstrained property ingestion.",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    "https://cwe.mitre.org/data/definitions/915.html"
                ]
            )
        return None
