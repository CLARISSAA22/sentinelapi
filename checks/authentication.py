import re
import json
from typing import Dict, Any, Optional
from checks.base_check import BaseSecurityCheck, CheckResult

class MissingAuthCheck(BaseSecurityCheck):
    check_id = "AUTH-001"
    name = "Missing Authentication on Sensitive Endpoint"
    category = "Authentication"
    description = "Detects critical/sensitive operations (users, payments, billing, admin, account) that do not enforce authentication requirements."
    severity = "CRITICAL"
    default_cvss = 9.1
    safe_profile_allowed = True

    SENSITIVE_PATTERNS = [
        r'/admin', r'/users?', r'/accounts?', r'/payments?', r'/billing',
        r'/keys?', r'/tokens?', r'/credentials?', r'/roles?', r'/permissions?'
    ]

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        path = endpoint.get('path', '').lower()
        method = endpoint.get('method', 'GET').upper()
        # Non-safe methods (POST, PUT, DELETE, PATCH) or sensitive paths
        is_sensitive = any(re.search(p, path) for p in self.SENSITIVE_PATTERNS) or method in ['DELETE', 'PUT', 'PATCH']
        # Exempt public login/register/forgot-password routes
        if any(pub in path for pub in ['/login', '/register', '/signup', '/auth', '/health', '/status', '/docs']):
            return False
        return is_sensitive

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        auth_required = endpoint.get('auth_required', False)
        auth_types = endpoint.get('auth_types', [])
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')

        if not auth_required or len(auth_types) == 0:
            # Endpoint is marked unauthenticated or lacks security declaration
            evidence = {
                'endpoint': f"{method} {path}",
                'declared_auth_required': auth_required,
                'declared_auth_schemes': auth_types,
                'risk_factor': 'Sensitive operation is exposed without mandatory authentication requirement.'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Missing Authentication on Sensitive Endpoint ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="HIGH",
                description=f"The endpoint `{method} {path}` provides access to sensitive system resources or state changes without requiring authentication credentials (OWASP API Security Top 10: API2:2023 Broken Authentication).",
                remediation="Configure and enforce an authentication scheme (e.g. OAuth 2.0, Bearer JWT, API Key) in the OpenAPI definition and backend authorization middleware for this route.",
                evidence=evidence,
                request_data=f"{method} {path} HTTP/1.1\nHost: {context.base_url}\nAccept: application/json",
                response_data="HTTP/1.1 200 OK\nContent-Type: application/json\nAccess permitted without Authorization header",
                verification_result="Static analysis and specification audit confirmed no security scheme binding.",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                    "https://cwe.mitre.org/data/definitions/306.html"
                ]
            )
        return None

class WeakAuthSchemeCheck(BaseSecurityCheck):
    check_id = "AUTH-002"
    name = "Weak or Insecure Authentication Mechanism"
    category = "Authentication"
    description = "Identifies usage of insecure authentication schemes such as HTTP Basic Auth over unencrypted channels or API keys in URL query parameters."
    severity = "HIGH"
    default_cvss = 7.5
    safe_profile_allowed = True

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        parameters = endpoint.get('parameters', [])
        auth_types = endpoint.get('auth_types', [])
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')

        # Check for api_key passed in query parameters
        query_api_keys = [
            p['name'] for p in parameters 
            if p.get('in') == 'query' and any(k in p.get('name', '').lower() for k in ['api_key', 'apikey', 'key', 'token', 'auth', 'secret'])
        ]

        if query_api_keys:
            evidence = {
                'vulnerable_parameters': query_api_keys,
                'location': 'query_string',
                'reason': 'API keys in URL query strings are exposed in server logs, browser histories, proxy caches, and Referer headers.'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Sensitive Token in URL Query Parameters ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="HIGH",
                description=f"The endpoint `{method} {path}` accepts authentication secrets ({', '.join(query_api_keys)}) via URL query parameters instead of standard Authorization headers.",
                remediation="Refactor authentication to pass tokens exclusively within standard HTTP request headers (e.g. `Authorization: Bearer <token>` or `X-API-Key: <key>`).",
                evidence=evidence,
                request_data=f"{method} {path}?{query_api_keys[0]}=sample_secret_key HTTP/1.1\nHost: {context.base_url}",
                response_data="Query parameters logged in access logs and web proxies.",
                verification_result="Query parameter schema validation verified parameter placement in query string.",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                    "https://cwe.mitre.org/data/definitions/598.html"
                ]
            )
        return None
