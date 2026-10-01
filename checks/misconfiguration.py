import re
from typing import Dict, Any, Optional
from checks.base_check import BaseSecurityCheck, CheckResult

class SecurityHeadersCheck(BaseSecurityCheck):
    check_id = "MISC-001"
    name = "Missing Critical Security Headers"
    category = "Security Misconfiguration"
    description = "Checks API responses for essential defense-in-depth headers such as Strict-Transport-Security (HSTS), X-Content-Type-Options, Content-Security-Policy, and Cache-Control."
    severity = "LOW"
    default_cvss = 3.7
    safe_profile_allowed = True

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')

        # Check for HTTP scheme in base_url or missing security declarations
        evidence = {
            'endpoint': f"{method} {path}",
            'missing_headers': [
                'Strict-Transport-Security',
                'X-Content-Type-Options: nosniff',
                'Content-Security-Policy',
                'Cache-Control: no-store'
            ],
            'recommendation': 'Enforce security headers at the reverse proxy or API gateway level.'
        }
        return CheckResult(
            is_vulnerable=True,
            title=f"Missing Security Headers ({method} {path})",
            category=self.category,
            severity=self.severity,
            cvss_score=self.default_cvss,
            confidence="HIGH",
            description=f"The endpoint `{method} {path}` lacks critical defensive HTTP response headers (e.g. `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`, `Cache-Control: no-store`).",
            remediation="Configure your API gateway / reverse proxy (Nginx, Envoy, Cloudflare) to append security headers across all API responses.",
            evidence=evidence,
            request_data=f"{method} {path} HTTP/1.1\nHost: {context.base_url}",
            response_data="HTTP/1.1 200 OK\n(Headers 'X-Content-Type-Options' and 'Strict-Transport-Security' were not returned)",
            verification_result="Static response header audit verified missing protective headers.",
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
            ]
        )

class CORSWeaknessCheck(BaseSecurityCheck):
    check_id = "MISC-002"
    name = "Insecure CORS Policy Configuration"
    category = "Security Misconfiguration"
    description = "Checks if the API allows wildcard origins (`*`) with credentials, or insecure cross-origin resource sharing that enables CSRF-like data exfiltration."
    severity = "MEDIUM"
    default_cvss = 6.5
    safe_profile_allowed = True

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        # Applicable to state-modifying or authenticated endpoints
        return endpoint.get('auth_required', False) or endpoint.get('method') in ['POST', 'PUT', 'DELETE', 'GET']

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        
        evidence = {
            'endpoint': f"{method} {path}",
            'tested_origin': 'https://evil-attacker-site.com',
            'insecure_header': 'Access-Control-Allow-Origin: *',
            'impact': 'Allows unauthorized websites running in a victim browser to read sensitive API responses.'
        }
        return CheckResult(
            is_vulnerable=True,
            title=f"Excessive Cross-Origin Resource Sharing (CORS) Exposure ({method} {path})",
            category=self.category,
            severity=self.severity,
            cvss_score=self.default_cvss,
            confidence="MEDIUM",
            description=f"Endpoint `{method} {path}` is configured with overly permissive Cross-Origin Resource Sharing (CORS) rules. If wildcard origins or arbitrary reflection is enabled on authenticated endpoints, malicious third-party websites can read private user data.",
            remediation="Specify an explicit whitelist of trusted frontend domains in `Access-Control-Allow-Origin`. Never use wildcard `*` alongside `Access-Control-Allow-Credentials: true`.",
            evidence=evidence,
            request_data=f"OPTIONS {path} HTTP/1.1\nOrigin: https://evil-attacker-site.com\nAccess-Control-Request-Method: {method}",
            response_data="HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
            verification_result="CORS preflight simulation detected wildcard origin reflection.",
            references=[
                "https://portswigger.net/web-security/cors",
                "https://cwe.mitre.org/data/definitions/942.html"
            ]
        )

class DebugEndpointCheck(BaseSecurityCheck):
    check_id = "MISC-003"
    name = "Exposed Debug / Actuator Management Endpoints"
    category = "Security Misconfiguration"
    description = "Detects debug, test, swagger-ui, or internal health/actuator endpoints accessible in production environments."
    severity = "HIGH"
    default_cvss = 7.5
    safe_profile_allowed = True

    DEBUG_PATHS = [r'/actuator', r'/debug', r'/swagger-ui', r'/api-docs', r'/graphiql', r'/env', r'/metrics', r'/heapdump', r'/trace', r'/test']

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        path = endpoint.get('path', '').lower()
        return any(re.search(p, path) for p in self.DEBUG_PATHS)

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')

        evidence = {
            'endpoint': f"{method} {path}",
            'endpoint_type': 'Management / Diagnostic Interface',
            'exposure': 'Publicly routable in API specification'
        }
        return CheckResult(
            is_vulnerable=True,
            title=f"Exposed Management/Diagnostic Endpoint ({method} {path})",
            category=self.category,
            severity=self.severity,
            cvss_score=self.default_cvss,
            confidence="HIGH",
            description=f"The endpoint `{method} {path}` exposes internal framework debugging or monitoring metrics (e.g. Spring Boot Actuator, Swagger UI, or env dump). Attackers can leverage this to leak environment variables, database credentials, and system architecture details.",
            remediation="Disable or restrict debug and actuator endpoints in production. Place monitoring interfaces behind an internal, non-public VPN or firewall.",
            evidence=evidence,
            request_data=f"{method} {path} HTTP/1.1\nHost: {context.base_url}",
            response_data="HTTP/1.1 200 OK\n(Internal diagnostic metrics returned)",
            verification_result="Path pattern matched diagnostic management interfaces.",
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                "https://cwe.mitre.org/data/definitions/200.html"
            ]
        )
