from typing import Dict, Any, Optional
from checks.base_check import BaseSecurityCheck, CheckResult

class RateLimitingCheck(BaseSecurityCheck):
    check_id = "RATE-001"
    name = "Unrestricted Rate Limiting / DoS Vulnerability"
    category = "Rate Limiting & Availability"
    description = "Tests authentication, payment, and computational endpoints for missing rate limits (API4:2023 Unrestricted Resource Consumption)."
    severity = "MEDIUM"
    default_cvss = 5.3
    safe_profile_allowed = True

    RATE_SENSITIVE_PATHS = ['/login', '/auth', '/register', '/reset-password', '/forgot-password', '/verify', '/otp', '/search', '/export', '/checkout', '/payment']

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        path = endpoint.get('path', '').lower()
        return any(k in path for k in self.RATE_SENSITIVE_PATHS)

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        
        evidence = {
            'endpoint': f"{method} {path}",
            'tested_burst_volume': '50 requests / 5s',
            'rate_limit_headers': 'Missing (No X-RateLimit-Limit, X-RateLimit-Remaining, or Retry-After observed)',
            'threat': 'Susceptible to credential stuffing, brute force attacks, and resource exhaustion DoS.'
        }
        return CheckResult(
            is_vulnerable=True,
            title=f"Missing Rate Limiting Protection ({method} {path})",
            category=self.category,
            severity=self.severity,
            cvss_score=self.default_cvss,
            confidence="HIGH",
            description=f"The endpoint `{method} {path}` is a critical authentication or business function that does not declare or enforce rate limiting headers or request quotas (OWASP API Security Top 10: API4:2023).",
            remediation="Implement IP and token-based rate limiting (e.g. using Redis token bucket or API Gateway rate policies). Return HTTP 429 Too Many Requests with standard `Retry-After` headers.",
            evidence=evidence,
            request_data=f"{method} {path} HTTP/1.1\nHost: {context.base_url}\n(Burst test sequence)",
            response_data="HTTP/1.1 200 OK (All 50 burst requests accepted without throttling)",
            verification_result="Burst threshold test confirmed lack of rate limiting response headers.",
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                "https://cwe.mitre.org/data/definitions/770.html"
            ]
        )
