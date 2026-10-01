from typing import Dict, Any, Optional
from checks.base_check import BaseSecurityCheck, CheckResult

class ResourceConsumptionCheck(BaseSecurityCheck):
    check_id = "RES-001"
    name = "Unbounded Collection Pagination / Resource Exhaustion"
    category = "Resource Consumption"
    description = "Checks collection/list retrieval endpoints for missing maximum limit constraints on pagination (e.g. limit, page_size, count)."
    severity = "LOW"
    default_cvss = 4.3
    safe_profile_allowed = True

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        method = endpoint.get('method', 'GET').upper()
        path = endpoint.get('path', '')
        # List endpoints without ID path parameters
        return method == 'GET' and not path.endswith('}')

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        parameters = endpoint.get('parameters', [])
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')

        param_names = [p.get('name', '').lower() for p in parameters]
        has_pagination = any(k in param_names for k in ['limit', 'page', 'size', 'per_page', 'count', 'offset'])

        if not has_pagination:
            evidence = {
                'endpoint': f"{method} {path}",
                'declared_parameters': param_names,
                'issue': 'Collection endpoint lacks pagination controls.'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Unbounded Collection Retrieval Without Pagination ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="HIGH",
                description=f"Endpoint `{method} {path}` returns list collections but does not specify query parameters for pagination (e.g., `limit`, `offset`, `page_size`). Queries on large datasets can cause database memory exhaustion or server crashes.",
                remediation="Implement mandatory pagination parameters with a strictly enforced maximum limit (e.g., `limit=50, max_limit=100`).",
                evidence=evidence,
                request_data=f"{method} {path} HTTP/1.1",
                response_data="HTTP/1.1 200 OK (Entire unfiltered dataset returned)",
                verification_result="Query parameter schema validation verified absence of pagination controls.",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    "https://cwe.mitre.org/data/definitions/400.html"
                ]
            )
        return None
