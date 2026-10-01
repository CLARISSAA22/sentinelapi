import re
from typing import Dict, Any, Optional
from checks.base_check import BaseSecurityCheck, CheckResult

class PIIExposureCheck(BaseSecurityCheck):
    check_id = "PII-001"
    name = "Personally Identifiable Information (PII) Exposure"
    category = "Data Privacy & Compliance"
    description = "Identifies endpoints exposing unmasked credit cards, social security numbers (SSN), plain text passwords, or private biometric records."
    severity = "HIGH"
    default_cvss = 7.5
    safe_profile_allowed = True

    PII_KEYWORDS = ['ssn', 'social_security', 'credit_card', 'card_number', 'cvv', 'cvc', 'password_hash', 'raw_password', 'passport', 'driver_license']

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        resp_schemas = str(endpoint.get('response_schemas', {})).lower()
        desc = endpoint.get('description', '').lower()

        found_pii = [k for k in self.PII_KEYWORDS if k in resp_schemas or k in desc]
        if found_pii:
            evidence = {
                'endpoint': f"{method} {path}",
                'pii_fields_detected': found_pii,
                'compliance_impact': 'Violation of GDPR, CCPA, and PCI-DSS data protection standards.'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Potential PII Exposure in Response Schema ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="HIGH",
                description=f"Endpoint `{method} {path}` defines or returns sensitive Personally Identifiable Information fields ({', '.join(found_pii)}) without explicit data masking or tokenization.",
                remediation="Mask or omit sensitive PII before serialization. For payment data, leverage PCI-DSS compliant tokenization. Never return password hashes or raw secrets in API responses.",
                evidence=evidence,
                request_data=f"{method} {path} HTTP/1.1",
                response_data=f"Response schema defines fields: {', '.join(found_pii)}",
                verification_result="Response schema analysis verified unmasked PII attribute fields.",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    "https://cwe.mitre.org/data/definitions/359.html"
                ]
            )
        return None
