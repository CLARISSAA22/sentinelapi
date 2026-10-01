import re
from typing import Dict, Any, Optional
from checks.base_check import BaseSecurityCheck, CheckResult

class SecretExposureCheck(BaseSecurityCheck):
    check_id = "SEC-001"
    name = "Hardcoded Secret & Credential Leakage"
    category = "Sensitive Data Exposure"
    description = "Detects hardcoded API keys, JWT tokens, AWS credentials, database URIs, or private keys exposed in endpoint descriptions, default parameter values, or response schemas."
    severity = "CRITICAL"
    default_cvss = 9.8
    safe_profile_allowed = True

    SECRET_REGEXES = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'JWT Token': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        'Generic API Key': r'(?:api[_-]?key|secret[_-]?key|access[_-]?token)[\'\"]?\s*[:=]\s*[\'\"]?([a-zA-Z0-9_\-]{20,})[\'\"]?',
        'Private Key Block': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
        'Database Connection URI': r'(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@'
    }

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        desc = endpoint.get('description', '') + ' ' + endpoint.get('summary', '')
        params_str = str(endpoint.get('parameters', []))
        resp_str = str(endpoint.get('response_schemas', {}))
        
        combined_text = f"{path} {desc} {params_str} {resp_str}"
        detected_secrets = []

        for label, pattern in self.SECRET_REGEXES.items():
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                detected_secrets.append(label)

        if detected_secrets:
            evidence = {
                'endpoint': f"{method} {path}",
                'leaked_types': detected_secrets,
                'location': 'API Endpoint Schema / Descriptions'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Hardcoded Secret / Token Exposure ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="HIGH",
                description=f"Sensitive credentials ({', '.join(detected_secrets)}) were detected in endpoint metadata, parameter defaults, or schema documentation on `{method} {path}`.",
                remediation="Immediately revoke exposed secrets and credentials. Store secrets securely in environment variables or key vaults (AWS Secrets Manager, HashiCorp Vault) and ensure documentation never includes production credentials.",
                evidence=evidence,
                request_data=f"{method} {path} HTTP/1.1",
                response_data=f"Metadata contained potential credential pattern: {detected_secrets[0]}",
                verification_result="Static regular expression scanner detected credential signatures in spec.",
                references=[
                    "https://cwe.mitre.org/data/definitions/798.html",
                    "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
                ]
            )
        return None
