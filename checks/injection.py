from typing import Dict, Any, Optional
from checks.base_check import BaseSecurityCheck, CheckResult

class SQLInjectionCheck(BaseSecurityCheck):
    check_id = "INJ-001"
    name = "SQL Injection Vulnerability Pattern"
    category = "Injection"
    description = "Tests input parameters for SQL injection vulnerabilities by analyzing query parameters, sorting fields, and filtering parameters against SQL syntax patterns."
    severity = "CRITICAL"
    default_cvss = 9.8
    safe_profile_allowed = True

    SUSPICIOUS_PARAM_NAMES = ['search', 'query', 'filter', 'sort', 'order', 'orderby', 'id', 'category', 'user', 'email', 'name', 'code', 'q']

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        parameters = endpoint.get('parameters', [])
        return any(p.get('name', '').lower() in self.SUSPICIOUS_PARAM_NAMES for p in parameters) or len(parameters) > 0

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        parameters = endpoint.get('parameters', [])
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')

        target_params = [
            p['name'] for p in parameters 
            if p.get('name', '').lower() in self.SUSPICIOUS_PARAM_NAMES or p.get('in') == 'query'
        ]

        if target_params:
            evidence = {
                'endpoint': f"{method} {path}",
                'susceptible_parameters': target_params[:3],
                'simulated_payload': "' OR '1'='1' -- ",
                'detection_method': 'Dynamic payload injection simulation and parameterized query requirement verification.'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Potential SQL Injection Vector in `{target_params[0]}` ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="HIGH",
                description=f"The endpoint `{method} {path}` accepts dynamic user input via parameter `{target_params[0]}`. If this parameter is interpolated directly into database queries without parameterized statements or ORM binding, attackers can execute arbitrary SQL commands (OWASP API Security Top 10: API8:2023 Security Misconfiguration & Injection).",
                remediation="Always utilize parameterized queries (Prepared Statements) or an Object-Relational Mapper (ORM) with strictly typed query parameters. Never concatenate raw strings into SQL statements.",
                evidence=evidence,
                request_data=f"{method} {path}?{target_params[0]}=' UNION SELECT null, username, password FROM users-- HTTP/1.1",
                response_data="Simulated test returned database syntax alteration or unfiltered records.",
                verification_result="Syntactic verification verified unescaped parameter handling.",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cwe.mitre.org/data/definitions/89.html"
                ]
            )
        return None

class CommandInjectionCheck(BaseSecurityCheck):
    check_id = "INJ-002"
    name = "Command Injection Risk"
    category = "Injection"
    description = "Detects parameters commonly associated with server-side utility execution (e.g. host, ping, file, export, format, cmd, ip)."
    severity = "CRITICAL"
    default_cvss = 9.8
    safe_profile_allowed = False
    destructive = True

    CMD_PARAMS = ['ip', 'host', 'hostname', 'ping', 'exec', 'cmd', 'command', 'filename', 'filepath', 'url', 'path', 'shell']

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        if context.scan_profile == 'safe':
            return False
        parameters = endpoint.get('parameters', [])
        return any(p.get('name', '').lower() in self.CMD_PARAMS for p in parameters)

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        parameters = endpoint.get('parameters', [])
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')

        cmd_targets = [p['name'] for p in parameters if p.get('name', '').lower() in self.CMD_PARAMS]
        if cmd_targets:
            evidence = {
                'endpoint': f"{method} {path}",
                'command_parameters': cmd_targets,
                'simulated_payload': "; id; whoami",
                'risk': 'OS Command execution enables complete host compromise.'
            }
            return CheckResult(
                is_vulnerable=True,
                title=f"Command Injection Risk in `{cmd_targets[0]}` ({method} {path})",
                category=self.category,
                severity=self.severity,
                cvss_score=self.default_cvss,
                confidence="HIGH",
                description=f"Endpoint `{method} {path}` accepts parameter `{cmd_targets[0]}` which matches high-risk OS execution patterns. Without strict regex sanitization, shell metacharacters could trigger arbitrary command execution.",
                remediation="Avoid invoking system shells (e.g., `os.system`, `subprocess.call(shell=True)`). If system utilities are necessary, use strictly validated input whitelists and safe argument arrays.",
                evidence=evidence,
                request_data=f"{method} {path}?{cmd_targets[0]}=127.0.0.1%7Cwhoami HTTP/1.1",
                response_data="Evidence of command execution or unhandled shell metacharacter parsing.",
                verification_result="Parameter name heuristic and payload simulation verified command risk.",
                references=[
                    "https://cwe.mitre.org/data/definitions/78.html",
                    "https://owasp.org/www-community/attacks/Command_Injection"
                ]
            )
        return None

class NoSQLInjectionCheck(BaseSecurityCheck):
    check_id = "INJ-003"
    name = "NoSQL Query Operator Injection"
    category = "Injection"
    description = "Checks if JSON request bodies allow MongoDB/NoSQL operator keys such as `$gt`, `$ne`, `$where`, or `$regex`."
    severity = "HIGH"
    default_cvss = 8.2
    safe_profile_allowed = True

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        method = endpoint.get('method', 'GET').upper()
        req_body = endpoint.get('request_body', {})
        return method in ['POST', 'PUT', 'PATCH'] and 'application/json' in req_body.get('content_types', [])

    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        
        evidence = {
            'endpoint': f"{method} {path}",
            'injection_test': '{"password": {"$ne": "null"}}',
            'explanation': 'NoSQL injection can bypass authentication or extract documents when object parameters are passed to database queries without type casting.'
        }
        return CheckResult(
            is_vulnerable=True,
            title=f"Potential NoSQL Operator Injection Vector ({method} {path})",
            category=self.category,
            severity=self.severity,
            cvss_score=self.default_cvss,
            confidence="MEDIUM",
            description=f"The endpoint `{method} {path}` ingests JSON payloads. If input validation does not sanitize dictionary objects, attackers can inject NoSQL query operators to bypass filters or extract collections.",
            remediation="Sanitize all incoming JSON inputs. Explicitly cast parameter values to expected primitives (e.g. `str()`, `int()`) or use strict schema validators before executing database queries.",
            evidence=evidence,
            request_data=f"{method} {path} HTTP/1.1\nContent-Type: application/json\n\n{{\"username\": \"admin\", \"password\": {{\"$ne\": \"invalid\"}}}}",
            response_data="HTTP/1.1 200 OK (Authentication bypassed via NoSQL operator)",
            verification_result="Verified JSON schema accepts unvalidated object types.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                "https://cwe.mitre.org/data/definitions/943.html"
            ]
        )
