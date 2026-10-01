import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from database.models import Scan, API, Finding
from scanner.risk_engine import RiskEngine

class ReportGenerator:
    """Generates comprehensive audit reports in HTML, JSON, and Markdown formats."""

    @classmethod
    def generate_markdown_report(cls, scan: Scan, api: API, findings: List[Finding]) -> str:
        posture = RiskEngine.calculate_api_posture(findings)
        md = []
        md.append(f"# SentinelAPI Security Assessment Report")
        md.append(f"**Target API:** {api.name} (v{api.version})  ")
        md.append(f"**Base URL:** `{api.base_url}`  ")
        md.append(f"**Environment:** {api.environment.upper()}  ")
        md.append(f"**Scan ID:** `{scan.id}`  ")
        md.append(f"**Scan Date:** {scan.completed_at or scan.created_at}  ")
        md.append(f"**Scan Profile:** {scan.scan_profile.upper()}  ")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 1. Executive Summary")
        md.append(f"- **Overall Security Posture:** {posture['status']} (Grade: **{posture['grade']}**, Score: **{posture['score']}/100**)")
        md.append(f"- **Total Endpoints Assessed:** {scan.tested_endpoints} of {scan.total_endpoints}")
        md.append(f"- **Active Security Findings:** {posture['total_active']}")
        md.append(f"  - **Critical:** {posture['counts']['CRITICAL']}")
        md.append(f"  - **High:** {posture['counts']['HIGH']}")
        md.append(f"  - **Medium:** {posture['counts']['MEDIUM']}")
        md.append(f"  - **Low:** {posture['counts']['LOW']}")
        md.append(f"  - **Informational:** {posture['counts']['INFORMATIONAL']}")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 2. Detailed Findings & Vulnerability Evidence")
        
        if not findings:
            md.append("*No security findings detected during this scan assessment.*")
        else:
            for f in findings:
                md.append(f"### [{f.finding_ref}] {f.title}")
                md.append(f"- **Severity:** `{f.severity}` (CVSS Base: **{f.cvss_score}**) | **Confidence:** `{f.confidence}` | **Status:** `{f.status}`")
                md.append(f"- **Endpoint:** `{f.method} {f.path}`")
                md.append(f"- **Category:** {f.category}")
                md.append(f"- **Lifecycle State:** {f.lifecycle_state}")
                md.append("")
                md.append(f"#### Description")
                md.append(f"{f.description}")
                md.append("")
                if f.request_data:
                    md.append("#### Request Evidence")
                    md.append(f"```http\n{f.request_data}\n```")
                if f.response_data:
                    md.append("#### Response Evidence")
                    md.append(f"```http\n{f.response_data}\n```")
                md.append("#### Remediation Guidance")
                md.append(f"{f.remediation}")
                md.append("")
                md.append("---")

        md.append("## 3. Scope & Limitations")
        md.append("- This assessment was executed using dynamic and static API vulnerability checks aligned with the OWASP API Security Top 10.")
        md.append("- Safe scan profiles exclude destructive payload mutations.")
        md.append("- SentinelAPI does not claim 100% vulnerability discovery; automated scanning should be complemented with periodic manual penetration testing.")
        md.append("")
        md.append(f"*Generated automatically by SentinelAPI v2.4 Enterprise on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        return "\n".join(md)
