from typing import List, Dict, Any
from database.models import Finding

class RiskEngine:
    """Calculates comprehensive API security posture, CVSS metrics, and risk scores."""

    SEVERITY_WEIGHTS = {
        'CRITICAL': 10.0,
        'HIGH': 7.5,
        'MEDIUM': 4.5,
        'LOW': 2.0,
        'INFORMATIONAL': 0.5
    }

    @classmethod
    def calculate_api_posture(cls, findings: List[Finding]) -> Dict[str, Any]:
        """Calculates security posture score (0-100) and grade (A, B, C, D, F)."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFORMATIONAL': 0}
        active_findings = [f for f in findings if f.lifecycle_state not in ['Resolved', 'Remediated']]

        for f in active_findings:
            sev = f.severity.upper()
            if sev in counts:
                counts[sev] += 1

        total_active = len(active_findings)
        
        # Base score starts at 100 and deductions occur based on open findings
        deductions = (
            (counts['CRITICAL'] * 25.0) +
            (counts['HIGH'] * 12.0) +
            (counts['MEDIUM'] * 5.0) +
            (counts['LOW'] * 1.5) +
            (counts['INFORMATIONAL'] * 0.5)
        )
        
        posture_score = max(0.0, min(100.0, 100.0 - deductions))
        posture_score = round(posture_score, 1)

        if posture_score >= 90:
            grade = 'A'
            posture_status = 'EXCELLENT'
        elif posture_score >= 75:
            grade = 'B'
            posture_status = 'GOOD'
        elif posture_score >= 60:
            grade = 'C'
            posture_status = 'FAIR'
        elif posture_score >= 40:
            grade = 'D'
            posture_status = 'POOR'
        else:
            grade = 'F'
            posture_status = 'CRITICAL RISK'

        return {
            'score': posture_score,
            'grade': grade,
            'status': posture_status,
            'counts': counts,
            'total_active': total_active,
            'total_resolved': len(findings) - total_active
        }
