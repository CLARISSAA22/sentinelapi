import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from database.database import get_db
from database.models import Finding, FindingHistory, APIEndpoint

def get_now():
    return datetime.now(timezone.utc)

class FindingEngine:
    """Manages finding generation, deduplication, regression tracking, and lifecycle states."""

    @classmethod
    def generate_finding_ref(cls, db_session) -> str:
        """Generates a sequential human-readable finding reference like SEC-0001, SEC-0002."""
        count = db_session.query(Finding).count()
        return f"SEC-{str(count + 1).zfill(4)}"

    @classmethod
    def record_finding(
        cls,
        scan_id: str,
        api_id: str,
        endpoint_id: Optional[str],
        check_result: Any,
        endpoint: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> Finding:
        db = get_db()
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET')
        title = check_result.title

        # Check for existing finding on this API + Endpoint + Title
        existing_finding = db.query(Finding).filter_by(
            api_id=api_id,
            path=path,
            method=method,
            title=title
        ).first()

        now = get_now()

        if existing_finding:
            # Check for regression!
            old_state = existing_finding.lifecycle_state
            if old_state in ['Resolved', 'Remediated']:
                existing_finding.lifecycle_state = 'Reopened'
                existing_finding.last_detected_at = now
                
                # Record regression audit history
                hist = FindingHistory(
                    finding_id=existing_finding.id,
                    user_id=user_id,
                    action='Reopened',
                    old_state=old_state,
                    new_state='Reopened',
                    comment='Finding re-occurred during latest security scan (Regression Detected).'
                )
                db.add(hist)
            else:
                existing_finding.last_detected_at = now
                existing_finding.scan_id = scan_id

            # Update evidence and verification
            existing_finding.evidence_json = json.dumps(check_result.evidence or {})
            existing_finding.request_data = check_result.request_data
            existing_finding.response_data = check_result.response_data
            existing_finding.verification_result = check_result.verification_result
            
            # Update endpoint risk status
            if endpoint_id:
                ep_obj = db.query(APIEndpoint).filter_by(id=endpoint_id).first()
                if ep_obj:
                    ep_obj.risk_status = existing_finding.severity
                    ep_obj.last_tested_at = now
                    
            db.commit()
            return existing_finding

        # Create new finding
        finding_ref = cls.generate_finding_ref(db)
        new_finding = Finding(
            finding_ref=finding_ref,
            scan_id=scan_id,
            api_id=api_id,
            endpoint_id=endpoint_id,
            title=title,
            category=check_result.category,
            method=method,
            path=path,
            severity=check_result.severity,
            cvss_score=check_result.cvss_score,
            confidence=check_result.confidence,
            description=check_result.description,
            evidence_json=json.dumps(check_result.evidence or {}),
            request_data=check_result.request_data,
            response_data=check_result.response_data,
            verification_result=check_result.verification_result,
            remediation=check_result.remediation,
            references_json=json.dumps(check_result.references or []),
            status=check_result.status,
            lifecycle_state='New',
            first_detected_at=now,
            last_detected_at=now
        )
        db.add(new_finding)
        db.flush()

        # Add initial history event
        hist = FindingHistory(
            finding_id=new_finding.id,
            user_id=user_id,
            action='Detected',
            old_state=None,
            new_state='New',
            comment=f"First discovered during scan {scan_id}."
        )
        db.add(hist)

        # Update endpoint risk status
        if endpoint_id:
            ep_obj = db.query(APIEndpoint).filter_by(id=endpoint_id).first()
            if ep_obj:
                ep_obj.risk_status = new_finding.severity
                ep_obj.last_tested_at = now

        db.commit()
        return new_finding
