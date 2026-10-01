import time
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from database.database import get_db
from database.models import Scan, ScanTest, API, APIEndpoint, Finding, Report
from scanner.scan_context import ScanContext
from scanner.test_planner import TestPlanner
from scanner.verification import VerificationEngine
from scanner.finding_engine import FindingEngine
from scanner.risk_engine import RiskEngine

def get_now():
    return datetime.now(timezone.utc)

class ScannerEngine:
    """Core modular scanner orchestrating the full API security testing lifecycle."""

    @classmethod
    def execute_scan(cls, scan_id: str) -> bool:
        db = get_db()
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return False

        api = db.query(API).filter_by(id=scan.api_id).first()
        if not api:
            scan.status = 'failed'
            scan.error_message = 'Associated API target no longer exists.'
            db.commit()
            return False

        try:
            # 1. State: preparing
            scan.status = 'preparing'
            scan.started_at = get_now()
            db.commit()

            # 2. State: discovery
            scan.status = 'discovery'
            db.commit()
            endpoints = [ep.to_dict() for ep in api.endpoints]
            scan.total_endpoints = len(endpoints)
            db.commit()

            # 3. State: authentication
            scan.status = 'authentication'
            db.commit()
            auth_headers = {}
            for cred in api.credentials:
                if cred.auth_type == 'bearer':
                    auth_headers['Authorization'] = f"Bearer {cred.masked_value}"
                elif cred.auth_type == 'api_key':
                    auth_headers['X-API-Key'] = cred.masked_value

            # 4. State: test_planning
            scan.status = 'test_planning'
            db.commit()
            context = ScanContext(
                api_id=api.id,
                scan_id=scan.id,
                base_url=api.base_url,
                scan_profile=scan.scan_profile,
                auth_headers=auth_headers
            )
            planner = TestPlanner(context)
            test_matrix = planner.build_plan(endpoints)

            # 5. State: testing
            scan.status = 'testing'
            db.commit()
            tested_endpoint_ids = set()
            new_findings_count = 0

            for ep_dict, check in test_matrix:
                start_time = time.time()
                endpoint_id = ep_dict.get('id')
                check_status = 'executed'
                check_details = None

                try:
                    result = check.run(ep_dict, context)
                    duration = round((time.time() - start_time) * 1000, 2)
                    
                    if result and result.is_vulnerable:
                        # 6. State: verification
                        ver_status, ver_note = VerificationEngine.verify_finding(result, ep_dict, context)
                        result.status = ver_status
                        result.verification_result = ver_note

                        FindingEngine.record_finding(
                            scan_id=scan.id,
                            api_id=api.id,
                            endpoint_id=endpoint_id,
                            check_result=result,
                            endpoint=ep_dict,
                            user_id=scan.user_id
                        )
                        new_findings_count += 1
                        check_details = f"Finding generated: {result.title} (Confidence: {result.confidence})"
                    else:
                        check_details = "Check completed. No vulnerability detected."

                except Exception as ex:
                    check_status = 'failed'
                    duration = round((time.time() - start_time) * 1000, 2)
                    check_details = f"Check failed with error: {str(ex)}"

                # Record individual test trace
                test_record = ScanTest(
                    scan_id=scan.id,
                    endpoint_id=endpoint_id,
                    check_id=check.check_id,
                    check_name=check.name,
                    category=check.category,
                    status=check_status,
                    duration_ms=duration,
                    details=check_details
                )
                db.add(test_record)
                if endpoint_id:
                    tested_endpoint_ids.add(endpoint_id)

            # 7. State: correlation & risk calculation
            scan.status = 'risk_calculation'
            scan.tested_endpoints = len(tested_endpoint_ids)
            scan.findings_count = new_findings_count
            db.commit()

            # 8. State: report_generation
            scan.status = 'report_generation'
            db.commit()
            
            # Generate Report summary
            all_findings = db.query(Finding).filter_by(api_id=api.id).all()
            posture = RiskEngine.calculate_api_posture(all_findings)
            
            report_summary = {
                'scan_id': scan.id,
                'scan_name': scan.name,
                'scan_profile': scan.scan_profile,
                'api_name': api.name,
                'api_version': api.version,
                'base_url': api.base_url,
                'endpoints_tested': scan.tested_endpoints,
                'total_endpoints': scan.total_endpoints,
                'findings_count': new_findings_count,
                'posture_score': posture['score'],
                'posture_grade': posture['grade'],
                'posture_status': posture['status'],
                'severity_breakdown': posture['counts'],
                'tests_executed_count': len(test_matrix),
                'completed_at': get_now().isoformat()
            }
            
            report = Report(
                scan_id=scan.id,
                api_id=api.id,
                user_id=scan.user_id,
                title=f"Security Assessment: {api.name} ({scan.name})",
                report_format='html',
                summary_json=json.dumps(report_summary)
            )
            db.add(report)

            # 9. State: completed
            scan.status = 'completed'
            scan.completed_at = get_now()
            db.commit()
            return True

        except Exception as e:
            scan.status = 'failed'
            scan.error_message = f"Scan failed: {str(e)}"
            scan.completed_at = get_now()
            db.commit()
            return False
