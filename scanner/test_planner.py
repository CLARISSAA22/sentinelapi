from typing import List, Dict, Any, Tuple
from checks import get_all_checks
from checks.base_check import BaseSecurityCheck
from scanner.scan_context import ScanContext

class TestPlanner:
    """Generates an intelligent test execution plan matching applicable checks to endpoint profiles."""

    def __init__(self, context: ScanContext):
        self.context = context
        self.all_checks: List[BaseSecurityCheck] = get_all_checks()

    def build_plan(self, endpoints: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], BaseSecurityCheck]]:
        """Build a prioritized matrix of (endpoint, check) execution pairs."""
        plan = []
        for ep in endpoints:
            for check in self.all_checks:
                if check.can_run(ep, self.context):
                    plan.append((ep, check))
        return plan
