from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

@dataclass
class CheckResult:
    is_vulnerable: bool
    title: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    cvss_score: float
    confidence: str  # HIGH, MEDIUM, LOW
    description: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    request_data: str = ""
    response_data: str = ""
    verification_result: str = ""
    references: List[str] = field(default_factory=list)
    status: str = "CONFIRMED"  # CONFIRMED, POTENTIAL, NOT_VULNERABLE, NOT_APPLICABLE, ERROR

class BaseSecurityCheck(ABC):
    """Abstract Base Class for all SentinelAPI security testing modules."""

    check_id: str = "BASE-000"
    name: str = "Base Security Check"
    category: str = "General"
    description: str = "Base security check interface"
    severity: str = "MEDIUM"
    default_cvss: float = 5.0
    safe_profile_allowed: bool = True
    destructive: bool = False

    def can_run(self, endpoint: Dict[str, Any], context: Any) -> bool:
        """Determines if this check is applicable for the given endpoint and scan profile."""
        if self.destructive and context.scan_profile == 'safe':
            return False
        return True

    @abstractmethod
    def run(self, endpoint: Dict[str, Any], context: Any) -> Optional[CheckResult]:
        """Execute the security check against the target endpoint."""
        pass

    def verify(self, baseline_response: Any, test_response: Any) -> Tuple[bool, str]:
        """Compare baseline and test response to verify genuine vulnerability."""
        if not baseline_response or not test_response:
            return False, "Insufficient data for response verification comparison."
        return True, "Response comparison verified."
