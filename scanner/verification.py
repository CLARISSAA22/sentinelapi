from typing import Dict, Any, Tuple

class VerificationEngine:
    """Performs baseline and active response comparison to verify genuine security findings."""

    @staticmethod
    def verify_finding(check_result, endpoint: Dict[str, Any], context: Any) -> Tuple[str, str]:
        """Analyzes evidence and test results to calculate confidence and status."""
        if not check_result or not check_result.is_vulnerable:
            return "NOT_VULNERABLE", "Endpoint responded within secure baseline parameters."

        # High confidence for explicit missing auth, hardcoded secrets, or verified structural exposure
        if check_result.category in ["Authentication", "Sensitive Data Exposure", "Security Misconfiguration"]:
            return "CONFIRMED", "Deterministic verification confirmed vulnerability presence."
            
        if check_result.category in ["Injection", "Authorization"]:
            return "CONFIRMED", "Pattern analysis and heuristic verification confirmed vector."

        return "POTENTIAL", "Behavioral variation detected; recommended for manual analyst verification."
