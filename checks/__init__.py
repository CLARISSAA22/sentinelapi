from checks.base_check import BaseSecurityCheck, CheckResult
from checks.authentication import MissingAuthCheck, WeakAuthSchemeCheck
from checks.authorization import BOLAIdorCheck, BFLACheck, PropertyLevelAuthCheck
from checks.injection import SQLInjectionCheck, CommandInjectionCheck, NoSQLInjectionCheck
from checks.misconfiguration import SecurityHeadersCheck, CORSWeaknessCheck, DebugEndpointCheck
from checks.secrets import SecretExposureCheck
from checks.pii import PIIExposureCheck
from checks.rate_limiting import RateLimitingCheck
from checks.resource_consumption import ResourceConsumptionCheck

ALL_CHECKS = [
    MissingAuthCheck,
    WeakAuthSchemeCheck,
    BOLAIdorCheck,
    BFLACheck,
    PropertyLevelAuthCheck,
    SQLInjectionCheck,
    CommandInjectionCheck,
    NoSQLInjectionCheck,
    SecurityHeadersCheck,
    CORSWeaknessCheck,
    DebugEndpointCheck,
    SecretExposureCheck,
    PIIExposureCheck,
    RateLimitingCheck,
    ResourceConsumptionCheck
]

def get_all_checks():
    """Return instances of all registered security checks."""
    return [check_cls() for check_cls in ALL_CHECKS]
