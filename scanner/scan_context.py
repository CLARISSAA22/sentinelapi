from typing import Dict, Any, Optional
from dataclasses import dataclass, field

@dataclass
class ScanContext:
    api_id: str
    scan_id: str
    base_url: str
    scan_profile: str = "standard"  # safe, standard, authenticated, advanced
    auth_headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 10
    config: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_safe_mode(self) -> bool:
        return self.scan_profile == "safe"
