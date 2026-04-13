from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Device:
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)

@dataclass
class Vulnerability:
    device_ip: str
    service: str
    vulnerability_type: str
    description: str
    severity: SeverityLevel
    cvss_score: float
    remediation: str

@dataclass
class RiskAssessment:
    device_ip: str
    overall_risk_score: float
    severity: SeverityLevel
    vulnerabilities: List[Vulnerability] = field(default_factory=list)