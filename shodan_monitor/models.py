"""
Data models for Shodan Security Monitor using Pydantic.
Provides validation and type safety for all data structures.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field, validator, HttpUrl


class ScanStatus(str, Enum):
    """Status of a scan run."""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ServiceProtocol(str, Enum):
    """Network protocol for services."""
    TCP = "tcp"
    UDP = "udp"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk levels for services."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Vulnerability(BaseModel):
    """Vulnerability information."""
    id: str = Field(..., description="Vulnerability ID (CVE, etc.)")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score if available")
    summary: Optional[str] = Field(None, description="Brief description")
    published_date: Optional[datetime] = Field(None, description="When vulnerability was published")
    references: List[HttpUrl] = Field(default_factory=list, description="Reference URLs")

    @validator('id')
    def validate_id_format(cls, v):
        """Basic validation for vulnerability IDs."""
        v = v.strip().upper()
        if not v:
            raise ValueError("Vulnerability ID cannot be empty")
        return v


class Service(BaseModel):
    """Discovered network service."""
    port: int = Field(..., ge=1, le=65535, description="Port number")
    transport: ServiceProtocol = Field(ServiceProtocol.TCP, description="Transport protocol")
    product: Optional[str] = Field(None, description="Service/product name")
    version: Optional[str] = Field(None, description="Service version")
    banner: Optional[str] = Field(None, description="Raw banner if available")
    cpe: List[str] = Field(default_factory=list, description="CPE identifiers")
    vulns: List[Vulnerability] = Field(default_factory=list, description="Vulnerabilities")
    ssl_info: Optional[Dict[str, Any]] = Field(None, description="SSL/TLS information")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When service was discovered")
    risk_score: int = Field(0, ge=0, le=100, description="Calculated risk score")
    risk_level: RiskLevel = Field(RiskLevel.INFO, description="Risk level")

    @validator('cpe')
    def validate_cpe(cls, v):
        """Validate CPE format."""
        validated = []
        for cpe in v:
            if cpe and cpe.strip():
                cpe_str = cpe.strip()
                if cpe_str.startswith('cpe:'):
                    validated.append(cpe_str)
                else:
                    # Try to fix common issues
                    if ':' in cpe_str:
                        validated.append(cpe_str)
                    else:
                        # Skip invalid CPEs but don't fail
                        continue
        return validated

    @validator('risk_level', always=True)
    def set_risk_level_from_score(cls, v, values):
        """Set risk level based on risk score."""
        if 'risk_score' in values:
            score = values['risk_score']
            if score >= 80:
                return RiskLevel.CRITICAL
            elif score >= 60:
                return RiskLevel.HIGH
            elif score >= 40:
                return RiskLevel.MEDIUM
            elif score >= 20:
                return RiskLevel.LOW
        return RiskLevel.INFO


class Target(BaseModel):
    """Target IP address with metadata."""
    ip: str = Field(..., description="IP address")
    org: Optional[str] = Field(None, description="Organization")
    asn: Optional[str] = Field(None, description="Autonomous System Number")
    country: Optional[str] = Field(None, description="Country code")
    country_name: Optional[str] = Field(None, description="Country name")
    first_seen: datetime = Field(default_factory=datetime.utcnow, description="First discovery")
    last_seen: datetime = Field(default_factory=datetime.utcnow, description="Last discovery")
    services: List[Service] = Field(default_factory=list, description="Discovered services")

    @validator('ip')
    def validate_ip(cls, v):
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")


class ScanRun(BaseModel):
    """Scan run metadata and statistics."""
    id: str = Field(..., description="Unique scan ID")
    started_at: datetime = Field(default_factory=datetime.utcnow, description="Scan start time")
    finished_at: Optional[datetime] = Field(None, description="Scan finish time")
    status: ScanStatus = Field(ScanStatus.RUNNING, description="Scan status")
    targets_count: int = Field(0, ge=0, description="Number of targets planned")
    successful_targets: int = Field(0, ge=0, description="Successfully scanned targets")
    failed_targets: int = Field(0, ge=0, description="Failed targets")
    total_services: int = Field(0, ge=0, description="Total services discovered")

    @validator('successful_targets', 'failed_targets')
    def validate_target_counts(cls, v, values):
        """Ensure target counts are consistent."""
        if 'targets_count' in values and v > values['targets_count']:
            raise ValueError(f"Cannot have {v} targets exceeding total {values['targets_count']}")
        return v

    @property
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds if completed."""
        if self.finished_at and self.started_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def success_rate(self) -> float:
        """Get success rate as percentage."""
        if self.targets_count == 0:
            return 0.0
        return (self.successful_targets / self.targets_count) * 100


class ShodanHostResponse(BaseModel):
    """Response from Shodan host API."""
    ip: str
    org: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    country_name: Optional[str] = None
    last_update: Optional[str] = None
    data: List[Dict[str, Any]] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    class Config:
        extra = "ignore"  # Ignore extra fields from Shodan API


class CollectorConfig(BaseModel):
    """Collector configuration."""
    interval_seconds: int = Field(21600, ge=300, description="Scan interval in seconds")
    request_delay: float = Field(1.0, ge=0.5, le=10.0, description="Delay between requests")
    max_retries: int = Field(3, ge=0, le=10, description="Max API retries")
    timeout_minutes: int = Field(30, ge=5, le=1440, description="Scan timeout")
    shodan_api_key: str = Field(..., description="Shodan API key")
    db_host: str = Field("localhost", description="Database host")
    db_port: int = Field(5432, ge=1, le=65535, description="Database port")
    db_name: str = Field("shodan", description="Database name")
    db_user: str = Field("shodan", description="Database user")
    db_pass: str = Field("shodan", description="Database password")

    @validator('shodan_api_key')
    def validate_api_key(cls, v):
        """Validate Shodan API key format."""
        if not v or len(v.strip()) < 10:
            raise ValueError("Invalid Shodan API key")
        return v.strip()