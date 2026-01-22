"""
Pydantic models for EthiScan.

Defines core data structures for vulnerabilities, scan results, and reports.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    """Vulnerability severity levels following CVSS conventions."""
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @property
    def color(self) -> str:
        """Get color code for severity level."""
        colors = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue",
        }
        return colors.get(self.value, "white")
    
    @property
    def score_range(self) -> tuple[float, float]:
        """Get CVSS score range for severity level."""
        ranges = {
            "CRITICAL": (9.0, 10.0),
            "HIGH": (7.0, 8.9),
            "MEDIUM": (4.0, 6.9),
            "LOW": (0.1, 3.9),
            "INFO": (0.0, 0.0),
        }
        return ranges.get(self.value, (0.0, 0.0))


class Vulnerability(BaseModel):
    """
    Represents a discovered security vulnerability.
    
    Attributes:
        name: Short, descriptive name of the vulnerability.
        description: Detailed explanation of the issue.
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        evidence: Proof of the vulnerability (headers, response data, etc.).
        fix: Recommended remediation steps.
        module: Name of the module that detected this vulnerability.
        url: URL where vulnerability was found.
        cwe_id: Optional CWE identifier (e.g., "CWE-79" for XSS).
        references: Optional list of reference URLs.
    """
    
    name: str = Field(..., description="Vulnerability name")
    description: str = Field(..., description="Detailed description")
    severity: Severity = Field(..., description="Severity level")
    evidence: str = Field(default="", description="Evidence/proof")
    fix: str = Field(default="", description="Remediation recommendation")
    module: str = Field(default="unknown", description="Detecting module")
    url: str = Field(default="", description="Affected URL")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True


class ScanTarget(BaseModel):
    """Information about the scan target."""
    
    url: str = Field(..., description="Target URL")
    ip_address: Optional[str] = Field(default=None, description="Resolved IP address")
    server: Optional[str] = Field(default=None, description="Server header value")
    technologies: List[str] = Field(default_factory=list, description="Detected technologies")


class ScanResult(BaseModel):
    """
    Complete scan result containing all findings.
    
    Attributes:
        target: Information about the scanned target.
        vulnerabilities: List of discovered vulnerabilities.
        scan_time: Timestamp when scan was performed.
        duration: Scan duration in seconds.
        modules_run: List of modules that were executed.
        active_scan: Whether active scanning was enabled.
    """
    
    target: ScanTarget = Field(..., description="Scan target info")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list,
        description="Discovered vulnerabilities"
    )
    scan_time: datetime = Field(
        default_factory=datetime.now,
        description="Scan timestamp"
    )
    duration: float = Field(default=0.0, description="Scan duration in seconds")
    modules_run: List[str] = Field(default_factory=list, description="Executed modules")
    active_scan: bool = Field(default=False, description="Active scan enabled")
    
    @property
    def vulnerability_count(self) -> int:
        """Get total vulnerability count."""
        return len(self.vulnerabilities)
    
    @property
    def critical_count(self) -> int:
        """Get critical vulnerability count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL])
    
    @property
    def high_count(self) -> int:
        """Get high severity vulnerability count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.HIGH])
    
    @property
    def medium_count(self) -> int:
        """Get medium severity vulnerability count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM])
    
    @property
    def low_count(self) -> int:
        """Get low severity vulnerability count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.LOW])
    
    @property
    def info_count(self) -> int:
        """Get informational finding count."""
        return len([v for v in self.vulnerabilities if v.severity == Severity.INFO])
    
    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities filtered by severity."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_by_module(self, module: str) -> List[Vulnerability]:
        """Get vulnerabilities filtered by module name."""
        return [v for v in self.vulnerabilities if v.module == module]
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """Get summary dictionary for reporting."""
        return {
            "target": self.target.url,
            "scan_time": self.scan_time.isoformat(),
            "duration": f"{self.duration:.2f}s",
            "total_vulnerabilities": self.vulnerability_count,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "modules_run": self.modules_run,
            "active_scan": self.active_scan,
        }
