"""
JSON Report Generator.

Generates machine-readable JSON reports.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from ethiscan.core.models import ScanResult


class JsonReporter:
    """
    JSON report generator.
    
    Produces machine-readable JSON reports suitable for
    integration with other tools and automation.
    """
    
    def __init__(self, pretty: bool = True) -> None:
        """
        Initialize the JSON reporter.
        
        Args:
            pretty: Whether to format JSON with indentation.
        """
        self.extension = ".json"
        self.pretty = pretty
    
    def generate(self, result: ScanResult, output_path: str) -> str:
        """
        Generate a JSON report.
        
        Args:
            result: Scan result to report.
            output_path: Base output path (without extension).
            
        Returns:
            Path to the generated report file.
        """
        file_path = f"{output_path}{self.extension}"
        
        # Build report structure
        report = {
            "meta": {
                "tool": "EthiScan",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
            },
            "target": {
                "url": result.target.url,
                "ip_address": result.target.ip_address,
                "server": result.target.server,
                "technologies": result.target.technologies,
            },
            "scan": {
                "time": result.scan_time.isoformat(),
                "duration_seconds": result.duration,
                "active_scan": result.active_scan,
                "modules_run": result.modules_run,
            },
            "summary": {
                "total": result.vulnerability_count,
                "by_severity": {
                    "critical": result.critical_count,
                    "high": result.high_count,
                    "medium": result.medium_count,
                    "low": result.low_count,
                    "info": result.info_count,
                },
            },
            "vulnerabilities": [
                self._vulnerability_to_dict(v)
                for v in result.vulnerabilities
            ],
        }
        
        # Write to file
        with open(file_path, "w", encoding="utf-8") as f:
            if self.pretty:
                json.dump(report, f, indent=2, ensure_ascii=False)
            else:
                json.dump(report, f, ensure_ascii=False)
        
        return file_path
    
    def _vulnerability_to_dict(self, vuln) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            "name": vuln.name,
            "severity": vuln.severity,
            "module": vuln.module,
            "url": vuln.url,
            "description": vuln.description,
            "evidence": vuln.evidence,
            "fix": vuln.fix,
            "cwe_id": vuln.cwe_id,
            "references": vuln.references,
        }
