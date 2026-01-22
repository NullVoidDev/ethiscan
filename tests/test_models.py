"""
Unit tests for EthiScan core models.
"""

import pytest
from datetime import datetime

from ethiscan.core.models import Vulnerability, ScanResult, ScanTarget, Severity


class TestSeverity:
    """Tests for Severity enum."""
    
    def test_severity_values(self):
        """Test all severity values exist."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"
    
    def test_severity_color(self):
        """Test severity color property."""
        assert Severity.CRITICAL.color == "red"
        assert Severity.HIGH.color == "orange"
        assert Severity.INFO.color == "blue"


class TestVulnerability:
    """Tests for Vulnerability model."""
    
    def test_create_vulnerability(self):
        """Test creating a vulnerability."""
        vuln = Vulnerability(
            name="Test Vulnerability",
            description="A test vulnerability",
            severity=Severity.HIGH,
            evidence="Test evidence",
            fix="Test fix",
            module="test",
            url="https://example.com",
        )
        
        assert vuln.name == "Test Vulnerability"
        assert vuln.severity == "HIGH"
        assert vuln.module == "test"
    
    def test_vulnerability_with_cwe(self):
        """Test vulnerability with CWE ID."""
        vuln = Vulnerability(
            name="XSS",
            description="Cross-site scripting",
            severity=Severity.HIGH,
            cwe_id="CWE-79",
        )
        
        assert vuln.cwe_id == "CWE-79"
    
    def test_vulnerability_with_references(self):
        """Test vulnerability with references."""
        refs = ["https://owasp.org", "https://cwe.mitre.org"]
        vuln = Vulnerability(
            name="SQLi",
            description="SQL injection",
            severity=Severity.CRITICAL,
            references=refs,
        )
        
        assert len(vuln.references) == 2
        assert "https://owasp.org" in vuln.references


class TestScanTarget:
    """Tests for ScanTarget model."""
    
    def test_create_target(self):
        """Test creating a scan target."""
        target = ScanTarget(
            url="https://example.com",
            ip_address="93.184.216.34",
            server="nginx",
        )
        
        assert target.url == "https://example.com"
        assert target.ip_address == "93.184.216.34"
        assert target.server == "nginx"
    
    def test_target_with_technologies(self):
        """Test target with detected technologies."""
        target = ScanTarget(
            url="https://example.com",
            technologies=["nginx", "PHP", "WordPress"],
        )
        
        assert len(target.technologies) == 3


class TestScanResult:
    """Tests for ScanResult model."""
    
    def test_create_result(self):
        """Test creating a scan result."""
        result = ScanResult(
            target=ScanTarget(url="https://example.com"),
            vulnerabilities=[],
            modules_run=["headers", "cookies"],
        )
        
        assert result.target.url == "https://example.com"
        assert result.vulnerability_count == 0
    
    def test_result_counts(self):
        """Test vulnerability count properties."""
        vulns = [
            Vulnerability(name="V1", description="D1", severity=Severity.CRITICAL),
            Vulnerability(name="V2", description="D2", severity=Severity.HIGH),
            Vulnerability(name="V3", description="D3", severity=Severity.HIGH),
            Vulnerability(name="V4", description="D4", severity=Severity.MEDIUM),
            Vulnerability(name="V5", description="D5", severity=Severity.LOW),
            Vulnerability(name="V6", description="D6", severity=Severity.INFO),
        ]
        
        result = ScanResult(
            target=ScanTarget(url="https://example.com"),
            vulnerabilities=vulns,
        )
        
        assert result.vulnerability_count == 6
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.info_count == 1
    
    def test_get_by_severity(self):
        """Test filtering by severity."""
        vulns = [
            Vulnerability(name="V1", description="D1", severity=Severity.HIGH),
            Vulnerability(name="V2", description="D2", severity=Severity.HIGH),
            Vulnerability(name="V3", description="D3", severity=Severity.LOW),
        ]
        
        result = ScanResult(
            target=ScanTarget(url="https://example.com"),
            vulnerabilities=vulns,
        )
        
        high_vulns = result.get_by_severity(Severity.HIGH)
        assert len(high_vulns) == 2
    
    def test_get_by_module(self):
        """Test filtering by module."""
        vulns = [
            Vulnerability(name="V1", description="D1", severity=Severity.HIGH, module="headers"),
            Vulnerability(name="V2", description="D2", severity=Severity.HIGH, module="cookies"),
            Vulnerability(name="V3", description="D3", severity=Severity.LOW, module="headers"),
        ]
        
        result = ScanResult(
            target=ScanTarget(url="https://example.com"),
            vulnerabilities=vulns,
        )
        
        header_vulns = result.get_by_module("headers")
        assert len(header_vulns) == 2
    
    def test_summary_dict(self):
        """Test summary dictionary generation."""
        result = ScanResult(
            target=ScanTarget(url="https://example.com"),
            vulnerabilities=[],
            modules_run=["headers"],
            active_scan=False,
        )
        
        summary = result.to_summary_dict()
        
        assert summary["target"] == "https://example.com"
        assert summary["total_vulnerabilities"] == 0
        assert summary["active_scan"] == False
