"""
EthiScan - Ethical Web Vulnerability Scanner

A professional, modular security scanner for ethical assessments.
Use responsibly and only with explicit authorization.
"""

__version__ = "1.0.0"
__author__ = "EthiScan Team"
__license__ = "MIT"

from ethiscan.core.models import Vulnerability, ScanResult, Severity
from ethiscan.scanners.web_scanner import WebScanner

__all__ = [
    "Vulnerability",
    "ScanResult", 
    "Severity",
    "WebScanner",
    "__version__",
]
