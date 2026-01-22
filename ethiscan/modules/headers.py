"""
Security Headers Scanner Module.

Checks for missing or misconfigured HTTP security headers.
"""

from typing import List, Optional

import requests

from ethiscan.core.models import Severity, Vulnerability
from ethiscan.modules.__base__ import BaseModule, register_module


# Security headers with their importance and recommended values
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "description": "Content Security Policy (CSP) helps prevent XSS, clickjacking, and other code injection attacks.",
        "fix": "Implement a strict Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
        "cwe_id": "CWE-16",
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "Prevents MIME type sniffing which can lead to security vulnerabilities.",
        "fix": "Add header: X-Content-Type-Options: nosniff",
        "cwe_id": "CWE-16",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "Protects against clickjacking attacks by controlling iframe embedding.",
        "fix": "Add header: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
        "cwe_id": "CWE-1021",
    },
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS.",
        "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe_id": "CWE-319",
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "Legacy XSS filter for older browsers. Modern browsers use CSP instead.",
        "fix": "Add header: X-XSS-Protection: 1; mode=block (or rely on CSP for modern browsers)",
        "cwe_id": "CWE-79",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Controls how much referrer information is sent with requests.",
        "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe_id": "CWE-200",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Controls which browser features can be used (camera, microphone, etc.).",
        "fix": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "cwe_id": "CWE-16",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": Severity.INFO,
        "description": "Prevents other origins from accessing the window object.",
        "fix": "Add header: Cross-Origin-Opener-Policy: same-origin",
        "cwe_id": "CWE-346",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": Severity.INFO,
        "description": "Controls which origins can load resources.",
        "fix": "Add header: Cross-Origin-Resource-Policy: same-origin",
        "cwe_id": "CWE-346",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": Severity.INFO,
        "description": "Controls embedding of cross-origin resources.",
        "fix": "Add header: Cross-Origin-Embedder-Policy: require-corp",
        "cwe_id": "CWE-346",
    },
}


@register_module
class HeadersModule(BaseModule):
    """
    Security headers vulnerability scanner.
    
    Checks for missing or misconfigured HTTP security headers
    that could leave the application vulnerable to various attacks.
    """
    
    @property
    def name(self) -> str:
        """Module identifier."""
        return "headers"
    
    @property
    def description(self) -> str:
        """Module description."""
        return "Checks for missing or misconfigured HTTP security headers"
    
    @property
    def is_active(self) -> bool:
        """This is a passive module."""
        return False
    
    def scan(
        self,
        url: str,
        session: requests.Session,
        response: Optional[requests.Response] = None,
    ) -> List[Vulnerability]:
        """
        Scan for missing security headers.
        
        Args:
            url: Target URL.
            session: HTTP session.
            response: Pre-fetched response (optional).
            
        Returns:
            List of vulnerabilities for missing headers.
        """
        vulnerabilities: List[Vulnerability] = []
        
        # Use provided response or fetch new one
        if response is None:
            try:
                response = session.get(url, timeout=10)
            except requests.RequestException:
                return vulnerabilities
        
        headers = response.headers
        
        # Check each security header
        for header_name, header_info in SECURITY_HEADERS.items():
            if header_name not in headers:
                vuln = Vulnerability(
                    name=f"Missing Security Header: {header_name}",
                    description=header_info["description"],
                    severity=header_info["severity"],
                    evidence=f"Header '{header_name}' is not present in the response.",
                    fix=header_info["fix"],
                    module=self.name,
                    url=url,
                    cwe_id=header_info.get("cwe_id"),
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
                    ],
                )
                vulnerabilities.append(vuln)
            else:
                # Check for weak configurations
                value = headers[header_name].lower()
                weak_config = self._check_weak_config(header_name, value)
                if weak_config:
                    vuln = Vulnerability(
                        name=f"Weak Security Header: {header_name}",
                        description=weak_config["description"],
                        severity=Severity.LOW,
                        evidence=f"Header value: {headers[header_name]}",
                        fix=weak_config["fix"],
                        module=self.name,
                        url=url,
                        cwe_id=header_info.get("cwe_id"),
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_weak_config(self, header: str, value: str) -> Optional[dict]:
        """
        Check for weak header configurations.
        
        Args:
            header: Header name.
            value: Header value (lowercase).
            
        Returns:
            Dict with description and fix if weak, None otherwise.
        """
        weak_configs = {
            "X-Frame-Options": {
                "check": lambda v: v == "allowall",
                "description": "X-Frame-Options is set to ALLOWALL which provides no protection.",
                "fix": "Change to: X-Frame-Options: DENY or SAMEORIGIN",
            },
            "Strict-Transport-Security": {
                "check": lambda v: "max-age=0" in v or int(v.split("max-age=")[1].split(";")[0]) < 31536000 if "max-age=" in v else True,
                "description": "HSTS max-age is too short (should be at least 1 year).",
                "fix": "Set max-age to at least 31536000 (1 year)",
            },
            "X-XSS-Protection": {
                "check": lambda v: v == "0",
                "description": "X-XSS-Protection is disabled.",
                "fix": "Change to: X-XSS-Protection: 1; mode=block",
            },
            "Content-Security-Policy": {
                "check": lambda v: "unsafe-inline" in v and "unsafe-eval" in v,
                "description": "CSP allows both 'unsafe-inline' and 'unsafe-eval' which weakens protection.",
                "fix": "Remove 'unsafe-inline' and 'unsafe-eval' where possible, use nonces or hashes instead.",
            },
        }
        
        if header in weak_configs:
            config = weak_configs[header]
            try:
                if config["check"](value):
                    return {
                        "description": config["description"],
                        "fix": config["fix"],
                    }
            except (ValueError, IndexError):
                pass
        
        return None
