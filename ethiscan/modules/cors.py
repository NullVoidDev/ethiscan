"""
CORS Misconfiguration Scanner Module.

Detects insecure Cross-Origin Resource Sharing configurations.
"""

from typing import List, Optional

import requests

from ethiscan.core.models import Severity, Vulnerability
from ethiscan.modules.__base__ import BaseModule, register_module


# Dangerous CORS configurations
DANGEROUS_ORIGINS = ["*", "null"]
DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH"]


@register_module
class CorsModule(BaseModule):
    """
    CORS misconfiguration scanner.
    
    Detects insecure CORS configurations that could allow
    unauthorized cross-origin access to sensitive data.
    """
    
    @property
    def name(self) -> str:
        """Module identifier."""
        return "cors"
    
    @property
    def description(self) -> str:
        """Module description."""
        return "Detects CORS misconfiguration vulnerabilities"
    
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
        Scan for CORS misconfigurations.
        
        Args:
            url: Target URL.
            session: HTTP session.
            response: Pre-fetched response (optional).
            
        Returns:
            List of CORS-related vulnerabilities.
        """
        vulnerabilities: List[Vulnerability] = []
        
        # Use provided response or fetch new one
        if response is None:
            try:
                response = session.get(url, timeout=10)
            except requests.RequestException:
                return vulnerabilities
        
        headers = response.headers
        
        # Check Access-Control-Allow-Origin
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = headers.get("Access-Control-Allow-Methods", "")
        acah = headers.get("Access-Control-Allow-Headers", "")
        
        # Check for wildcard origin
        if acao == "*":
            severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
            
            vuln = Vulnerability(
                name="CORS Wildcard Origin",
                description="The server allows requests from any origin (*). This could expose sensitive data to malicious websites.",
                severity=severity,
                evidence=f"Access-Control-Allow-Origin: {acao}" + (f"\nAccess-Control-Allow-Credentials: {acac}" if acac else ""),
                fix="Configure specific trusted origins instead of using wildcard. Example: Access-Control-Allow-Origin: https://trusted.example.com",
                module=self.name,
                url=url,
                cwe_id="CWE-942",
                references=[
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ],
            )
            vulnerabilities.append(vuln)
        
        # Check for null origin (can be exploited via sandboxed iframes)
        if acao.lower() == "null":
            vuln = Vulnerability(
                name="CORS Null Origin Allowed",
                description="The server allows the 'null' origin, which can be exploited via sandboxed iframes or file:// URLs.",
                severity=Severity.HIGH,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                fix="Remove 'null' from allowed origins. Only allow specific trusted domains.",
                module=self.name,
                url=url,
                cwe_id="CWE-942",
                references=[
                    "https://portswigger.net/web-security/cors",
                ],
            )
            vulnerabilities.append(vuln)
        
        # Check for credentials with wildcard
        if acao == "*" and acac == "true":
            vuln = Vulnerability(
                name="CORS Credentials with Wildcard",
                description="The server allows credentials with wildcard origin. Modern browsers block this, but misconfigurations may exist.",
                severity=Severity.HIGH,
                evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                fix="Use specific origins when allowing credentials. Wildcard and credentials are mutually exclusive in modern browsers.",
                module=self.name,
                url=url,
                cwe_id="CWE-942",
            )
            vulnerabilities.append(vuln)
        
        # Check for dangerous methods
        if acam:
            dangerous_found = [m for m in DANGEROUS_METHODS if m in acam.upper()]
            if dangerous_found:
                vuln = Vulnerability(
                    name="CORS Allows Dangerous Methods",
                    description=f"The server allows potentially dangerous HTTP methods via CORS: {', '.join(dangerous_found)}",
                    severity=Severity.MEDIUM,
                    evidence=f"Access-Control-Allow-Methods: {acam}",
                    fix="Limit allowed methods to only those necessary (typically GET, POST). Remove dangerous methods like DELETE, PUT unless required.",
                    module=self.name,
                    url=url,
                    cwe_id="CWE-942",
                )
                vulnerabilities.append(vuln)
        
        # Test with Origin header to check if server reflects arbitrary origins
        vulnerabilities.extend(self._test_origin_reflection(url, session))
        
        return vulnerabilities
    
    def _test_origin_reflection(self, url: str, session: requests.Session) -> List[Vulnerability]:
        """Test if server reflects arbitrary Origin headers."""
        vulnerabilities = []
        
        test_origin = "https://evil-attacker.com"
        
        try:
            headers = {"Origin": test_origin}
            response = session.get(url, headers=headers, timeout=10)
            
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            
            # Check if our evil origin was reflected
            if acao == test_origin:
                acac = response.headers.get("Access-Control-Allow-Credentials", "").lower()
                severity = Severity.CRITICAL if acac == "true" else Severity.HIGH
                
                vuln = Vulnerability(
                    name="CORS Origin Reflection",
                    description="The server reflects arbitrary Origin headers in Access-Control-Allow-Origin. This is a critical misconfiguration that allows any website to make authenticated requests.",
                    severity=severity,
                    evidence=f"Request Origin: {test_origin}\nResponse Access-Control-Allow-Origin: {acao}",
                    fix="Validate Origin against a whitelist of trusted domains. Never reflect the Origin header directly.",
                    module=self.name,
                    url=url,
                    cwe_id="CWE-942",
                    references=[
                        "https://portswigger.net/web-security/cors/access-control-allow-origin",
                    ],
                )
                vulnerabilities.append(vuln)
        except requests.RequestException:
            pass
        
        return vulnerabilities
