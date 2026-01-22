"""
Cookie Security Scanner Module.

Checks for insecure cookie configurations.
"""

from typing import List, Optional

import requests

from ethiscan.core.models import Severity, Vulnerability
from ethiscan.modules.__base__ import BaseModule, register_module


@register_module
class CookiesModule(BaseModule):
    """
    Cookie security vulnerability scanner.
    
    Analyzes cookies for missing security flags and potentially
    sensitive information exposure.
    """
    
    @property
    def name(self) -> str:
        """Module identifier."""
        return "cookies"
    
    @property
    def description(self) -> str:
        """Module description."""
        return "Checks for insecure cookie configurations (missing Secure, HttpOnly, SameSite flags)"
    
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
        Scan cookies for security issues.
        
        Args:
            url: Target URL.
            session: HTTP session.
            response: Pre-fetched response (optional).
            
        Returns:
            List of cookie-related vulnerabilities.
        """
        vulnerabilities: List[Vulnerability] = []
        
        # Use provided response or fetch new one
        if response is None:
            try:
                response = session.get(url, timeout=10)
            except requests.RequestException:
                return vulnerabilities
        
        # Check Set-Cookie headers
        set_cookie_headers = response.headers.get("Set-Cookie", "")
        if not set_cookie_headers:
            # Also check raw headers for multiple Set-Cookie
            raw_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, 'headers') else []
            if not raw_cookies:
                return vulnerabilities
        
        # Parse cookies from response
        cookies = response.cookies
        
        if not cookies:
            return vulnerabilities
        
        is_https = url.startswith("https://")
        
        for cookie in cookies:
            cookie_issues = []
            
            # Check Secure flag
            if is_https and not cookie.secure:
                cookie_issues.append({
                    "name": f"Cookie Missing Secure Flag: {cookie.name}",
                    "description": f"The cookie '{cookie.name}' is transmitted over HTTPS but lacks the Secure flag, making it vulnerable to man-in-the-middle attacks if transmitted over HTTP.",
                    "severity": Severity.MEDIUM,
                    "fix": "Add the Secure flag to the cookie: Set-Cookie: name=value; Secure",
                    "cwe_id": "CWE-614",
                })
            
            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr("HttpOnly") and not self._is_httponly(cookie):
                cookie_issues.append({
                    "name": f"Cookie Missing HttpOnly Flag: {cookie.name}",
                    "description": f"The cookie '{cookie.name}' lacks the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS cookie theft.",
                    "severity": Severity.MEDIUM,
                    "fix": "Add the HttpOnly flag to the cookie: Set-Cookie: name=value; HttpOnly",
                    "cwe_id": "CWE-1004",
                })
            
            # Check SameSite attribute
            samesite = self._get_samesite(cookie)
            if samesite is None:
                cookie_issues.append({
                    "name": f"Cookie Missing SameSite Attribute: {cookie.name}",
                    "description": f"The cookie '{cookie.name}' lacks the SameSite attribute, potentially making it vulnerable to CSRF attacks.",
                    "severity": Severity.LOW,
                    "fix": "Add the SameSite attribute: Set-Cookie: name=value; SameSite=Lax (or Strict for sensitive cookies)",
                    "cwe_id": "CWE-1275",
                })
            elif samesite.lower() == "none" and not cookie.secure:
                cookie_issues.append({
                    "name": f"Cookie SameSite=None Without Secure: {cookie.name}",
                    "description": f"The cookie '{cookie.name}' has SameSite=None but lacks the Secure flag. Modern browsers will reject this cookie.",
                    "severity": Severity.MEDIUM,
                    "fix": "When using SameSite=None, always include the Secure flag: Set-Cookie: name=value; SameSite=None; Secure",
                    "cwe_id": "CWE-614",
                })
            
            # Check for sensitive cookie names without protection
            sensitive_names = ["session", "token", "auth", "jwt", "api_key", "apikey", "password", "secret"]
            if any(s in cookie.name.lower() for s in sensitive_names):
                if not cookie.secure or not self._is_httponly(cookie):
                    cookie_issues.append({
                        "name": f"Sensitive Cookie Without Full Protection: {cookie.name}",
                        "description": f"The cookie '{cookie.name}' appears to contain sensitive data but lacks full security protection (Secure and HttpOnly flags).",
                        "severity": Severity.HIGH,
                        "fix": "Sensitive cookies should always have both Secure and HttpOnly flags: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
                        "cwe_id": "CWE-311",
                    })
            
            # Create vulnerability objects
            for issue in cookie_issues:
                vuln = Vulnerability(
                    name=issue["name"],
                    description=issue["description"],
                    severity=issue["severity"],
                    evidence=f"Cookie: {cookie.name}={cookie.value[:20]}{'...' if len(str(cookie.value)) > 20 else ''}",
                    fix=issue["fix"],
                    module=self.name,
                    url=url,
                    cwe_id=issue.get("cwe_id"),
                    references=[
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
                    ],
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_httponly(self, cookie) -> bool:
        """Check if cookie has HttpOnly flag."""
        # requests library stores _rest attribute with extra flags
        if hasattr(cookie, "_rest"):
            return "HttpOnly" in cookie._rest or "httponly" in [k.lower() for k in cookie._rest.keys()]
        return False
    
    def _get_samesite(self, cookie) -> Optional[str]:
        """Get SameSite attribute value."""
        if hasattr(cookie, "_rest"):
            for key in cookie._rest:
                if key.lower() == "samesite":
                    return cookie._rest[key]
        return None
