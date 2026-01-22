"""
XSS (Cross-Site Scripting) Scanner Module.

Tests forms for reflected XSS vulnerabilities.
WARNING: This is an ACTIVE module that modifies input data.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from ethiscan.core.models import Severity, Vulnerability
from ethiscan.modules.__base__ import BaseModule, register_module


# XSS test payloads - designed to be detectable but minimally invasive
XSS_PAYLOADS = [
    '<script>alert("ETHISCAN_XSS_TEST")</script>',
    '"><script>alert("ETHISCAN_XSS_TEST")</script>',
    "'\"><img src=x onerror=alert('ETHISCAN_XSS_TEST')>",
    '<svg onload=alert("ETHISCAN_XSS_TEST")>',
    "javascript:alert('ETHISCAN_XSS_TEST')",
    '<img src="x" onerror="alert(\'ETHISCAN_XSS_TEST\')">',
    '<body onload=alert("ETHISCAN_XSS_TEST")>',
    '{{constructor.constructor("alert(1)")()}}',  # Template injection
]

# Patterns to detect XSS payload reflection
XSS_DETECTION_PATTERNS = [
    re.compile(r'<script>alert\("ETHISCAN_XSS_TEST"\)</script>', re.IGNORECASE),
    re.compile(r'onerror\s*=\s*alert\([\'"]ETHISCAN_XSS_TEST[\'"]\)', re.IGNORECASE),
    re.compile(r'onload\s*=\s*alert\([\'"]ETHISCAN_XSS_TEST[\'"]\)', re.IGNORECASE),
    re.compile(r'<svg\s+onload', re.IGNORECASE),
    re.compile(r'<img\s+src\s*=.*onerror', re.IGNORECASE),
]


@register_module
class XSSModule(BaseModule):
    """
    Cross-Site Scripting (XSS) vulnerability scanner.
    
    Tests forms and URL parameters for reflected XSS vulnerabilities
    by injecting test payloads and checking for reflection.
    
    WARNING: This is an ACTIVE module that sends payloads to the target.
    Only use with explicit authorization.
    """
    
    @property
    def name(self) -> str:
        """Module identifier."""
        return "xss"
    
    @property
    def description(self) -> str:
        """Module description."""
        return "Tests for reflected Cross-Site Scripting (XSS) vulnerabilities [ACTIVE]"
    
    @property
    def is_active(self) -> bool:
        """This is an ACTIVE module."""
        return True
    
    def scan(
        self,
        url: str,
        session: requests.Session,
        response: Optional[requests.Response] = None,
    ) -> List[Vulnerability]:
        """
        Scan for XSS vulnerabilities.
        
        Args:
            url: Target URL.
            session: HTTP session.
            response: Pre-fetched response (optional).
            
        Returns:
            List of XSS vulnerabilities found.
        """
        vulnerabilities: List[Vulnerability] = []
        
        # Get the page to find forms
        if response is None:
            try:
                response = session.get(url, timeout=10)
            except requests.RequestException:
                return vulnerabilities
        
        # Find all forms on the page
        forms = self._extract_forms(response.text, url)
        
        # Test each form
        for form in forms:
            vulns = self._test_form(form, session)
            vulnerabilities.extend(vulns)
        
        # Test URL parameters
        vulns = self._test_url_params(url, session)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML."""
        soup = BeautifulSoup(html, "lxml")
        forms = []
        
        for form in soup.find_all("form"):
            action = form.get("action", "")
            action = urljoin(base_url, action) if action else base_url
            method = form.get("method", "GET").upper()
            
            inputs = []
            for inp in form.find_all(["input", "textarea"]):
                input_type = inp.get("type", "text")
                input_name = inp.get("name", "")
                
                # Skip non-injectable types
                if input_type in ["submit", "button", "image", "file", "hidden"]:
                    if input_type != "hidden":
                        continue
                
                if input_name:
                    inputs.append({
                        "name": input_name,
                        "type": input_type,
                        "value": inp.get("value", ""),
                    })
            
            if inputs:
                forms.append({
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                })
        
        return forms
    
    def _test_form(self, form: Dict, session: requests.Session) -> List[Vulnerability]:
        """Test a single form for XSS."""
        vulnerabilities = []
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        
        # Test each input field
        for target_input in inputs:
            if target_input["type"] in ["hidden"]:
                continue
            
            for payload in XSS_PAYLOADS[:3]:  # Limit payloads for efficiency
                # Prepare form data
                data = {}
                for inp in inputs:
                    if inp["name"] == target_input["name"]:
                        data[inp["name"]] = payload
                    else:
                        data[inp["name"]] = inp.get("value", "test")
                
                try:
                    if method == "POST":
                        resp = session.post(action, data=data, timeout=10)
                    else:
                        resp = session.get(action, params=data, timeout=10)
                    
                    # Check for XSS reflection
                    if self._detect_xss(resp.text, payload):
                        vuln = Vulnerability(
                            name=f"Reflected XSS in Form Field: {target_input['name']}",
                            description=f"The form field '{target_input['name']}' is vulnerable to reflected Cross-Site Scripting (XSS). User input is reflected in the response without proper sanitization.",
                            severity=Severity.HIGH,
                            evidence=f"Form: {action}\nField: {target_input['name']}\nMethod: {method}\nPayload: {payload}",
                            fix="Implement proper input validation and output encoding. Use Content-Security-Policy headers. Encode all user input before rendering in HTML context.",
                            module=self.name,
                            url=action,
                            cwe_id="CWE-79",
                            references=[
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            ],
                        )
                        vulnerabilities.append(vuln)
                        break  # Found XSS, no need to test more payloads
                        
                except requests.RequestException:
                    continue
        
        return vulnerabilities
    
    def _test_url_params(self, url: str, session: requests.Session) -> List[Vulnerability]:
        """Test URL parameters for XSS."""
        vulnerabilities = []
        
        # Parse existing URL parameters
        from urllib.parse import parse_qs, urlparse, urlencode, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        for param_name in params:
            for payload in XSS_PAYLOADS[:2]:
                # Create test URL with payload
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    urlencode(test_params),
                    parsed.fragment,
                ))
                
                try:
                    resp = session.get(test_url, timeout=10)
                    
                    if self._detect_xss(resp.text, payload):
                        vuln = Vulnerability(
                            name=f"Reflected XSS in URL Parameter: {param_name}",
                            description=f"The URL parameter '{param_name}' is vulnerable to reflected XSS.",
                            severity=Severity.HIGH,
                            evidence=f"URL: {url}\nParameter: {param_name}\nPayload: {payload}",
                            fix="Sanitize and encode URL parameters before reflecting in HTML output.",
                            module=self.name,
                            url=url,
                            cwe_id="CWE-79",
                        )
                        vulnerabilities.append(vuln)
                        break
                        
                except requests.RequestException:
                    continue
        
        return vulnerabilities
    
    def _detect_xss(self, response_text: str, payload: str) -> bool:
        """
        Detect if XSS payload was reflected in response.
        
        Args:
            response_text: HTTP response body.
            payload: The XSS payload that was sent.
            
        Returns:
            True if XSS appears exploitable.
        """
        # Check for exact payload reflection (unescaped)
        if payload in response_text:
            # Verify it's in an exploitable context (not inside a comment or escaped)
            for pattern in XSS_DETECTION_PATTERNS:
                if pattern.search(response_text):
                    return True
        
        return False
