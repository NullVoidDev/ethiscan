"""
SQL Injection Scanner Module.

Tests forms and parameters for SQL injection vulnerabilities.
WARNING: This is an ACTIVE module that sends payloads to the target.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

from ethiscan.core.models import Severity, Vulnerability
from ethiscan.modules.__base__ import BaseModule, register_module


# SQL injection test payloads - designed to trigger errors without causing damage
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1' AND '1'='2",
    "1; SELECT 1--",
    "1' UNION SELECT NULL--",
    "1' WAITFOR DELAY '0:0:5'--",  # Time-based (MSSQL)
    "1' AND SLEEP(5)--",  # Time-based (MySQL)
]

# Error patterns indicating SQL injection vulnerability
SQL_ERROR_PATTERNS = [
    # MySQL errors
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"Warning.*mysql_", re.IGNORECASE),
    re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"check the manual that corresponds to your MySQL", re.IGNORECASE),
    
    # PostgreSQL errors
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"Warning.*\bpg_", re.IGNORECASE),
    re.compile(r"valid PostgreSQL result", re.IGNORECASE),
    re.compile(r"PSQLException", re.IGNORECASE),
    
    # SQL Server errors
    re.compile(r"Driver.*SQL Server", re.IGNORECASE),
    re.compile(r"OLE DB.*SQL Server", re.IGNORECASE),
    re.compile(r"\bSQL Server\b.*Driver", re.IGNORECASE),
    re.compile(r"Warning.*mssql_", re.IGNORECASE),
    re.compile(r"Microsoft SQL Native Client.*error", re.IGNORECASE),
    re.compile(r"ODBC SQL Server Driver", re.IGNORECASE),
    re.compile(r"SqlException", re.IGNORECASE),
    
    # Oracle errors
    re.compile(r"\bORA-\d{5}", re.IGNORECASE),
    re.compile(r"Oracle error", re.IGNORECASE),
    re.compile(r"Warning.*oci_", re.IGNORECASE),
    re.compile(r"Oracle.*Driver", re.IGNORECASE),
    
    # SQLite errors
    re.compile(r"SQLite.*Error", re.IGNORECASE),
    re.compile(r"Warning.*sqlite_", re.IGNORECASE),
    re.compile(r"SQLiteException", re.IGNORECASE),
    
    # Generic SQL errors
    re.compile(r"SQL syntax error", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"syntax error at or near", re.IGNORECASE),
    re.compile(r"unexpected end of SQL command", re.IGNORECASE),
]


@register_module
class SQLiModule(BaseModule):
    """
    SQL Injection vulnerability scanner.
    
    Tests forms and URL parameters for SQL injection by sending
    payloads and analyzing responses for database error messages.
    
    WARNING: This is an ACTIVE module that sends payloads to the target.
    Only use with explicit authorization.
    """
    
    @property
    def name(self) -> str:
        """Module identifier."""
        return "sqli"
    
    @property
    def description(self) -> str:
        """Module description."""
        return "Tests for SQL Injection vulnerabilities [ACTIVE]"
    
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
        Scan for SQL injection vulnerabilities.
        
        Args:
            url: Target URL.
            session: HTTP session.
            response: Pre-fetched response (optional).
            
        Returns:
            List of SQLi vulnerabilities found.
        """
        vulnerabilities: List[Vulnerability] = []
        
        # Get the page to find forms
        if response is None:
            try:
                response = session.get(url, timeout=10)
            except requests.RequestException:
                return vulnerabilities
        
        # Store baseline response for comparison
        baseline = response.text
        
        # Find all forms on the page
        forms = self._extract_forms(response.text, url)
        
        # Test each form
        for form in forms:
            vulns = self._test_form(form, session, baseline)
            vulnerabilities.extend(vulns)
        
        # Test URL parameters
        vulns = self._test_url_params(url, session, baseline)
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
            for inp in form.find_all(["input", "textarea", "select"]):
                input_type = inp.get("type", "text")
                input_name = inp.get("name", "")
                
                # Skip certain input types
                if input_type in ["submit", "button", "image", "file"]:
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
    
    def _test_form(self, form: Dict, session: requests.Session, baseline: str) -> List[Vulnerability]:
        """Test a single form for SQL injection."""
        vulnerabilities = []
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        
        tested_fields = set()
        
        # Test each input field
        for target_input in inputs:
            if target_input["name"] in tested_fields:
                continue
            
            for payload in SQLI_PAYLOADS[:5]:  # Limit payloads
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
                    
                    # Check for SQL error patterns
                    error_found = self._detect_sqli(resp.text)
                    
                    if error_found:
                        vuln = Vulnerability(
                            name=f"SQL Injection in Form Field: {target_input['name']}",
                            description=f"The form field '{target_input['name']}' is vulnerable to SQL injection. Database error messages were triggered by the test payload.",
                            severity=Severity.CRITICAL,
                            evidence=f"Form: {action}\nField: {target_input['name']}\nMethod: {method}\nPayload: {payload}\nError Pattern: {error_found}",
                            fix="Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and use an ORM.",
                            module=self.name,
                            url=action,
                            cwe_id="CWE-89",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                        )
                        vulnerabilities.append(vuln)
                        tested_fields.add(target_input["name"])
                        break  # Found SQLi, stop testing this field
                        
                except requests.RequestException:
                    continue
        
        return vulnerabilities
    
    def _test_url_params(self, url: str, session: requests.Session, baseline: str) -> List[Vulnerability]:
        """Test URL parameters for SQL injection."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        tested_params = set()
        
        for param_name in params:
            if param_name in tested_params:
                continue
            
            for payload in SQLI_PAYLOADS[:4]:
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
                    
                    error_found = self._detect_sqli(resp.text)
                    
                    if error_found:
                        vuln = Vulnerability(
                            name=f"SQL Injection in URL Parameter: {param_name}",
                            description=f"The URL parameter '{param_name}' is vulnerable to SQL injection.",
                            severity=Severity.CRITICAL,
                            evidence=f"URL: {url}\nParameter: {param_name}\nPayload: {payload}\nError: {error_found}",
                            fix="Use parameterized queries. Never concatenate user input into SQL strings.",
                            module=self.name,
                            url=url,
                            cwe_id="CWE-89",
                        )
                        vulnerabilities.append(vuln)
                        tested_params.add(param_name)
                        break
                        
                except requests.RequestException:
                    continue
        
        return vulnerabilities
    
    def _detect_sqli(self, response_text: str) -> Optional[str]:
        """
        Detect SQL injection based on error patterns.
        
        Args:
            response_text: HTTP response body.
            
        Returns:
            Matched error pattern string or None.
        """
        for pattern in SQL_ERROR_PATTERNS:
            match = pattern.search(response_text)
            if match:
                return match.group(0)
        
        return None
