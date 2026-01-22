"""
Server Information Disclosure Scanner Module.

Checks for server version and technology disclosure in headers, responses,
HTML comments, and meta tags.
"""

import re
from typing import List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup

from ethiscan.core.models import Severity, Vulnerability
from ethiscan.modules.__base__ import BaseModule, register_module


# Headers that commonly disclose server information
INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "X-Backend-Server",
    "Via",
    "X-Pingback",
    "X-Runtime",
    "X-Version",
]

# Patterns indicating technology disclosure
TECH_PATTERNS = {
    "php": re.compile(r"PHP/[\d.]+", re.IGNORECASE),
    "apache": re.compile(r"Apache/[\d.]+", re.IGNORECASE),
    "nginx": re.compile(r"nginx/[\d.]+", re.IGNORECASE),
    "iis": re.compile(r"Microsoft-IIS/[\d.]+", re.IGNORECASE),
    "asp.net": re.compile(r"ASP\.NET|X-AspNet", re.IGNORECASE),
    "express": re.compile(r"Express", re.IGNORECASE),
    "django": re.compile(r"Django|djdt|csrfmiddlewaretoken", re.IGNORECASE),
    "wordpress": re.compile(r"WordPress|wp-content|wp-includes", re.IGNORECASE),
    "drupal": re.compile(r"Drupal|drupal\.js", re.IGNORECASE),
    "joomla": re.compile(r"Joomla!", re.IGNORECASE),
    "tomcat": re.compile(r"Apache-Coyote|Tomcat", re.IGNORECASE),
    "jetty": re.compile(r"Jetty", re.IGNORECASE),
}

# Sensitive keywords in HTML comments
SENSITIVE_COMMENT_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "key", "token", "api_key", "apikey",
    "api-key", "auth", "credential", "private", "internal", "admin", "root",
    "todo", "fixme", "hack", "xxx", "bug", "debug", "test", "dev", "temp",
    "remove", "delete", "deprecated", "sql", "query", "database", "db",
    "config", "configuration", "setting", "env", "environment",
]

# Debug mode indicators
DEBUG_PATTERNS = [
    (r"DJANGO_DEBUG\s*=\s*True", "Django debug mode"),
    (r"display_errors\s*=\s*on", "PHP display_errors enabled"),
    (r'"debug"\s*:\s*true', "Debug mode in config"),
    (r"APP_DEBUG\s*=\s*true", "Laravel debug mode"),
    (r"DEBUG\s*=\s*True", "Debug flag enabled"),
    (r"<title>.*(?:Debug|Error|Exception|Traceback).*</title>", "Debug page title"),
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"Stack trace:", "Stack trace exposed"),
    (r"at\s+[\w.]+\([\w.]+:\d+\)", "Java/C# stack trace"),
    (r"Fatal error:", "PHP fatal error"),
    (r"Parse error:", "PHP parse error"),
    (r"MySQL Error|mysqli_error|mysql_error", "MySQL error exposed"),
    (r"pg_query\(\)|PostgreSQL.*ERROR", "PostgreSQL error exposed"),
    (r"ORA-\d{5}", "Oracle error exposed"),
]

# Error page signatures
ERROR_PAGE_SIGNATURES = [
    (r"<h1>Server Error</h1>.*<h2>.*Exception", Severity.HIGH, "ASP.NET Error Page"),
    (r"Django Version:.*Python Version:", Severity.HIGH, "Django Debug Page"),
    (r"<div id=\"sf-resetcontent\"", Severity.MEDIUM, "Symfony Error Page"),
    (r"Whoops! There was an error", Severity.MEDIUM, "Laravel Whoops Page"),
    (r"<pre class=\"cake-error\">", Severity.MEDIUM, "CakePHP Error Page"),
]


@register_module
class ServerInfoModule(BaseModule):
    """
    Server information disclosure scanner.
    
    Detects exposed server versions, technologies, sensitive comments,
    and debug information that could aid attackers.
    """
    
    @property
    def name(self) -> str:
        """Module identifier."""
        return "server_info"
    
    @property
    def description(self) -> str:
        """Module description."""
        return "Detects server version disclosure, sensitive comments, and debug info"
    
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
        Scan for server information disclosure.
        
        Args:
            url: Target URL.
            session: HTTP session.
            response: Pre-fetched response (optional).
            
        Returns:
            List of information disclosure vulnerabilities.
        """
        vulnerabilities: List[Vulnerability] = []
        
        # Use provided response or fetch new one
        if response is None:
            try:
                response = session.get(url, timeout=10)
            except requests.RequestException:
                return vulnerabilities
        
        # Check headers for information disclosure
        vulnerabilities.extend(self._check_headers(url, response.headers))
        
        # Check response body for various issues
        if response.text:
            vulnerabilities.extend(self._check_html_comments(url, response.text))
            vulnerabilities.extend(self._check_meta_generator(url, response.text))
            vulnerabilities.extend(self._check_debug_mode(url, response.text))
            vulnerabilities.extend(self._check_error_pages(url, response.text))
            vulnerabilities.extend(self._check_source_maps(url, response.text))
        
        # Check for common sensitive paths via robots.txt
        vulnerabilities.extend(self._check_sensitive_paths(url, session))
        
        return vulnerabilities
    
    def _check_headers(self, url: str, headers: dict) -> List[Vulnerability]:
        """Check headers for information disclosure."""
        vulnerabilities = []
        disclosed_info = []
        
        for header_name in INFO_DISCLOSURE_HEADERS:
            if header_name in headers:
                value = headers[header_name]
                disclosed_info.append(f"{header_name}: {value}")
                
                # Check for version numbers
                for tech, pattern in TECH_PATTERNS.items():
                    if pattern.search(value):
                        vuln = Vulnerability(
                            name=f"Server Technology Disclosure: {tech.upper()}",
                            description=f"The server discloses its technology stack ({tech}) with version information in the '{header_name}' header.",
                            severity=Severity.LOW,
                            evidence=f"{header_name}: {value}",
                            fix=f"Configure the server to hide or obfuscate the {header_name} header. For Apache: ServerTokens Prod. For Nginx: server_tokens off.",
                            module=self.name,
                            url=url,
                            cwe_id="CWE-200",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                            ],
                        )
                        vulnerabilities.append(vuln)
        
        # Generic disclosure if multiple headers found
        if len(disclosed_info) >= 2:
            vuln = Vulnerability(
                name="Multiple Server Information Headers",
                description="The server exposes multiple headers that reveal information about its technology stack.",
                severity=Severity.INFO,
                evidence="\n".join(disclosed_info),
                fix="Review and remove unnecessary headers that disclose server information.",
                module=self.name,
                url=url,
                cwe_id="CWE-200",
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_html_comments(self, url: str, body: str) -> List[Vulnerability]:
        """Check HTML comments for sensitive information."""
        vulnerabilities = []
        
        # Extract all HTML comments
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL | re.IGNORECASE)
        comments = comment_pattern.findall(body)
        
        sensitive_comments = []
        for comment in comments:
            comment_lower = comment.lower()
            for keyword in SENSITIVE_COMMENT_KEYWORDS:
                if keyword in comment_lower:
                    # Truncate long comments
                    excerpt = comment.strip()[:100]
                    if len(comment) > 100:
                        excerpt += "..."
                    sensitive_comments.append((keyword, excerpt))
                    break
        
        if sensitive_comments:
            # Group by severity
            critical_keywords = ["password", "secret", "key", "token", "credential", "api_key"]
            has_critical = any(kw in critical_keywords for kw, _ in sensitive_comments)
            
            evidence_lines = [f"[{kw}]: {excerpt}" for kw, excerpt in sensitive_comments[:5]]
            
            vuln = Vulnerability(
                name="Sensitive Information in HTML Comments",
                description=f"Found {len(sensitive_comments)} HTML comment(s) containing potentially sensitive keywords. These may expose internal information, TODO items, or credentials.",
                severity=Severity.MEDIUM if has_critical else Severity.LOW,
                evidence="\n".join(evidence_lines),
                fix="Remove all development comments, TODO notes, passwords, API keys, and debug information from production HTML. Implement a build process that strips comments.",
                module=self.name,
                url=url,
                cwe_id="CWE-615",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
                ],
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_meta_generator(self, url: str, body: str) -> List[Vulnerability]:
        """Check meta generator tag for CMS/framework disclosure."""
        vulnerabilities = []
        
        soup = BeautifulSoup(body, "lxml")
        generator = soup.find("meta", attrs={"name": "generator"})
        
        if generator and generator.get("content"):
            content = generator["content"]
            
            # Check for version numbers
            version_match = re.search(r"[\d.]+", content)
            has_version = version_match is not None
            
            vuln = Vulnerability(
                name="Meta Generator Tag Disclosure",
                description=f"The meta generator tag reveals the CMS or framework: '{content}'. " + 
                          ("Version numbers are exposed, making it easier to find applicable exploits." if has_version else ""),
                severity=Severity.LOW if has_version else Severity.INFO,
                evidence=f'<meta name="generator" content="{content}">',
                fix="Remove the meta generator tag from your HTML, or configure your CMS to not output it. For WordPress: add remove_action('wp_head', 'wp_generator') to functions.php",
                module=self.name,
                url=url,
                cwe_id="CWE-200",
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_debug_mode(self, url: str, body: str) -> List[Vulnerability]:
        """Check for debug mode indicators."""
        vulnerabilities = []
        
        for pattern, description in DEBUG_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                vuln = Vulnerability(
                    name="Debug Mode or Error Details Exposed",
                    description=f"The application appears to be exposing debug information or detailed errors ({description}). This can reveal sensitive system information to attackers.",
                    severity=Severity.HIGH,
                    evidence=f"Pattern matched: {match.group(0)[:100]}",
                    fix="Disable debug mode in production. Configure error handling to show generic error pages. For Django: DEBUG=False. For Laravel: APP_DEBUG=false. For PHP: display_errors=Off.",
                    module=self.name,
                    url=url,
                    cwe_id="CWE-489",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                    ],
                )
                vulnerabilities.append(vuln)
                break  # Only report once
        
        return vulnerabilities
    
    def _check_error_pages(self, url: str, body: str) -> List[Vulnerability]:
        """Check for framework-specific error pages."""
        vulnerabilities = []
        
        for pattern, severity, framework in ERROR_PAGE_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                vuln = Vulnerability(
                    name=f"Framework Error Page Exposed: {framework}",
                    description=f"A {framework} is exposed, potentially revealing sensitive application internals, stack traces, or configuration details.",
                    severity=severity,
                    evidence=f"Detected: {framework}",
                    fix="Configure custom error pages that don't expose framework details. Disable debug mode in production.",
                    module=self.name,
                    url=url,
                    cwe_id="CWE-209",
                )
                vulnerabilities.append(vuln)
                break
        
        return vulnerabilities
    
    def _check_source_maps(self, url: str, body: str) -> List[Vulnerability]:
        """Check for JavaScript source map references."""
        vulnerabilities = []
        
        # Check for source map references
        sourcemap_pattern = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)", re.IGNORECASE)
        matches = sourcemap_pattern.findall(body)
        
        if matches:
            vuln = Vulnerability(
                name="JavaScript Source Maps Exposed",
                description=f"Found {len(matches)} JavaScript source map reference(s). Source maps can reveal original source code, including comments and variable names.",
                severity=Severity.LOW,
                evidence=f"Source maps: {', '.join(matches[:3])}",
                fix="Remove source map references from production builds. Configure your build tool to not generate source maps for production, or ensure .map files are not served.",
                module=self.name,
                url=url,
                cwe_id="CWE-540",
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_sensitive_paths(self, url: str, session: requests.Session) -> List[Vulnerability]:
        """Check for common sensitive files/paths via robots.txt."""
        vulnerabilities = []
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            robots_url = f"{base_url}/robots.txt"
            
            response = session.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                content = response.text.lower()
                sensitive_disallows = []
                
                interesting = [
                    "admin", "administrator", "backup", "backups", "config", 
                    "database", "db", "debug", "api", "private", "secret", 
                    "test", "dev", "staging", ".git", ".env", ".svn",
                    "phpmyadmin", "wp-admin", "cpanel", "dashboard"
                ]
                
                for line in content.split("\n"):
                    if line.strip().startswith("disallow:"):
                        path = line.replace("disallow:", "").strip()
                        if any(i in path.lower() for i in interesting):
                            sensitive_disallows.append(path)
                
                if sensitive_disallows:
                    vuln = Vulnerability(
                        name="Sensitive Paths in robots.txt",
                        description=f"The robots.txt file reveals {len(sensitive_disallows)} potentially sensitive path(s). While robots.txt is public, it can reveal the existence of admin panels, backup directories, or API endpoints.",
                        severity=Severity.INFO,
                        evidence=f"Sensitive paths:\n" + "\n".join(f"• {p}" for p in sensitive_disallows[:10]),
                        fix="Consider if these paths should be listed in robots.txt. Ensure all sensitive paths are properly secured with authentication regardless of robots.txt status.",
                        module=self.name,
                        url=robots_url,
                        cwe_id="CWE-200",
                    )
                    vulnerabilities.append(vuln)
                    
        except requests.RequestException:
            pass
        
        return vulnerabilities
