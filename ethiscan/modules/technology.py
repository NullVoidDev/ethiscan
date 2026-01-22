"""
Technology Fingerprinting Scanner Module.

Detects web frameworks, CMS, CDNs, and other technologies.
"""

import re
from typing import Dict, List, Optional, Set

import requests
from bs4 import BeautifulSoup

from ethiscan.core.models import Severity, Vulnerability
from ethiscan.modules.__base__ import BaseModule, register_module


# Technology signatures
HEADER_SIGNATURES = {
    # CDNs
    "cf-ray": ("Cloudflare", "CDN"),
    "x-vercel-id": ("Vercel", "CDN/Hosting"),
    "x-amz-cf-id": ("Amazon CloudFront", "CDN"),
    "x-amz-request-id": ("Amazon S3/AWS", "Cloud"),
    "x-azure-ref": ("Microsoft Azure", "Cloud"),
    "x-cache": ("CDN Cache", "CDN"),
    "x-served-by": ("Fastly", "CDN"),
    "x-akamai-transformed": ("Akamai", "CDN"),
    
    # Frameworks
    "x-powered-by": ("Framework", "Server"),
    "x-aspnet-version": ("ASP.NET", "Framework"),
    "x-aspnetmvc-version": ("ASP.NET MVC", "Framework"),
    "x-drupal-cache": ("Drupal", "CMS"),
    "x-generator": ("Generator", "CMS"),
    "x-pingback": ("WordPress", "CMS"),
    "x-litespeed-cache": ("LiteSpeed", "Server"),
    "x-turbo-charged-by": ("LiteSpeed", "Server"),
}

# Server header patterns
SERVER_PATTERNS = {
    r"Apache/[\d.]+": "Apache",
    r"nginx/[\d.]+": "Nginx",
    r"Microsoft-IIS/[\d.]+": "Microsoft IIS",
    r"LiteSpeed": "LiteSpeed",
    r"openresty": "OpenResty",
    r"cloudflare": "Cloudflare",
    r"AmazonS3": "Amazon S3",
    r"gunicorn": "Gunicorn",
    r"Werkzeug": "Werkzeug/Flask",
    r"uvicorn": "Uvicorn/FastAPI",
    r"Phusion Passenger": "Passenger",
    r"Cowboy": "Cowboy/Elixir",
}

# X-Powered-By patterns
POWERED_BY_PATTERNS = {
    r"PHP/[\d.]+": "PHP",
    r"ASP\.NET": "ASP.NET",
    r"Express": "Express.js",
    r"Next\.js": "Next.js",
    r"Servlet": "Java Servlet",
    r"JSF": "JavaServer Faces",
    r"Phusion Passenger": "Passenger",
    r"PleskLin": "Plesk",
}

# HTML/Body patterns for framework detection
HTML_SIGNATURES = {
    # Next.js
    r"/_next/static": ("Next.js", "Framework"),
    r"__NEXT_DATA__": ("Next.js", "Framework"),
    r"_next/image": ("Next.js", "Framework"),
    
    # React
    r'data-reactroot': ("React", "Framework"),
    r'__REACT_DEVTOOLS': ("React", "Framework"),
    
    # Vue.js
    r'data-v-[a-f0-9]+': ("Vue.js", "Framework"),
    r'__VUE__': ("Vue.js", "Framework"),
    
    # Angular
    r'ng-version': ("Angular", "Framework"),
    r'ng-app': ("AngularJS", "Framework"),
    
    # WordPress
    r'/wp-content/': ("WordPress", "CMS"),
    r'/wp-includes/': ("WordPress", "CMS"),
    r'wp-json': ("WordPress", "CMS"),
    
    # Drupal
    r'Drupal\.settings': ("Drupal", "CMS"),
    r'/sites/default/files': ("Drupal", "CMS"),
    
    # Joomla
    r'/media/jui/': ("Joomla", "CMS"),
    r'Joomla!': ("Joomla", "CMS"),
    
    # Laravel
    r'laravel_session': ("Laravel", "Framework"),
    r'XSRF-TOKEN': ("Laravel/Symfony", "Framework"),
    
    # Django
    r'csrfmiddlewaretoken': ("Django", "Framework"),
    r'__admin_media_prefix__': ("Django", "Framework"),
    
    # Ruby on Rails
    r'csrf-token': ("Ruby on Rails", "Framework"),
    r'data-turbolinks': ("Ruby on Rails", "Framework"),
    
    # jQuery
    r'jquery[.-][\d.]+\.(?:min\.)?js': ("jQuery", "Library"),
    
    # Bootstrap
    r'bootstrap[.-][\d.]+': ("Bootstrap", "Library"),
    
    # Google
    r'googletagmanager\.com': ("Google Tag Manager", "Analytics"),
    r'google-analytics\.com': ("Google Analytics", "Analytics"),
    r'gtag/js': ("Google Analytics 4", "Analytics"),
}

# Meta generator patterns
META_GENERATOR_PATTERNS = {
    r"WordPress[\s]*([\d.]+)?": "WordPress",
    r"Drupal[\s]*([\d.]+)?": "Drupal",
    r"Joomla!?[\s]*([\d.]+)?": "Joomla",
    r"TYPO3[\s]*([\d.]+)?": "TYPO3",
    r"Wix\.com": "Wix",
    r"Squarespace": "Squarespace",
    r"Blogger": "Blogger",
    r"Ghost[\s]*([\d.]+)?": "Ghost",
    r"Hugo[\s]*([\d.]+)?": "Hugo",
    r"Jekyll": "Jekyll",
    r"Gatsby": "Gatsby",
}


@register_module
class TechnologyModule(BaseModule):
    """
    Technology fingerprinting scanner.
    
    Detects web frameworks, CMS platforms, CDNs, and other
    technologies used by the target application.
    """
    
    @property
    def name(self) -> str:
        """Module identifier."""
        return "technology"
    
    @property
    def description(self) -> str:
        """Module description."""
        return "Fingerprints web frameworks, CMS, CDNs, and technologies"
    
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
        Scan for technology fingerprints.
        
        Args:
            url: Target URL.
            session: HTTP session.
            response: Pre-fetched response (optional).
            
        Returns:
            List of technology disclosure findings.
        """
        vulnerabilities: List[Vulnerability] = []
        detected_techs: Dict[str, Set[str]] = {}  # tech_name -> set of sources
        
        # Use provided response or fetch new one
        if response is None:
            try:
                response = session.get(url, timeout=10)
            except requests.RequestException:
                return vulnerabilities
        
        # Check headers
        self._check_headers(response.headers, detected_techs)
        
        # Check HTML body
        if response.text:
            self._check_html(response.text, detected_techs)
            self._check_meta_generator(response.text, detected_techs)
        
        # Generate vulnerability reports
        if detected_techs:
            # Group by category
            frameworks = []
            cms = []
            servers = []
            cdns = []
            libraries = []
            analytics = []
            others = []
            
            for tech, sources in detected_techs.items():
                source_str = ", ".join(sources)
                if "Framework" in source_str:
                    frameworks.append(tech)
                elif "CMS" in source_str:
                    cms.append(tech)
                elif "Server" in source_str:
                    servers.append(tech)
                elif "CDN" in source_str or "Cloud" in source_str:
                    cdns.append(tech)
                elif "Library" in source_str:
                    libraries.append(tech)
                elif "Analytics" in source_str:
                    analytics.append(tech)
                else:
                    others.append(tech)
            
            # Create summary vulnerability
            all_techs = list(detected_techs.keys())
            evidence_lines = [f"• {tech}: {', '.join(sources)}" for tech, sources in detected_techs.items()]
            
            vuln = Vulnerability(
                name="Technology Stack Fingerprinting",
                description=f"Detected {len(all_techs)} technologies. This information could help attackers identify known vulnerabilities in specific versions.",
                severity=Severity.INFO,
                evidence="\n".join(evidence_lines[:15]),  # Limit evidence
                fix="Consider removing or obfuscating technology headers and fingerprints. Keep all detected technologies updated to their latest versions.",
                module=self.name,
                url=url,
                cwe_id="CWE-200",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                ],
            )
            vulnerabilities.append(vuln)
            
            # Specific warnings for version disclosure
            version_disclosed = [t for t in all_techs if re.search(r'[\d.]+', t)]
            if version_disclosed:
                vuln = Vulnerability(
                    name="Software Version Disclosure",
                    description=f"Specific version numbers were disclosed for: {', '.join(version_disclosed[:5])}. Version disclosure helps attackers find applicable exploits.",
                    severity=Severity.LOW,
                    evidence=f"Versions detected: {', '.join(version_disclosed[:5])}",
                    fix="Hide version numbers in server responses. For Apache: ServerTokens Prod. For Nginx: server_tokens off. Remove X-Powered-By headers.",
                    module=self.name,
                    url=url,
                    cwe_id="CWE-200",
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_headers(self, headers: dict, detected: Dict[str, Set[str]]) -> None:
        """Check response headers for technology signatures."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check known header signatures
        for header, (tech, category) in HEADER_SIGNATURES.items():
            if header in headers_lower:
                value = headers_lower[header]
                if header == "x-powered-by":
                    # Parse X-Powered-By more specifically
                    for pattern, tech_name in POWERED_BY_PATTERNS.items():
                        match = re.search(pattern, value, re.IGNORECASE)
                        if match:
                            detected.setdefault(match.group(0), set()).add(f"Header ({category})")
                else:
                    detected.setdefault(tech, set()).add(f"Header: {header}")
        
        # Check Server header
        server = headers_lower.get("server", "")
        if server:
            for pattern, tech in SERVER_PATTERNS.items():
                match = re.search(pattern, server, re.IGNORECASE)
                if match:
                    detected.setdefault(match.group(0), set()).add("Server header")
                    break
    
    def _check_html(self, html: str, detected: Dict[str, Set[str]]) -> None:
        """Check HTML body for technology signatures."""
        for pattern, (tech, category) in HTML_SIGNATURES.items():
            if re.search(pattern, html, re.IGNORECASE):
                detected.setdefault(tech, set()).add(f"HTML ({category})")
    
    def _check_meta_generator(self, html: str, detected: Dict[str, Set[str]]) -> None:
        """Check meta generator tag."""
        soup = BeautifulSoup(html, "lxml")
        generator = soup.find("meta", attrs={"name": "generator"})
        
        if generator and generator.get("content"):
            content = generator["content"]
            for pattern, tech in META_GENERATOR_PATTERNS.items():
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    detected.setdefault(match.group(0), set()).add("Meta generator")
                    break
            else:
                # Unknown generator
                detected.setdefault(content, set()).add("Meta generator")
    
    def get_detected_technologies(
        self,
        url: str,
        session: requests.Session,
        response: Optional[requests.Response] = None,
    ) -> Dict[str, Set[str]]:
        """
        Get detected technologies without generating vulnerabilities.
        
        Useful for embedding technology info in reports.
        """
        detected: Dict[str, Set[str]] = {}
        
        if response is None:
            try:
                response = session.get(url, timeout=10)
            except requests.RequestException:
                return detected
        
        self._check_headers(response.headers, detected)
        if response.text:
            self._check_html(response.text, detected)
            self._check_meta_generator(response.text, detected)
        
        return detected
