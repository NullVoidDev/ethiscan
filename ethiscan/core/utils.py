"""
Utility functions for EthiScan.

Provides URL validation, HTTP session management, and helper functions.
"""

import re
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ethiscan.core.config import Config, load_config


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate and normalize a URL.
    
    Args:
        url: URL string to validate.
        
    Returns:
        Tuple of (is_valid, normalized_url_or_error).
    """
    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    try:
        parsed = urlparse(url)
        
        # Check required components
        if not parsed.scheme or parsed.scheme not in ("http", "https"):
            return False, "Invalid URL scheme (must be http or https)"
        
        if not parsed.netloc:
            return False, "Invalid URL: missing domain"
        
        # Basic domain validation
        domain = parsed.netloc.split(":")[0]  # Remove port if present
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$|^localhost$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            # Allow localhost and IP addresses too
            if domain not in ("localhost",) and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                return False, f"Invalid domain: {domain}"
        
        # Reconstruct normalized URL
        normalized = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.path:
            normalized += parsed.path
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        return True, normalized
        
    except Exception as e:
        return False, f"URL parsing error: {str(e)}"


def resolve_ip(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address.
    
    Args:
        hostname: Domain name to resolve.
        
    Returns:
        IP address string or None if resolution fails.
    """
    try:
        # Extract just the hostname from URL if needed
        if "://" in hostname:
            hostname = urlparse(hostname).netloc
        hostname = hostname.split(":")[0]  # Remove port
        
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def create_session(
    config: Optional[Config] = None,
    custom_headers: Optional[Dict[str, str]] = None,
) -> requests.Session:
    """
    Create a configured requests Session with retry logic.
    
    Args:
        config: Optional Config object. Uses default config if None.
        custom_headers: Optional additional headers to add.
        
    Returns:
        Configured requests.Session instance.
    """
    if config is None:
        config = load_config()
    
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set default headers
    session.headers.update({
        "User-Agent": config.scanner.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    
    # Add custom headers
    if custom_headers:
        session.headers.update(custom_headers)
    
    # Configure SSL verification and redirects
    session.verify = config.scanner.verify_ssl
    session.max_redirects = config.scanner.max_redirects
    
    return session


def safe_request(
    session: requests.Session,
    url: str,
    method: str = "GET",
    timeout: int = 10,
    **kwargs: Any,
) -> Tuple[Optional[requests.Response], Optional[str]]:
    """
    Perform a safe HTTP request with error handling.
    
    Args:
        session: requests Session to use.
        url: Target URL.
        method: HTTP method (GET, POST, etc.).
        timeout: Request timeout in seconds.
        **kwargs: Additional arguments for requests.
        
    Returns:
        Tuple of (response, error_message). One will be None.
    """
    try:
        response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=True,
            **kwargs,
        )
        return response, None
        
    except requests.exceptions.Timeout:
        return None, f"Request timeout after {timeout}s"
    except requests.exceptions.SSLError as e:
        return None, f"SSL error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection error: {str(e)}"
    except requests.exceptions.TooManyRedirects:
        return None, "Too many redirects"
    except requests.exceptions.RequestException as e:
        return None, f"Request failed: {str(e)}"


def extract_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
    """
    Extract form information from HTML.
    
    Args:
        html: HTML content to parse.
        base_url: Base URL for resolving relative URLs.
        
    Returns:
        List of form dictionaries with action, method, and inputs.
    """
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html, "lxml")
    forms = []
    
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url
        
        method = form.get("method", "GET").upper()
        
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_type = inp.get("type", "text")
            input_name = inp.get("name", "")
            input_value = inp.get("value", "")
            
            if input_name:  # Only include named inputs
                inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_value,
                })
        
        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })
    
    return forms


def get_base_url(url: str) -> str:
    """
    Get the base URL (scheme + netloc) from a full URL.
    
    Args:
        url: Full URL string.
        
    Returns:
        Base URL string.
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_header_name(header: str) -> str:
    """
    Normalize HTTP header name to Title-Case.
    
    Args:
        header: Header name string.
        
    Returns:
        Normalized header name.
    """
    return "-".join(word.capitalize() for word in header.split("-"))
