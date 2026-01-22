"""
Web Scanner - Main orchestrator for vulnerability scanning.

Coordinates all scanning modules and aggregates results.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional

import requests

from ethiscan.core.config import Config, load_config
from ethiscan.core.logger import ScanLogger, get_logger
from ethiscan.core.models import ScanResult, ScanTarget, Vulnerability
from ethiscan.core.utils import create_session, resolve_ip, safe_request, validate_url
from ethiscan.modules import get_all_modules
from ethiscan.modules.__base__ import BaseModule


class WebScanner:
    """
    Main web vulnerability scanner.
    
    Orchestrates scanning modules, manages HTTP sessions, and
    aggregates scan results.
    
    Attributes:
        config: Scanner configuration.
        modules: Dictionary of enabled scanning modules.
        active_mode: Whether active scanning is enabled.
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        active_mode: bool = False,
    ) -> None:
        """
        Initialize the web scanner.
        
        Args:
            config: Optional configuration. Uses default if None.
            active_mode: Enable active (intrusive) scanning modules.
        """
        self.config = config or load_config()
        self.active_mode = active_mode
        self.logger = ScanLogger()
        self._logger = get_logger("ethiscan.scanner")
        
        # Load and filter modules
        self._all_modules = get_all_modules()
        self.modules: Dict[str, BaseModule] = {}
        self._load_modules()
    
    def _load_modules(self) -> None:
        """Load and filter modules based on configuration and mode."""
        for name, module in self._all_modules.items():
            # Check if module is enabled in config
            if name in self.config.modules:
                if not self.config.modules[name].enabled:
                    self._logger.debug(f"Module '{name}' disabled in config")
                    continue
            
            # Only include active modules if active_mode is enabled
            if module.is_active and not self.active_mode:
                self._logger.debug(f"Skipping active module '{name}' (active mode disabled)")
                continue
            
            self.modules[name] = module
            self._logger.debug(f"Loaded module: {name}")
    
    def scan(
        self,
        url: str,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> ScanResult:
        """
        Perform a full vulnerability scan on the target URL.
        
        Args:
            url: Target URL to scan.
            custom_headers: Optional custom HTTP headers.
            
        Returns:
            ScanResult containing all findings.
            
        Raises:
            ValueError: If URL is invalid.
        """
        # Validate URL
        is_valid, result = validate_url(url)
        if not is_valid:
            raise ValueError(f"Invalid URL: {result}")
        
        url = result  # Use normalized URL
        
        start_time = time.time()
        
        # Log scan start
        module_names = list(self.modules.keys())
        self.logger.scan_start(url, module_names)
        
        # Create session
        session = create_session(self.config, custom_headers)
        
        # Resolve IP address
        ip_address = resolve_ip(url)
        
        # Initial request for passive scanning
        initial_response, error = safe_request(
            session, url, timeout=self.config.scanner.timeout
        )
        
        if error:
            self._logger.error(f"Failed to fetch {url}: {error}")
            # Return empty result with error
            return ScanResult(
                target=ScanTarget(url=url, ip_address=ip_address),
                vulnerabilities=[],
                scan_time=datetime.now(),
                duration=time.time() - start_time,
                modules_run=[],
                active_scan=self.active_mode,
            )
        
        # Extract server info from initial response
        server_header = initial_response.headers.get("Server", "")
        
        # Run all modules
        all_vulnerabilities: List[Vulnerability] = []
        modules_run: List[str] = []
        
        for name, module in self.modules.items():
            try:
                self.logger.module_start(name)
                
                # Run the module
                vulnerabilities = module.scan(
                    url=url,
                    session=session,
                    response=initial_response,
                )
                
                # Log results
                self.logger.module_complete(name, len(vulnerabilities))
                
                # Log individual vulnerabilities
                for vuln in vulnerabilities:
                    self.logger.vulnerability_found(vuln.name, vuln.severity)
                
                all_vulnerabilities.extend(vulnerabilities)
                modules_run.append(name)
                
            except Exception as e:
                self.logger.error(f"Module '{name}' failed", e)
                self._logger.exception(f"Error in module {name}")
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log completion
        self.logger.scan_complete(url, len(all_vulnerabilities), duration)
        
        # Build and return result
        return ScanResult(
            target=ScanTarget(
                url=url,
                ip_address=ip_address,
                server=server_header or None,
                technologies=self._detect_technologies(initial_response),
            ),
            vulnerabilities=all_vulnerabilities,
            scan_time=datetime.now(),
            duration=duration,
            modules_run=modules_run,
            active_scan=self.active_mode,
        )
    
    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect technologies from response headers."""
        technologies = []
        
        headers = response.headers
        
        # Common technology headers
        tech_headers = {
            "X-Powered-By": lambda v: v,
            "Server": lambda v: v.split("/")[0] if "/" in v else v,
            "X-AspNet-Version": lambda v: f"ASP.NET {v}",
            "X-AspNetMvc-Version": lambda v: f"ASP.NET MVC {v}",
        }
        
        for header, extractor in tech_headers.items():
            if header in headers:
                try:
                    tech = extractor(headers[header])
                    if tech and tech not in technologies:
                        technologies.append(tech)
                except Exception:
                    pass
        
        return technologies
    
    def list_modules(self) -> Dict[str, Dict]:
        """
        Get information about all available modules.
        
        Returns:
            Dictionary with module info including name, description, and type.
        """
        all_mods = get_all_modules()
        return {
            name: {
                "name": module.name,
                "description": module.description,
                "type": "ACTIVE" if module.is_active else "PASSIVE",
                "enabled": name in self.modules,
            }
            for name, module in all_mods.items()
        }
    
    def get_passive_modules(self) -> List[str]:
        """Get list of passive module names."""
        return [name for name, mod in self.modules.items() if not mod.is_active]
    
    def get_active_modules(self) -> List[str]:
        """Get list of active module names."""
        return [name for name, mod in self.modules.items() if mod.is_active]
