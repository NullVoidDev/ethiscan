"""
Base module class for EthiScan scanner modules.

All scanner modules must inherit from BaseModule and implement the scan method.
"""

import importlib
import pkgutil
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type

import requests

from ethiscan.core.models import Vulnerability


class BaseModule(ABC):
    """
    Abstract base class for all scanner modules.
    
    All modules must inherit from this class and implement:
    - name: Module identifier
    - description: Human-readable description
    - is_active: Whether module performs active/intrusive testing
    - scan(): Main scanning method
    """
    
    def __init__(self) -> None:
        """Initialize the module."""
        self._enabled: bool = True
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique module identifier.
        
        Returns:
            Module name string (lowercase, no spaces).
        """
        ...
    
    @property
    @abstractmethod
    def description(self) -> str:
        """
        Human-readable module description.
        
        Returns:
            Description string explaining what the module checks.
        """
        ...
    
    @property
    @abstractmethod
    def is_active(self) -> bool:
        """
        Whether this module performs active/intrusive testing.
        
        Active modules may modify data or trigger security alerts.
        They require explicit user confirmation before running.
        
        Returns:
            True if active scanning, False if passive only.
        """
        ...
    
    @property
    def enabled(self) -> bool:
        """Check if module is enabled."""
        return self._enabled
    
    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable the module."""
        self._enabled = value
    
    @abstractmethod
    def scan(
        self,
        url: str,
        session: requests.Session,
        response: Optional[requests.Response] = None,
    ) -> List[Vulnerability]:
        """
        Perform security scan on target URL.
        
        Args:
            url: Target URL to scan.
            session: Configured requests Session.
            response: Optional pre-fetched response for passive scanning.
            
        Returns:
            List of discovered Vulnerability objects.
        """
        ...
    
    def __repr__(self) -> str:
        """String representation of module."""
        mode = "ACTIVE" if self.is_active else "PASSIVE"
        status = "enabled" if self.enabled else "disabled"
        return f"<{self.__class__.__name__}({self.name}) [{mode}] {status}>"


# Module registry
_module_registry: Dict[str, Type[BaseModule]] = {}


def register_module(module_class: Type[BaseModule]) -> Type[BaseModule]:
    """
    Decorator to register a module class.
    
    Args:
        module_class: Module class to register.
        
    Returns:
        The same module class (allows use as decorator).
    """
    instance = module_class()
    _module_registry[instance.name] = module_class
    return module_class


def get_all_modules() -> Dict[str, BaseModule]:
    """
    Get all registered module instances.
    
    This function dynamically imports all modules from the modules package
    and returns instances of each.
    
    Returns:
        Dictionary mapping module names to module instances.
    """
    # Import all modules in the package to trigger registration
    import ethiscan.modules
    
    package_path = ethiscan.modules.__path__
    for _, module_name, _ in pkgutil.iter_modules(package_path):
        if not module_name.startswith("_"):
            try:
                importlib.import_module(f"ethiscan.modules.{module_name}")
            except ImportError:
                pass
    
    return {name: cls() for name, cls in _module_registry.items()}


def get_module_by_name(name: str) -> Optional[BaseModule]:
    """
    Get a specific module by name.
    
    Args:
        name: Module name to retrieve.
        
    Returns:
        Module instance or None if not found.
    """
    # Ensure modules are loaded
    get_all_modules()
    
    if name in _module_registry:
        return _module_registry[name]()
    return None


def get_passive_modules() -> Dict[str, BaseModule]:
    """
    Get all passive (non-intrusive) modules.
    
    Returns:
        Dictionary of passive module instances.
    """
    all_modules = get_all_modules()
    return {name: mod for name, mod in all_modules.items() if not mod.is_active}


def get_active_modules() -> Dict[str, BaseModule]:
    """
    Get all active (intrusive) modules.
    
    Returns:
        Dictionary of active module instances.
    """
    all_modules = get_all_modules()
    return {name: mod for name, mod in all_modules.items() if mod.is_active}
