"""
Professional logging setup for EthiScan.

Uses coloredlogs for beautiful console output and supports file logging.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

import coloredlogs


# Custom log format with colors
DEFAULT_FORMAT = "%(asctime)s │ %(name)-12s │ %(levelname)-8s │ %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Color scheme for different log levels
LEVEL_STYLES = {
    "debug": {"color": "cyan"},
    "info": {"color": "green"},
    "warning": {"color": "yellow", "bold": True},
    "error": {"color": "red", "bold": True},
    "critical": {"color": "red", "bold": True, "background": "white"},
}

FIELD_STYLES = {
    "asctime": {"color": "white", "faint": True},
    "name": {"color": "blue"},
    "levelname": {"color": "white", "bold": True},
}


def setup_logger(
    name: str = "ethiscan",
    level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
) -> logging.Logger:
    """
    Set up a professional logger with colored console output.
    
    Args:
        name: Logger name (usually 'ethiscan' or module name).
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to log file for persistent logging.
        log_format: Optional custom format string.
        
    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Use custom or default format
    fmt = log_format or DEFAULT_FORMAT
    
    # Install coloredlogs for console output
    coloredlogs.install(
        level=level.upper(),
        logger=logger,
        fmt=fmt,
        datefmt=DATE_FORMAT,
        level_styles=LEVEL_STYLES,
        field_styles=FIELD_STYLES,
        stream=sys.stderr,
    )
    
    # Add file handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        file_handler.setFormatter(logging.Formatter(fmt, DATE_FORMAT))
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "ethiscan") -> logging.Logger:
    """
    Get an existing logger or create a new one.
    
    Args:
        name: Logger name to retrieve.
        
    Returns:
        Logger instance.
    """
    logger = logging.getLogger(name)
    
    # If logger has no handlers, set up with defaults
    if not logger.handlers:
        return setup_logger(name)
    
    return logger


class ScanLogger:
    """
    Specialized logger for scan operations with structured output.
    
    Provides methods for logging scan progress, findings, and errors
    with consistent formatting.
    """
    
    def __init__(self, name: str = "ethiscan.scan"):
        """Initialize scan logger."""
        self.logger = get_logger(name)
    
    def scan_start(self, url: str, modules: list[str]) -> None:
        """Log scan start with target and modules."""
        self.logger.info(f"🎯 Starting scan on: {url}")
        self.logger.info(f"📦 Modules enabled: {', '.join(modules)}")
    
    def scan_complete(self, url: str, vuln_count: int, duration: float) -> None:
        """Log scan completion with summary."""
        self.logger.info(f"✅ Scan complete: {url}")
        self.logger.info(f"📊 Found {vuln_count} vulnerabilities in {duration:.2f}s")
    
    def module_start(self, module_name: str) -> None:
        """Log module execution start."""
        self.logger.debug(f"▶️  Running module: {module_name}")
    
    def module_complete(self, module_name: str, findings: int) -> None:
        """Log module completion with findings count."""
        if findings > 0:
            self.logger.warning(f"🔍 {module_name}: Found {findings} issue(s)")
        else:
            self.logger.info(f"✓ {module_name}: No issues found")
    
    def vulnerability_found(self, name: str, severity: str) -> None:
        """Log individual vulnerability discovery."""
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }
        emoji = severity_emoji.get(severity.upper(), "⚪")
        self.logger.warning(f"{emoji} [{severity}] {name}")
    
    def error(self, message: str, exc: Optional[Exception] = None) -> None:
        """Log error with optional exception."""
        if exc:
            self.logger.error(f"❌ {message}: {str(exc)}")
        else:
            self.logger.error(f"❌ {message}")
