"""
Configuration management for EthiScan.

Handles loading and validating YAML configuration files with Pydantic.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field


class ScannerConfig(BaseModel):
    """Scanner-specific configuration."""
    
    timeout: int = Field(default=10, ge=1, le=120, description="Request timeout in seconds")
    max_redirects: int = Field(default=5, ge=0, le=20, description="Maximum redirects to follow")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    user_agent: str = Field(
        default="EthiScan/1.0 (Ethical Security Scanner)",
        description="User-Agent header for requests"
    )


class LoggingConfig(BaseModel):
    """Logging configuration."""
    
    level: str = Field(default="INFO", description="Log level")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string"
    )
    file: Optional[str] = Field(default=None, description="Log file path")


class ModuleConfig(BaseModel):
    """Configuration for individual modules."""
    
    enabled: bool = Field(default=True, description="Whether module is enabled")
    payloads: Optional[List[str]] = Field(default=None, description="Custom payloads for active modules")


class ReportConfig(BaseModel):
    """Report generation configuration."""
    
    include_evidence: bool = Field(default=True, description="Include evidence in reports")
    include_fixes: bool = Field(default=True, description="Include fix recommendations")
    html_theme: str = Field(default="bootstrap", description="HTML report theme")


class SecurityHeadersConfig(BaseModel):
    """Security headers configuration."""
    
    required: List[str] = Field(default_factory=list, description="Required security headers")
    recommended: List[str] = Field(default_factory=list, description="Recommended security headers")


class Config(BaseModel):
    """Main configuration container."""
    
    language: str = Field(default="en", description="Language: 'en' or 'pt-br'")
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    modules: Dict[str, ModuleConfig] = Field(default_factory=dict)
    report: ReportConfig = Field(default_factory=ReportConfig)
    security_headers: SecurityHeadersConfig = Field(default_factory=SecurityHeadersConfig)


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to configuration file. If None, uses default config.
        
    Returns:
        Config object with loaded or default settings.
        
    Raises:
        FileNotFoundError: If specified config file doesn't exist.
        yaml.YAMLError: If config file has invalid YAML syntax.
    """
    if config_path is None:
        # Use default config from package
        default_path = Path(__file__).parent.parent.parent / "config" / "default.yaml"
        if default_path.exists():
            config_path = str(default_path)
        else:
            return Config()
    
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    
    # Convert modules dict to ModuleConfig objects
    if "modules" in data:
        modules_data = data["modules"]
        data["modules"] = {
            name: ModuleConfig(**cfg) if isinstance(cfg, dict) else ModuleConfig(enabled=bool(cfg))
            for name, cfg in modules_data.items()
        }
    # Initialize language
    config = Config(**data)
    
    # Set up i18n
    from ethiscan.core.i18n import set_language
    set_language(config.language)
    
    return config


def get_default_config() -> Config:
    """Get default configuration without loading from file."""
    return Config(
        security_headers=SecurityHeadersConfig(
            required=[
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Strict-Transport-Security",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Permissions-Policy",
            ],
            recommended=[
                "X-Permitted-Cross-Domain-Policies",
                "Cross-Origin-Embedder-Policy",
                "Cross-Origin-Opener-Policy",
                "Cross-Origin-Resource-Policy",
            ]
        )
    )
