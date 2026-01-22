"""
Unit tests for EthiScan modules.
"""

import pytest
from unittest.mock import Mock, MagicMock

from ethiscan.modules.__base__ import BaseModule, get_all_modules
from ethiscan.modules.headers import HeadersModule
from ethiscan.modules.cookies import CookiesModule
from ethiscan.core.models import Severity


class TestBaseModule:
    """Tests for BaseModule class."""
    
    def test_get_all_modules(self):
        """Test that all modules are discovered."""
        modules = get_all_modules()
        
        assert "headers" in modules
        assert "cookies" in modules
        assert "server_info" in modules
        assert "xss" in modules
        assert "sqli" in modules
    
    def test_module_properties(self):
        """Test module properties are implemented."""
        modules = get_all_modules()
        
        for name, module in modules.items():
            assert hasattr(module, "name")
            assert hasattr(module, "description")
            assert hasattr(module, "is_active")
            assert module.name == name


class TestHeadersModule:
    """Tests for HeadersModule."""
    
    def test_module_properties(self):
        """Test headers module properties."""
        module = HeadersModule()
        
        assert module.name == "headers"
        assert module.is_active == False
        assert "security headers" in module.description.lower()
    
    def test_scan_missing_headers(self):
        """Test detection of missing security headers."""
        module = HeadersModule()
        
        # Create mock response without security headers
        mock_response = Mock()
        mock_response.headers = {
            "Content-Type": "text/html",
        }
        
        mock_session = Mock()
        
        vulns = module.scan(
            url="https://example.com",
            session=mock_session,
            response=mock_response,
        )
        
        # Should find missing headers
        assert len(vulns) > 0
        
        # Check that CSP is reported as missing
        csp_vuln = next((v for v in vulns if "Content-Security-Policy" in v.name), None)
        assert csp_vuln is not None
    
    def test_scan_with_headers(self):
        """Test when security headers are present."""
        module = HeadersModule()
        
        # Create mock response with all security headers
        mock_response = Mock()
        mock_response.headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
        }
        
        mock_session = Mock()
        
        vulns = module.scan(
            url="https://example.com",
            session=mock_session,
            response=mock_response,
        )
        
        # Should find no missing headers
        missing_header_vulns = [v for v in vulns if "Missing" in v.name]
        assert len(missing_header_vulns) == 0


class TestCookiesModule:
    """Tests for CookiesModule."""
    
    def test_module_properties(self):
        """Test cookies module properties."""
        module = CookiesModule()
        
        assert module.name == "cookies"
        assert module.is_active == False
        assert "cookie" in module.description.lower()
    
    def test_scan_no_cookies(self):
        """Test scan with no cookies."""
        module = CookiesModule()
        
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.cookies = []
        
        mock_session = Mock()
        
        vulns = module.scan(
            url="https://example.com",
            session=mock_session,
            response=mock_response,
        )
        
        assert len(vulns) == 0


class TestActiveModules:
    """Tests for active module identification."""
    
    def test_xss_is_active(self):
        """Test that XSS module is marked as active."""
        modules = get_all_modules()
        
        assert modules["xss"].is_active == True
    
    def test_sqli_is_active(self):
        """Test that SQLi module is marked as active."""
        modules = get_all_modules()
        
        assert modules["sqli"].is_active == True
    
    def test_passive_modules(self):
        """Test that passive modules are not active."""
        modules = get_all_modules()
        
        assert modules["headers"].is_active == False
        assert modules["cookies"].is_active == False
        assert modules["server_info"].is_active == False
