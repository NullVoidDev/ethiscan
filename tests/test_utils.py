"""
Unit tests for EthiScan utility functions.
"""

import pytest

from ethiscan.core.utils import validate_url, get_base_url, normalize_header_name


class TestValidateUrl:
    """Tests for URL validation."""
    
    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        is_valid, result = validate_url("https://example.com")
        assert is_valid == True
        assert result == "https://example.com"
    
    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        is_valid, result = validate_url("http://example.com")
        assert is_valid == True
        assert result == "http://example.com"
    
    def test_url_without_scheme(self):
        """Test URL without scheme adds https."""
        is_valid, result = validate_url("example.com")
        assert is_valid == True
        assert result.startswith("https://")
    
    def test_url_with_path(self):
        """Test URL with path."""
        is_valid, result = validate_url("https://example.com/path/to/page")
        assert is_valid == True
        assert "/path/to/page" in result
    
    def test_url_with_query(self):
        """Test URL with query parameters."""
        is_valid, result = validate_url("https://example.com?id=123")
        assert is_valid == True
        assert "?id=123" in result
    
    def test_localhost(self):
        """Test localhost URL."""
        is_valid, result = validate_url("http://localhost")
        assert is_valid == True
    
    def test_ip_address(self):
        """Test IP address URL."""
        is_valid, result = validate_url("http://192.168.1.1")
        assert is_valid == True
    
    def test_url_with_port(self):
        """Test URL with port number."""
        is_valid, result = validate_url("http://localhost:8080")
        assert is_valid == True


class TestGetBaseUrl:
    """Tests for get_base_url function."""
    
    def test_simple_url(self):
        """Test simple URL."""
        base = get_base_url("https://example.com/path")
        assert base == "https://example.com"
    
    def test_url_with_port(self):
        """Test URL with port."""
        base = get_base_url("http://localhost:8080/page")
        assert base == "http://localhost:8080"
    
    def test_url_with_query(self):
        """Test URL with query is stripped."""
        base = get_base_url("https://example.com/path?id=1")
        assert base == "https://example.com"


class TestNormalizeHeaderName:
    """Tests for header name normalization."""
    
    def test_lowercase_header(self):
        """Test lowercase header normalization."""
        result = normalize_header_name("content-type")
        assert result == "Content-Type"
    
    def test_uppercase_header(self):
        """Test uppercase header normalization."""
        result = normalize_header_name("CONTENT-TYPE")
        assert result == "Content-Type"
    
    def test_mixed_case_header(self):
        """Test mixed case header normalization."""
        result = normalize_header_name("Content-security-POLICY")
        assert result == "Content-Security-Policy"
