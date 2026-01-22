"""
Light Web Crawler for EthiScan.

Crawls internal links with configurable depth for multi-page scanning.
"""

import re
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from ethiscan.core.logger import get_logger


class Crawler:
    """
    Light web crawler for discovering internal pages.
    
    Features:
    - Configurable crawl depth (0-3)
    - Same-domain only
    - Maximum page limit
    - Optional robots.txt respect
    """
    
    def __init__(
        self,
        max_depth: int = 1,
        max_pages: int = 20,
        respect_robots: bool = True,
        delay: float = 0.5,
    ) -> None:
        """
        Initialize the crawler.
        
        Args:
            max_depth: Maximum crawl depth (0 = start URL only).
            max_pages: Maximum number of pages to crawl.
            respect_robots: Whether to check robots.txt.
            delay: Delay between requests in seconds.
        """
        self.max_depth = min(max_depth, 3)  # Cap at 3
        self.max_pages = min(max_pages, 50)  # Cap at 50
        self.respect_robots = respect_robots
        self.delay = delay
        self.logger = get_logger("ethiscan.crawler")
        
        self._visited: Set[str] = set()
        self._disallowed: Set[str] = set()
        self._base_domain: str = ""
    
    def crawl(
        self,
        start_url: str,
        session: requests.Session,
        progress_callback: Optional[callable] = None,
    ) -> List[str]:
        """
        Crawl starting from the given URL.
        
        Args:
            start_url: URL to start crawling from.
            session: Configured requests session.
            progress_callback: Optional callback(current, total, url) for progress.
            
        Returns:
            List of discovered URLs (including start_url).
        """
        self._visited.clear()
        self._disallowed.clear()
        
        # Parse base domain
        parsed = urlparse(start_url)
        self._base_domain = parsed.netloc
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check robots.txt if enabled
        if self.respect_robots:
            self._parse_robots(base_url, session)
        
        # Start crawling
        urls_to_scan: List[str] = []
        self._crawl_recursive(start_url, session, 0, urls_to_scan, progress_callback)
        
        return urls_to_scan
    
    def _crawl_recursive(
        self,
        url: str,
        session: requests.Session,
        depth: int,
        results: List[str],
        progress_callback: Optional[callable],
    ) -> None:
        """Recursively crawl URLs."""
        # Check limits
        if len(results) >= self.max_pages:
            return
        
        if depth > self.max_depth:
            return
        
        # Normalize URL
        url = self._normalize_url(url)
        
        # Skip if already visited
        if url in self._visited:
            return
        
        # Skip if disallowed by robots.txt
        if self._is_disallowed(url):
            self.logger.debug(f"Skipping (robots.txt): {url}")
            return
        
        # Mark as visited
        self._visited.add(url)
        results.append(url)
        
        # Progress callback
        if progress_callback:
            progress_callback(len(results), self.max_pages, url)
        
        self.logger.debug(f"Crawled ({depth}/{self.max_depth}): {url}")
        
        # Don't crawl deeper if at max depth
        if depth >= self.max_depth:
            return
        
        # Fetch and parse page
        try:
            import time
            if self.delay > 0 and len(results) > 1:
                time.sleep(self.delay)
            
            response = session.get(url, timeout=10)
            
            # Only parse HTML responses
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                return
            
            # Extract links
            links = self._extract_links(response.text, url)
            
            # Crawl each link
            for link in links:
                if len(results) >= self.max_pages:
                    break
                self._crawl_recursive(link, session, depth + 1, results, progress_callback)
                
        except requests.RequestException as e:
            self.logger.debug(f"Failed to crawl {url}: {e}")
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract internal links from HTML."""
        links = []
        soup = BeautifulSoup(html, "lxml")
        
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            
            # Skip empty, anchors, javascript, mailto
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            
            # Resolve relative URLs
            full_url = urljoin(base_url, href)
            
            # Parse and validate
            parsed = urlparse(full_url)
            
            # Only same domain
            if parsed.netloc != self._base_domain:
                continue
            
            # Skip certain file types
            if re.search(r"\.(jpg|jpeg|png|gif|svg|ico|css|js|pdf|zip|tar|gz|mp3|mp4|webp|woff|woff2|ttf|eot)$", 
                        parsed.path, re.IGNORECASE):
                continue
            
            # Normalize and add
            normalized = self._normalize_url(full_url)
            if normalized not in self._visited and normalized not in links:
                links.append(normalized)
        
        return links[:20]  # Limit links per page
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison."""
        parsed = urlparse(url)
        
        # Remove fragment
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Remove trailing slash for consistency (except for root)
        if normalized.endswith("/") and parsed.path != "/":
            normalized = normalized[:-1]
        
        # Keep query string if present
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        return normalized
    
    def _parse_robots(self, base_url: str, session: requests.Session) -> None:
        """Parse robots.txt for disallowed paths."""
        try:
            robots_url = f"{base_url}/robots.txt"
            response = session.get(robots_url, timeout=5)
            
            if response.status_code != 200:
                return
            
            current_agent = None
            for line in response.text.split("\n"):
                line = line.strip().lower()
                
                if line.startswith("user-agent:"):
                    agent = line.split(":", 1)[1].strip()
                    current_agent = agent
                
                elif line.startswith("disallow:") and current_agent in ("*", "ethiscan"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        self._disallowed.add(path)
                        
        except requests.RequestException:
            pass
    
    def _is_disallowed(self, url: str) -> bool:
        """Check if URL is disallowed by robots.txt."""
        if not self._disallowed:
            return False
        
        parsed = urlparse(url)
        path = parsed.path
        
        for disallowed in self._disallowed:
            if path.startswith(disallowed):
                return True
        
        return False


def crawl_urls(
    start_url: str,
    session: requests.Session,
    depth: int = 1,
    max_pages: int = 20,
    progress_callback: Optional[callable] = None,
) -> List[str]:
    """
    Convenience function to crawl URLs.
    
    Args:
        start_url: Starting URL.
        session: Requests session.
        depth: Crawl depth.
        max_pages: Maximum pages.
        progress_callback: Progress callback.
        
    Returns:
        List of URLs found.
    """
    crawler = Crawler(max_depth=depth, max_pages=max_pages)
    return crawler.crawl(start_url, session, progress_callback)
