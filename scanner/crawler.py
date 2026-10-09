"""
crawler.py - Same-origin crawler that collects pages and their HTML forms.
"""

import time
import urllib.robotparser
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup


class Page:
    def __init__(self, url, status_code, html, headers=None):
        self.url = url
        self.status_code = status_code
        self.html = html
        self.headers = headers or {}
        self.soup = BeautifulSoup(html, "html.parser") if html else None

    @property
    def forms(self):
        if not self.soup:
            return []
        return self.soup.find_all("form")

    @property
    def links(self):
        if not self.soup:
            return []
        return [a.get("href") for a in self.soup.find_all("a", href=True)]


class Crawler:
    def __init__(
        self,
        start_url: str,
        session: requests.Session,
        max_pages: int = 50,
        delay: float = 0.5,
        respect_robots: bool = True,
        timeout: float = 10,
        logger=None,
    ):
        self.start_url = start_url
        self.domain = urlparse(start_url).netloc
        self.session = session
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.logger = logger
        self.visited = set()
        self.pages = []
        self.robots = self._init_robots(respect_robots)

    # ---- robots.txt --------------------------------------------------- #

    def _init_robots(self, respect_robots: bool):
        """Fetch robots.txt through the scan session (same headers, cookies, timeout)."""
        if not respect_robots:
            return None
        robots_url = urljoin(self.start_url, "/robots.txt")
        try:
            resp = self.session.get(robots_url, timeout=self.timeout)
        except requests.RequestException:
            return None
        if resp.status_code != 200:
            return None  # missing/unreadable robots.txt means no restrictions
        robots = urllib.robotparser.RobotFileParser()
        robots.parse(resp.text.splitlines())
        return robots

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.netloc != self.domain:
            return False
        if self.robots and not self.robots.can_fetch("*", url):
            return False
        return True

    def _log(self, msg: str):
        if self.logger:
            self.logger.debug(msg)

    # ---- network ------------------------------------------------------ #

    def _fetch(self, url: str):
        try:
            return self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            self._log(f"crawl error {url}: {e}")
            return None

    # ---- link extraction --------------------------------------------- #

    def _extract_links(self, page: Page, base_url: str):
        links = []
        for href in page.links:
            if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            absolute = urljoin(base_url, href)
            absolute, _ = urldefrag(absolute)
            links.append(absolute)
        return links

    # ---- main loop ---------------------------------------------------- #

    def crawl(self):
        queue = deque([self.start_url])
        seen = {self.start_url}

        while queue and len(self.pages) < self.max_pages:
            url = queue.popleft()
            clean_url, _ = urldefrag(url)
            if clean_url in self.visited:
                continue

            resp = self._fetch(clean_url)
            if resp is None:
                continue

            final_url = resp.url
            if final_url in self.visited:
                continue
            if not self._in_scope(final_url):
                self._log(f"redirected out of scope: {final_url}")
                continue

            self.visited.add(clean_url)
            self.visited.add(final_url)

            content_type = resp.headers.get("Content-Type", "")
            is_html = "html" in content_type or content_type == ""
            html = resp.text if is_html else ""

            page = Page(final_url, resp.status_code, html, headers=dict(resp.headers))
            self.pages.append(page)
            self._log(
                f"crawled [{resp.status_code}] {final_url} "
                f"({len(page.forms)} forms, {len(page.links)} links)"
            )

            for link in self._extract_links(page, final_url):
                if self._in_scope(link) and link not in seen:
                    seen.add(link)
                    queue.append(link)

            if queue:
                time.sleep(self.delay)

        return self.pages
