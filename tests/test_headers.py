"""
test_headers.py — Tests for the security headers scanner module.

Each test checks a behavior of HeadersScanner:
- Missing headers are reported correctly
- Present headers are not reported
- The check runs only once per host (not per page)
- A Server header containing a version is treated as information disclosure
"""

import pytest

from scanner.crawler import Page
from scanner.findings import FindingsCollector
from scanner.headers import HeadersScanner


@pytest.fixture
def collector():
    return FindingsCollector()


# ---- Test 1: Missing headers are reported ---------------------------- #

def test_missing_headers_are_reported(collector):
    # A Page with no security headers
    page = Page("https://example.com/", 200, "<html></html>", headers={})
    HeadersScanner(collector).scan_page(page)

    params = [f.parameter for f in collector.all()]
    assert "Strict-Transport-Security" in params
    assert "Content-Security-Policy" in params
    assert "X-Frame-Options" in params
    assert "X-Content-Type-Options" in params
    assert "Referrer-Policy" in params


# ---- Test 2: Present headers are not reported ------------------------ #

def test_present_headers_not_reported(collector):
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "Server": "nginx",   # No version number, so it should not be flagged
    }
    page = Page("https://example.com/", 200, "<html></html>", headers=headers)
    HeadersScanner(collector).scan_page(page)

    # No findings should be created
    assert len(collector) == 0


# ---- Test 3: Per-host, not per-page ---------------------------------- #

def test_same_host_reported_only_once(collector):
    scanner = HeadersScanner(collector)
    # Three pages from the same domain, all without headers
    for path in ("/a", "/b", "/c"):
        page = Page(f"https://example.com{path}", 200, "", headers={})
        scanner.scan_page(page)

    # Findings should be generated only once for the domain, not three times
    urls = [f.url for f in collector.all()]
    # The number of unique URLs should be less than the total number of findings
    # Meaning: 6 headers × 1 domain = 6 findings, not 18
    assert len(urls) == len(set(urls)) or len(urls) <= 7


# ---- Test 4: Server version disclosure -------------------------------- #

def test_server_header_with_version_flagged(collector):
    page = Page("https://example.com/", 200, "", headers={"Server": "nginx/1.18.0"})
    HeadersScanner(collector).scan_page(page)

    info_findings = [f for f in collector.all() if f.category == "Information Disclosure"]
    assert len(info_findings) == 1
    assert "nginx/1.18.0" in info_findings[0].evidence


# ---- Test 5: Headers are case-insensitive ----------------------------- #

def test_headers_are_case_insensitive(collector):
    # Send headers using different casing — they should still be detected
    headers = {
        "STRICT-TRANSPORT-SECURITY": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
        "Server": "nginx",
    }
    page = Page("https://example.com/", 200, "", headers=headers)
    HeadersScanner(collector).scan_page(page)
    assert len(collector) == 0