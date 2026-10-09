"""
test_scanners.py — SQLi / XSS / Auth tests using the shared app_url fixture.

The Flask app and its DB are started once in conftest.py; these tests reuse it.
"""

import requests
from bs4 import BeautifulSoup

from vulynx.sqli import SQLiScanner
from vulynx.xss import XSSScanner
from vulynx.auth import AuthScanner
from vulynx.findings import FindingsCollector


# ---- SQLi ----------------------------------------------------------- #

def test_sqli_error_based_detected(app_url):
    collector = FindingsCollector()
    SQLiScanner(requests.Session(), collector, delay=0.02).scan_url_params(f"{app_url}/search?q=test")
    assert "SQL Injection" in [f.category for f in collector.all()]


def test_sqli_safe_endpoint_not_flagged(app_url):
    collector = FindingsCollector()
    SQLiScanner(requests.Session(), collector, delay=0.02).scan_url_params(f"{app_url}/search_safe?q=test")
    assert len(collector) == 0


# ---- XSS ------------------------------------------------------------ #

def test_xss_reflected_detected(app_url):
    collector = FindingsCollector()
    XSSScanner(requests.Session(), collector, delay=0.02).scan_url_params(f"{app_url}/greet?name=World")
    assert "Reflected XSS" in [f.category for f in collector.all()]


def test_xss_escaped_not_flagged(app_url):
    collector = FindingsCollector()
    XSSScanner(requests.Session(), collector, delay=0.02).scan_url_params(f"{app_url}/greet_safe?name=World")
    assert len(collector) == 0


# ---- Broken Auth ---------------------------------------------------- #

def test_auth_csrf_missing_detected(app_url):
    session = requests.Session()
    resp = session.get(f"{app_url}/login")
    form = BeautifulSoup(resp.text, "html.parser").find("form")
    collector = FindingsCollector()
    AuthScanner(session, collector).scan_form(f"{app_url}/login", form)
    assert any("csrf" in f.description.lower() for f in collector.all())


def test_auth_username_enumeration_detected(app_url):
    session = requests.Session()
    resp = session.get(f"{app_url}/login")
    form = BeautifulSoup(resp.text, "html.parser").find("form")
    collector = FindingsCollector()
    AuthScanner(session, collector).scan_form(f"{app_url}/login", form)
    assert any("enumerate" in f.description.lower() for f in collector.all())


def test_auth_cookie_without_httponly_detected(app_url):
    session = requests.Session()
    session.post(f"{app_url}/login", data={"username": "admin", "password": "secret123"})
    collector = FindingsCollector()
    AuthScanner(session, collector).check_session_cookies(f"{app_url}/login")
    assert any("HttpOnly" in f.evidence for f in collector.all())