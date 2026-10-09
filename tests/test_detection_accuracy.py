"""
Accuracy tests: besides finding real issues, the scanners must stay quiet on
dynamic pages, pages that only talk about SQL errors, and non-state-changing forms.
"""

import requests
from bs4 import BeautifulSoup

from vulynx.auth import AuthScanner
from vulynx.findings import FindingsCollector
from vulynx.forms import extract_form_fields
from vulynx.sqli import SQLiScanner
from vulynx.textdiff import differs


def _form(html):
    return BeautifulSoup(html, "html.parser").find("form")


# ---- SQLi: boolean-based blind, judged against a baseline -------------- #

def test_blind_sqli_detected_without_any_error_message(app_url):
    collector = FindingsCollector()
    SQLiScanner(requests.Session(), collector, delay=0).scan_url_params(f"{app_url}/blind?name=admin")
    findings = collector.all()
    assert findings, "boolean-based blind SQLi should be detected"
    assert all(f.category == "SQL Injection" for f in findings)
    assert "boolean" in findings[0].description.lower()


def test_dynamic_page_not_flagged_as_sqli(app_url):
    collector = FindingsCollector()
    SQLiScanner(requests.Session(), collector, delay=0).scan_url_params(f"{app_url}/dynamic?q=a")
    assert len(collector) == 0


def test_sql_error_text_already_on_page_not_flagged(app_url):
    collector = FindingsCollector()
    SQLiScanner(requests.Session(), collector, delay=0).scan_url_params(f"{app_url}/sql_docs?q=x")
    assert len(collector) == 0


# ---- Auth: username enumeration ---------------------------------------- #

def test_generic_login_error_and_csrf_token_not_flagged(app_url):
    session = requests.Session()
    page = session.get(f"{app_url}/login_safe")
    collector = FindingsCollector()
    AuthScanner(session, collector).scan_form(f"{app_url}/login_safe", _form(page.text))
    text = " ".join(f.description.lower() for f in collector.all())
    assert "enumerate" not in text and "csrf" not in text


def test_enumeration_uses_configured_known_user(app_url):
    session = requests.Session()
    page = session.get(f"{app_url}/login")

    collector = FindingsCollector()
    AuthScanner(session, collector, known_users=["admin"]).check_username_enumeration(
        f"{app_url}/login", _form(page.text))
    assert any("enumerate" in f.description for f in collector.all())

    # A user that does not exist behaves like any other unknown user -> no finding.
    collector = FindingsCollector()
    AuthScanner(session, collector, known_users=["nobody-here"]).check_username_enumeration(
        f"{app_url}/login", _form(page.text))
    assert len(collector) == 0


# ---- Auth: CSRF only for state-changing forms ---------------------------- #

def _csrf_findings(html):
    form = _form(html)
    action, method, fields = extract_form_fields("http://t.example/page", form)
    collector = FindingsCollector()
    AuthScanner(requests.Session(), collector).check_csrf_token("http://t.example/page", action, method, fields)
    return collector.all()


def test_csrf_missing_on_state_changing_post_flagged():
    findings = _csrf_findings(
        '<form method="post" action="/profile"><input name="email"><input type="submit"></form>')
    assert len(findings) == 1
    assert findings[0].category == "Missing CSRF Protection"


def test_csrf_post_search_form_not_flagged():
    assert _csrf_findings(
        '<form method="post" action="/s"><input name="q"><input type="submit"></form>') == []


def test_csrf_form_with_token_not_flagged():
    assert _csrf_findings(
        '<form method="post"><input type="hidden" name="csrf_token" value="x">'
        '<input name="email"></form>') == []


def test_csrf_get_form_not_flagged():
    assert _csrf_findings('<form method="get"><input name="email"></form>') == []


# ---- textdiff helper -------------------------------------------------------- #

def test_textdiff_ignores_markup_and_whitespace():
    assert not differs("<p>Hello   world</p>", "<div>hello world</div>")


def test_textdiff_ignores_small_timestamp_change():
    page = "<p>" + " ".join(f"word{i}" for i in range(100)) + " time 12:00:01</p>"
    other = page.replace("12:00:01", "12:00:02")
    assert not differs(page, other)


def test_textdiff_detects_changed_message():
    assert differs("<p>No such user.</p>", "<p>Invalid password.</p>")
