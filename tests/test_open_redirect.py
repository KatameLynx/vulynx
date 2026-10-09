"""
test_open_redirect.py — Tests for the Open Redirect module.

A small in-memory Flask server is started with one intentionally vulnerable
endpoint and one secure endpoint, and the scanner is tested against them.
"""

import socket
import threading
import time

import pytest
import requests
from flask import Flask, redirect, request, Response

from scanner.findings import FindingsCollector
from scanner.open_redirect import OpenRedirectScanner


# ---- Test Flask app -------------------------------------------------- #

app = Flask(__name__)


@app.route("/vulnerable")
def vulnerable():
    target = request.args.get("next", "/")
    return redirect(target, code=302)


@app.route("/safe")
def safe():
    target = request.args.get("next", "/")
    normalized = target.replace("\\", "/")
    if (normalized.startswith("/")
            and not normalized.startswith("//")
            and "://" not in normalized
            and ":" not in normalized):
        return redirect(normalized, code=302)
    return "Invalid redirect target", 400


@app.route("/no-redirect")
def no_redirect():
    return "Nothing to see here"


# ---- Server setup ---------------------------------------------------- #

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

HOST = "127.0.0.1"
PORT = _free_port()
BASE = f"http://{HOST}:{PORT}"


@pytest.fixture(scope="module", autouse=True)
def live_server():
    thread = threading.Thread(
        target=lambda: app.run(host=HOST, port=PORT, debug=False, use_reloader=False),
        daemon=True,
    )
    thread.start()
    for _ in range(20):
        try:
            requests.get(BASE + "/", timeout=1)
            break
        except requests.RequestException:
            time.sleep(0.25)
    yield


@pytest.fixture
def collector():
    return FindingsCollector()


@pytest.fixture
def session():
    return requests.Session()


# ---- Tests ----------------------------------------------------------- #

def test_open_redirect_detected(session, collector):
    scanner = OpenRedirectScanner(session, collector, delay=0.02)
    scanner.scan_url_params(f"{BASE}/vulnerable?next=/home")
    cats = [f.category for f in collector.all()]
    assert "Open Redirect" in cats


def test_safe_endpoint_not_flagged(session, collector):
    scanner = OpenRedirectScanner(session, collector, delay=0.02)
    scanner.scan_url_params(f"{BASE}/safe?next=/home")
    assert len(collector) == 0


def test_param_not_used_not_flagged(session, collector):
    scanner = OpenRedirectScanner(session, collector, delay=0.02)
    scanner.scan_url_params(f"{BASE}/no-redirect?redirect=https://example.com")
    assert len(collector) == 0


def test_non_redirect_param_ignored(session, collector):
    scanner = OpenRedirectScanner(session, collector, delay=0.02)
    scanner.scan_url_params(f"{BASE}/vulnerable?q=hello&next=/home")
    findings = collector.all()
    assert all(f.parameter == "next" for f in findings)