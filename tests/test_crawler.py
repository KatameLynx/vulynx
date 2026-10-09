"""Crawler behaviour and the full crawl -> scan -> report pipeline."""

import json
from urllib.parse import urlparse

import requests

import vulynx
from scanner.crawler import Crawler


def _paths(pages):
    return {urlparse(p.url).path + ("?" + urlparse(p.url).query if urlparse(p.url).query else "")
            for p in pages}


def test_crawler_discovers_linked_pages_and_forms(app_url):
    pages = Crawler(app_url, requests.Session(), max_pages=50, delay=0).crawl()
    paths = _paths(pages)
    assert {"/", "/login", "/login_safe", "/search?q=admin", "/greet?name=World"} <= paths
    login = next(p for p in pages if urlparse(p.url).path == "/login")
    assert len(login.forms) == 1


def test_crawler_stays_in_scope(app_url):
    pages = Crawler(app_url, requests.Session(), max_pages=50, delay=0).crawl()
    assert all(urlparse(p.url).netloc == urlparse(app_url).netloc for p in pages)


def test_crawler_respects_max_pages(app_url):
    pages = Crawler(app_url, requests.Session(), max_pages=3, delay=0).crawl()
    assert len(pages) == 3


def test_crawler_respects_robots_txt(app_url):
    respected = Crawler(app_url, requests.Session(), delay=0, respect_robots=True).crawl()
    assert "/private" not in _paths(respected)

    ignored = Crawler(app_url, requests.Session(), delay=0, respect_robots=False).crawl()
    assert "/private" in _paths(ignored)


def test_full_scan_pipeline(app_url, tmp_path, monkeypatch):
    out = str(tmp_path / "scan")
    monkeypatch.setattr("sys.argv", ["vulynx", "-u", app_url, "--confirm", "--delay", "0", "-o", out])
    vulynx.main()

    report = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))
    found = {(f["category"], urlparse(f["url"]).path) for f in report["findings"]}

    # real problems are found through the crawler ...
    assert ("SQL Injection", "/search") in found
    assert ("SQL Injection", "/blind") in found
    assert ("Reflected XSS", "/greet") in found
    assert any(cat == "Broken Authentication" and path == "/login" for cat, path in found)

    # ... and safe endpoints produce no injection findings
    injection = {"SQL Injection", "Reflected XSS"}
    safe_hits = [f for f in report["findings"]
                 if f["category"] in injection
                 and urlparse(f["url"]).path in ("/search_safe", "/greet_safe", "/dynamic",
                                                "/sql_docs", "/login_safe")]
    assert safe_hits == []
    assert (tmp_path / "scan.html").exists()
