#!/usr/bin/env python3
"""
Vulynx - web application vulnerability scanner.

Examples:
  vulynx -u https://your-test-site.com
  vulynx -u https://your-test-site.com --confirm --max-pages 100 --delay 1.0
  vulynx -u https://your-test-site.com --confirm --cookie "session=abc123"Only scan applications you own or have explicit written 

authorization to test.
"""

import argparse
import logging
import sys
from datetime import datetime

import requests

from vulynx.crawler import Crawler
from vulynx.findings import FindingsCollector
from vulynx.sqli import SQLiScanner
from vulynx.xss import XSSScanner
from vulynx.auth import AuthScanner
from vulynx.headers import HeadersScanner
from vulynx.open_redirect import OpenRedirectScanner
from vulynx.report import write_json_report, write_html_report


def setup_logging(verbose: bool):
    logger = logging.getLogger("vulynx")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
    return logger


def confirm_authorization(target_url, skip_prompt: bool) -> bool:
    banner = (
        "\n" + "=" * 70 + "\n"
        "  AUTHORIZATION CHECK\n"
        "=" * 70 + "\n"
        f"  Target: {target_url}\n\n"
        "  This tool will actively send SQL injection and XSS test payloads\n"
        "  to this target and submit its forms. Only proceed if you own this\n"
        "  application or have explicit written authorization to test it.\n"
        "=" * 70
    )
    print(banner)
    if skip_prompt:
        return True
    answer = input("\nType 'yes' to confirm you are authorized to scan this target: ").strip().lower()
    return answer == "yes"


def parse_args():
    p = argparse.ArgumentParser(
        description="Vulynx: web app vulnerability scanner (SQLi, XSS, open redirect, auth, headers)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-u", "--url", required=True, help="Target base URL, e.g. https://example.com")
    p.add_argument("-o", "--outfile", default=None, help="Output base filename (default: scan_<timestamp>)")
    p.add_argument("--confirm", action="store_true",
                   help="Skip the interactive authorization prompt")
    p.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    p.add_argument("--delay", type=float, default=0.4, help="Delay between requests in seconds (default: 0.4)")
    p.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--ignore-robots", action="store_true", help="Don't respect robots.txt")
    p.add_argument("--enable-time-based", action="store_true",
                   help="Enable time-based blind SQLi tests (adds latency; off by default)")
    p.add_argument("--cookie", action="append", default=[],
                   help="Send an authenticated session cookie as name=value (repeatable)")
    p.add_argument("--header", action="append", default=[],
                   help="Extra request header as 'Name: value' (repeatable)")
    p.add_argument("--known-user", action="append", default=[],
                   help="Username that exists on the target, used by the username-enumeration "
                        "check (repeatable; default: admin). One failed login per name is sent.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()


def build_session(cookies, headers):
    session = requests.Session()
    session.headers.update({"User-Agent": "vulynx/1.0 (authorized security testing)"})
    for h in headers:
        if ":" not in h:
            continue
        name, value = h.split(":", 1)
        session.headers[name.strip()] = value.strip()
    for c in cookies:
        if "=" not in c:
            continue
        name, value = c.split("=", 1)
        session.cookies.set(name.strip(), value.strip())
    return session


def main():
    args = parse_args()

    if not confirm_authorization(args.url, args.confirm):
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)

    outfile_base = args.outfile or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    logger = setup_logging(args.verbose)

    session = build_session(args.cookie, args.header)
    collector = FindingsCollector()

    logger.info(f"Crawling {args.url} (max_pages={args.max_pages}, delay={args.delay}s)")
    crawler = Crawler(
        args.url, session,
        max_pages=args.max_pages,
        delay=args.delay,
        respect_robots=not args.ignore_robots,
        timeout=args.timeout,
        logger=logger,
    )
    pages = crawler.crawl()
    logger.info(f"Crawl complete: {len(pages)} page(s) discovered")

    sqli_scanner = SQLiScanner(session, collector, delay=args.delay, timeout=args.timeout,
                               enable_time_based=args.enable_time_based, logger=logger)
    xss_scanner = XSSScanner(session, collector, delay=args.delay, timeout=args.timeout, logger=logger)
    auth_scanner = AuthScanner(session, collector, timeout=args.timeout, logger=logger,
                               known_users=args.known_user)
    headers_scanner = HeadersScanner(collector, logger=logger)
    open_redirect_scanner = OpenRedirectScanner(session, collector, delay=args.delay, timeout=args.timeout, logger=logger)

    total_forms = sum(len(p.forms) for p in pages)
    logger.info(f"Testing {len(pages)} page(s) / {total_forms} form(s)...")

    for page in pages:
        if page.status_code >= 400:
            continue

        logger.debug(f"Scanning URL params on {page.url}")
        sqli_scanner.scan_url_params(page.url)
        xss_scanner.scan_url_params(page.url)
        open_redirect_scanner.scan_url_params(page.url)

        for form in page.forms:
            logger.debug(f"Scanning form on {page.url}")
            sqli_scanner.scan_form(page.url, form)
            xss_scanner.scan_form(page.url, form)
            auth_scanner.scan_form(page.url, form)

        auth_scanner.check_session_cookies(page.url)
        headers_scanner.scan_page(page)

    logger.info(f"Scan complete: {len(collector)} finding(s)")

    write_json_report(collector, args.url, f"{outfile_base}.json")
    write_html_report(collector, args.url, f"{outfile_base}.html")

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Target:         {args.url}")
    print(f"Pages crawled:  {len(pages)}")
    print(f"Total findings: {len(collector)}")
    for sev, count in sorted(collector.count_by_severity().items(),
                             key=lambda x: -order.get(x[0], 0)):
        print(f"  {sev:10s}  {count}")
    print(f"JSON report:    {outfile_base}.json")
    print(f"HTML report:    {outfile_base}.html")
    print("=" * 60)


if __name__ == "__main__":
    main()
