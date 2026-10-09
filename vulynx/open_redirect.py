"""
open_redirect.py — Detects Open Redirect vulnerabilities.

URL parameters that appear to control redirect destinations (next, url,
return, ...) are replaced with an external URL to check whether the server
redirects to that external domain.

Note: Requests are sent with allow_redirects=False so we can inspect the
3xx response and Location header ourselves instead of letting requests
follow the redirect automatically.
"""

import time
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .payloads import REDIRECT_PARAM_HINTS, OPEN_REDIRECT_TEST_DOMAIN
from .findings import Finding


class OpenRedirectScanner:
    def __init__(self, session, collector, delay=0.3, timeout=10, logger=None):
        self.session = session
        self.collector = collector
        self.delay = delay
        self.timeout = timeout
        self.logger = logger

    def _log(self, msg):
        if self.logger:
            self.logger.debug(msg)

    # ---- helpers ----------------------------------------------------- #

    def _build_payloads(self, marker: str):
        """Build several external URL variants to bypass simple filters."""
        return [
            f"https://{marker}.{OPEN_REDIRECT_TEST_DOMAIN}/",
            f"//{marker}.{OPEN_REDIRECT_TEST_DOMAIN}/",       # protocol-relative
            f"https:{marker}.{OPEN_REDIRECT_TEST_DOMAIN}/",   # Without // (some servers normalize it)
            f"/\\/{marker}.{OPEN_REDIRECT_TEST_DOMAIN}/",     # Backslash filter bypass
        ]

    @staticmethod
    def _is_redirect_param(name: str) -> bool:
        n = name.lower()
        return any(hint == n or hint in n for hint in REDIRECT_PARAM_HINTS)

    def _check_response_for_redirect(self, resp, marker: str):
        """Check whether the response redirects to our test domain."""
        # Case 1: 3xx response with a Location header
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if marker in location:
                return f"HTTP {resp.status_code} redirect to: {location}"

        # Case 2: Meta refresh in the HTML
        body = (resp.text or "").lower()
        if "http-equiv" in body and "refresh" in body and marker.lower() in body:
            return "HTML <meta http-equiv='refresh'> redirect in body"

        # Case 3: JavaScript redirect (less common, but possible)
        if "window.location" in body and marker.lower() in body:
            return "JavaScript window.location redirect in body"

        return None

    # ---- URL parameters ---------------------------------------------- #

    def scan_url_params(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            if not self._is_redirect_param(param):
                continue

            marker = "or" + uuid.uuid4().hex[:8]

            for payload in self._build_payloads(marker):
                new_params = {k: v[0] for k, v in params.items()}
                new_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))

                try:
                    resp = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        allow_redirects=False,   # Important: we want to inspect the 3xx response ourselves
                    )
                except Exception as e:
                    self._log(f"open redirect request failed: {e}")
                    continue
                time.sleep(self.delay)

                evidence = self._check_response_for_redirect(resp, marker)
                if evidence:
                    self.collector.add(Finding(
                        category="Open Redirect",
                        severity="medium",
                        cwe="CWE-601",
                        owasp="A01:2021 Broken Access Control",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=evidence,
                        description=f"Parameter '{param}' redirects to an "
                                     "attacker-controlled external URL without "
                                     "validation. This enables phishing and "
                                     "bypass of domain-based trust checks.",
                    ))
                    return  # One payload is enough; move to the next parameter