"""
xss.py — Reflected XSS detection.
"""

import time
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .payloads import build_xss_payloads
from .findings import Finding
from .forms import extract_form_fields, submit_form


class XSSScanner:
    def __init__(self, session, collector, delay=0.3, timeout=10, logger=None):
        self.session = session
        self.collector = collector
        self.delay = delay
        self.timeout = timeout
        self.logger = logger

    def _log(self, msg):
        if self.logger:
            self.logger.debug(msg)

    @staticmethod
    def _marker():
        return "xsstest" + uuid.uuid4().hex[:10]

    def _is_reflected_unescaped(self, response_text, payload, marker):
        if response_text is None:
            return False
        return payload in response_text and marker in response_text

    def scan_url_params(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            marker = self._marker()
            for payload in build_xss_payloads(marker):
                new_params = {k: v[0] for k, v in params.items()}
                new_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                except Exception as e:
                    self._log(f"xss request failed: {e}")
                    continue
                time.sleep(self.delay)

                if self._is_reflected_unescaped(resp.text, payload, marker):
                    self.collector.add(Finding(
                        category="Reflected XSS",
                        severity="high",
                        cwe="CWE-79",
                        owasp="A03:2021 Injection",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Payload reflected unescaped in HTML response.",
                        description=f"Parameter '{param}' reflects attacker-controlled "
                                     "input without HTML-encoding.",
                    ))
                    break

    def scan_form(self, page_url, form):
        action, method, fields = extract_form_fields(page_url, form)
        text_fields = [f for f in fields
                       if f["type"] not in ("submit", "checkbox", "radio", "hidden", "file")]
        if not text_fields:
            return

        for target_field in text_fields:
            marker = self._marker()
            for payload in build_xss_payloads(marker):
                data = {f["name"]: (f["value"] or "test") for f in fields if f["name"]}
                data[target_field["name"]] = payload
                try:
                    resp = submit_form(self.session, action, method, data, timeout=self.timeout)
                except Exception as e:
                    self._log(f"xss form request failed: {e}")
                    continue
                time.sleep(self.delay)

                if self._is_reflected_unescaped(resp.text, payload, marker):
                    self.collector.add(Finding(
                        category="Reflected XSS",
                        severity="high",
                        cwe="CWE-79",
                        owasp="A03:2021 Injection",
                        url=action,
                        parameter=target_field["name"],
                        payload=payload,
                        evidence="Payload reflected unescaped in HTML response.",
                        description=f"Form field '{target_field['name']}' on {page_url} "
                                     "reflects attacker-controlled input without HTML-encoding.",
                    ))
                    break