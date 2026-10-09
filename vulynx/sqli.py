import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .payloads import (
    SQLI_ERROR_PAYLOADS,
    SQLI_BOOLEAN_PAYLOADS,
    SQLI_TIME_PAYLOADS,
    SQLI_TIME_DELAY_THRESHOLD_SEC,
    SQL_ERROR_SIGNATURES,
)
from .findings import Finding
from .forms import extract_form_fields, submit_form
from .textdiff import differs

_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)


class SQLiScanner:
    def __init__(self, session, collector, delay=0.3, timeout=10,
                 enable_time_based=False, logger=None):
        self.session = session
        self.collector = collector
        self.delay = delay
        self.timeout = timeout
        self.enable_time_based = enable_time_based
        self.logger = logger

    def _log(self, msg):
        if self.logger:
            self.logger.debug(msg)

    def _get(self, url, **kwargs):
        """GET with error handling and rate limiting. Returns None on failure."""
        try:
            resp = self.session.get(url, timeout=kwargs.pop("timeout", self.timeout), **kwargs)
        except Exception as e:
            self._log(f"sqli request failed: {e}")
            return None
        time.sleep(self.delay)
        return resp

    # ---- URL parameters ------------------------------------------------ #

    def scan_url_params(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        # Baseline: how the page looks for the unmodified URL. Used to ignore
        # error text that is already on the page and to judge boolean tests.
        baseline = self._get(url)
        baseline_text = baseline.text if baseline is not None else None

        for param in params:
            self._test_param_error_based(url, parsed, params, param, baseline_text or "")
            if baseline_text is not None:
                self._test_param_boolean_based(url, parsed, params, param, baseline_text)
            if self.enable_time_based:
                self._test_param_time_based(url, parsed, params, param)

    def _build_url(self, parsed, params, param, value):
        new_params = {k: v[0] for k, v in params.items()}
        new_params[param] = value
        return urlunparse(parsed._replace(query=urlencode(new_params)))

    def _test_param_error_based(self, url, parsed, params, param, baseline_text):
        if _ERROR_RE.search(baseline_text):
            self._log(f"sqli error-based skipped for {url}: SQL error text already on the page")
            return
        for payload in SQLI_ERROR_PAYLOADS:
            resp = self._get(self._build_url(parsed, params, param, payload))
            if resp is None:
                continue
            match = _ERROR_RE.search(resp.text or "")
            if match:
                self.collector.add(Finding(
                    category="SQL Injection",
                    severity="critical",
                    cwe="CWE-89",
                    owasp="A03:2021 Injection",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Database error signature matched: '{match.group(0)}'",
                    description="A database error was reflected in the response "
                                 "after injecting a SQL metacharacter, indicating "
                                 "unsanitised input reaching a SQL query (error-based SQLi).",
                ))
                return

    def _test_param_boolean_based(self, url, parsed, params, param, baseline_text):
        """
        Boolean-based blind SQLi, judged against a baseline:

          * the page must be stable (two plain requests look the same),
          * the TRUE payload (original value + AND 1=1) must look like the normal page,
          * the FALSE payload (original value + AND 1=2) must look different,
          * and the FALSE result must repeat, so one-off noise is not reported.
        """
        original = params[param][0]

        again = self._get(url)
        if again is None:
            return
        if differs(baseline_text, again.text):
            self._log(f"sqli boolean-based skipped for {url}: page content is dynamic")
            return

        for true_suffix, false_suffix in SQLI_BOOLEAN_PAYLOADS:
            true_url = self._build_url(parsed, params, param, original + true_suffix)
            false_url = self._build_url(parsed, params, param, original + false_suffix)

            true_resp = self._get(true_url)
            false_resp = self._get(false_url)
            if true_resp is None or false_resp is None:
                continue
            if differs(baseline_text, true_resp.text):
                continue
            if not differs(baseline_text, false_resp.text):
                continue

            false_again = self._get(false_url)
            if false_again is None or differs(false_resp.text, false_again.text):
                continue

            self.collector.add(Finding(
                category="SQL Injection",
                severity="high",
                cwe="CWE-89",
                owasp="A03:2021 Injection",
                url=url,
                parameter=param,
                payload=f"{original + true_suffix!r} vs {original + false_suffix!r}",
                evidence="The page is stable and the TRUE-condition payload matches the "
                         "normal page, but the FALSE-condition payload changes it (repeatable).",
                description="Possible boolean-based blind SQL injection.",
            ))
            return

    def _test_param_time_based(self, url, parsed, params, param):
        for payload in SQLI_TIME_PAYLOADS:
            test_url = self._build_url(parsed, params, param, payload)
            start = time.time()
            resp = self._get(test_url, timeout=self.timeout + 10)
            if resp is None:
                continue
            elapsed = time.time() - start - self.delay
            if elapsed >= SQLI_TIME_DELAY_THRESHOLD_SEC:
                self.collector.add(Finding(
                    category="SQL Injection",
                    severity="high",
                    cwe="CWE-89",
                    owasp="A03:2021 Injection",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Response delayed {elapsed:.1f}s after time-based payload.",
                    description="Possible time-based blind SQL injection.",
                ))
                return

    # ---- HTML forms --------------------------------------------------- #

    def scan_form(self, page_url, form):
        action, method, fields = extract_form_fields(page_url, form)
        text_fields = [f for f in fields
                       if f["type"] not in ("submit", "checkbox", "radio", "hidden", "file")]
        if not text_fields:
            return

        defaults = {f["name"]: (f["value"] or "test") for f in fields if f["name"]}
        try:
            baseline = submit_form(self.session, action, method, defaults, timeout=self.timeout)
            time.sleep(self.delay)
            if _ERROR_RE.search(baseline.text or ""):
                self._log(f"sqli form check skipped for {action}: SQL error text already present")
                return
        except Exception as e:
            self._log(f"sqli form baseline failed: {e}")
            return

        for target_field in text_fields:
            for payload in SQLI_ERROR_PAYLOADS:
                data = dict(defaults)
                data[target_field["name"]] = payload
                try:
                    resp = submit_form(self.session, action, method, data, timeout=self.timeout)
                except Exception as e:
                    self._log(f"sqli form request failed: {e}")
                    continue
                time.sleep(self.delay)
                match = _ERROR_RE.search(resp.text or "")
                if match:
                    self.collector.add(Finding(
                        category="SQL Injection",
                        severity="critical",
                        cwe="CWE-89",
                        owasp="A03:2021 Injection",
                        url=action,
                        parameter=target_field["name"],
                        payload=payload,
                        evidence=f"Database error signature matched: '{match.group(0)}'",
                        description=f"Form field '{target_field['name']}' on {page_url} "
                                     "reflects a database error when sent a SQL metacharacter.",
                    ))
                    break
