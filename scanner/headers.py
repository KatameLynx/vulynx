"""
headers.py — Checks security-related response headers.

Headers checked:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

A missing header generates a Finding with an appropriate severity.
"""

from .findings import Finding


# Mapping: header name -> (severity, short description, suggested remediation)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "medium",
        "HSTS is missing. Without it, browsers may connect over plain HTTP "
        "before being redirected, allowing SSL-stripping MITM attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "Content-Security-Policy": (
        "medium",
        "CSP is missing. Without a Content-Security-Policy, the browser has "
        "no restriction on which scripts/styles can execute, making XSS "
        "impact significantly worse.",
        "Add a restrictive CSP, e.g. default-src 'self'.",
    ),
    "X-Frame-Options": (
        "medium",
        "X-Frame-Options is missing. The page can be embedded in an iframe "
        "on another site, enabling clickjacking attacks.",
        "Add: X-Frame-Options: DENY (or SAMEORIGIN).",
    ),
    "X-Content-Type-Options": (
        "low",
        "X-Content-Type-Options is missing. Browsers may MIME-sniff "
        "responses, potentially executing content as a different type.",
        "Add: X-Content-Type-Options: nosniff.",
    ),
    "Referrer-Policy": (
        "low",
        "Referrer-Policy is missing. Full URLs may leak to third-party "
        "sites via the Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    "Permissions-Policy": (
        "info",
        "Permissions-Policy is missing. There is no explicit restriction on "
        "browser features (camera, microphone, geolocation, ...).",
        "Add: Permissions-Policy: geolocation=(), microphone=(), camera=().",
    ),
}


class HeadersScanner:
    def __init__(self, collector, logger=None):
        self.collector = collector
        self.logger = logger
        self._reported_hosts = set()  # Report each domain only once

    def _log(self, msg):
        if self.logger:
            self.logger.debug(msg)

    def scan_page(self, page):
        """Check security headers for a Page."""
        from urllib.parse import urlparse

        # Security headers are usually consistent across the entire domain.
        # To avoid duplicate findings, check each domain only once.
        host = urlparse(page.url).netloc
        if host in self._reported_hosts:
            return
        self._reported_hosts.add(host)

        # Headers are case-insensitive, so normalize all names to lowercase.
        lower_headers = {k.lower(): v for k, v in page.headers.items()}

        for header_name, (severity, description, remediation) in SECURITY_HEADERS.items():
            if header_name.lower() not in lower_headers:
                self.collector.add(Finding(
                    category="Missing Security Header",
                    severity=severity,
                    cwe="CWE-693",
                    owasp="A05:2021 Security Misconfiguration",
                    url=page.url,
                    parameter=header_name,
                    evidence=f"Response does not include the '{header_name}' header.",
                    description=f"{description} Remediation: {remediation}",
                ))
            else:
                self._log(f"header present: {header_name} = {lower_headers[header_name.lower()]}")

        # Additional check: if the Server header reveals a version,
        # it may disclose unnecessary software information.
        server = lower_headers.get("server", "")
        if server and any(c.isdigit() for c in server):
            self.collector.add(Finding(
                category="Information Disclosure",
                severity="info",
                cwe="CWE-200",
                owasp="A05:2021 Security Misconfiguration",
                url=page.url,
                parameter="Server",
                evidence=f"Server header reveals version info: '{server}'",
                description="The Server header exposes software and version "
                            "information, helping attackers target known CVEs. "
                            "Consider removing or genericizing it.",
            ))