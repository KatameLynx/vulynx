"""
auth.py - Heuristic checks for authentication and session weaknesses.

No credential brute-forcing is performed. Only the following are tested:
  - Session cookies missing Secure/HttpOnly flags
  - Login form submitted over plain HTTP
  - State-changing (POST) forms without an anti-CSRF token
  - Username enumeration: does the login page answer differently for an
    unknown user than for a likely-existing user with a wrong password?
    (at most 2 + len(known_users) failed login attempts per login form)
"""

from urllib.parse import urlparse

from .payloads import LOGIN_FORM_FIELD_HINTS, SEARCH_FIELD_NAMES
from .findings import Finding
from .forms import extract_form_fields, submit_form, has_csrf_token
from .textdiff import differs, visible_text

DEFAULT_KNOWN_USERS = ("admin",)


class AuthScanner:
    def __init__(self, session, collector, timeout=10, logger=None, known_users=None):
        self.session = session
        self.collector = collector
        self.timeout = timeout
        self.logger = logger
        self.known_users = tuple(known_users) if known_users else DEFAULT_KNOWN_USERS

    def _log(self, msg):
        if self.logger:
            self.logger.debug(msg)

    @staticmethod
    def _looks_like_login_form(fields):
        names = " ".join(f["name"].lower() for f in fields)
        has_password = any(f["type"] == "password" for f in fields)
        has_identifier = any(hint in names for hint in LOGIN_FORM_FIELD_HINTS)
        return has_password and has_identifier

    @staticmethod
    def _is_search_form(fields):
        """A single free-text box named q/search/... is not state-changing."""
        visible = [f for f in fields if f["type"] not in ("hidden", "submit", "button")]
        return len(visible) == 1 and visible[0]["name"].lower() in SEARCH_FIELD_NAMES

    # ---- Cookie flags -------------------------------------------------- #

    def check_session_cookies(self, url):
        is_https = urlparse(url).scheme == "https"
        for cookie in self.session.cookies:
            # Track which flag is missing so we can map to the right CWE.
            missing = []
            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "_rest", {}).get("HttpOnly"):
                missing.append(("HttpOnly", "CWE-1004"))
            if is_https and not cookie.secure:
                missing.append(("Secure", "CWE-614"))

            if not missing:
                continue

            flag_names = [name for name, _ in missing]
            cwe_ids = [cwe for _, cwe in missing]

            self.collector.add(Finding(
                category="Broken Authentication",
                severity="medium",
                cwe=", ".join(cwe_ids),
                owasp="A05:2021 Security Misconfiguration",
                url=url,
                parameter=cookie.name,
                evidence=f"Cookie '{cookie.name}' missing flag(s): {', '.join(flag_names)}",
                description="Session cookies without HttpOnly are readable by "
                             "JavaScript (XSS-stealable); without Secure they can "
                             "be sent over plaintext HTTP.",
            ))

    # ---- Login over plain HTTP ------------------------------------------ #

    def check_plaintext_login(self, page_url, form_action, fields):
        if self._looks_like_login_form(fields) and urlparse(form_action).scheme == "http":
            self.collector.add(Finding(
                category="Broken Authentication",
                severity="high",
                cwe="CWE-319",
                owasp="A02:2021 Cryptographic Failures",
                url=page_url,
                evidence=f"Login form submits to {form_action} over plain HTTP.",
                description="Credentials submitted over unencrypted HTTP can be intercepted.",
            ))

    # ---- Missing CSRF token --------------------------------------------- #

    def check_csrf_token(self, page_url, form_action, method, fields):
        if method != "post" or self._is_search_form(fields) or has_csrf_token(fields):
            return
        self.collector.add(Finding(
            category="Missing CSRF Protection",
            severity="medium",
            cwe="CWE-352",
            owasp="A01:2021 Broken Access Control",
            url=page_url,
            evidence=f"POST form at {form_action} has no hidden CSRF-token-like field.",
            description="State-changing forms without an anti-CSRF token may be "
                         "vulnerable to cross-site request forgery. (Token sent via a "
                         "header or cookie is not detected by this check.)",
        ))

    # ---- Username enumeration -------------------------------------------- #

    def check_username_enumeration(self, page_url, form):
        action, method, fields = extract_form_fields(page_url, form)
        if not self._looks_like_login_form(fields):
            return

        user_field = next((f for f in fields if any(h in f["name"].lower()
                          for h in ("user", "email", "login"))), None)
        pass_field = next((f for f in fields if f["type"] == "password"), None)
        if not user_field or not pass_field:
            return

        base_data = {f["name"]: (f["value"] or "") for f in fields if f["name"]}

        def attempt(username):
            data = dict(base_data)
            data[user_field["name"]] = username
            data[pass_field["name"]] = "Wr0ng-pass-for-vulynx!"
            return submit_form(self.session, action, method, data, timeout=self.timeout)

        try:
            unknown_a = attempt("vulynx_no_such_user_a")
            unknown_b = attempt("vulynx_no_such_user_b")
            # Two unknown users must get the same answer, otherwise the page is
            # too dynamic (or rate limited) for this check to mean anything.
            if (unknown_a.status_code != unknown_b.status_code
                    or differs(unknown_a.text, unknown_b.text)):
                self._log(f"enumeration check skipped on {action}: unstable responses")
                return

            for candidate in self.known_users:
                known = attempt(candidate)
                if known.status_code == 429 or known.status_code >= 500:
                    return
                if known.status_code != unknown_a.status_code or differs(unknown_a.text, known.text):
                    self.collector.add(Finding(
                        category="Broken Authentication",
                        severity="low",
                        cwe="CWE-204",
                        owasp="A07:2021 Identification and Authentication Failures",
                        url=action,
                        parameter=user_field["name"],
                        payload=candidate,
                        evidence=(
                            f"Unknown user -> HTTP {unknown_a.status_code}: "
                            f"'{visible_text(unknown_a.text)[:80]}'; "
                            f"'{candidate}' with wrong password -> HTTP {known.status_code}: "
                            f"'{visible_text(known.text)[:80]}'"
                        ),
                        description="The login form answers differently for an unknown user "
                                     "than for an existing user with a wrong password, which "
                                     "lets an attacker enumerate valid usernames.",
                    ))
                    return
        except Exception as e:
            self._log(f"auth enumeration check failed: {e}")

    # ---- Orchestration --------------------------------------------------- #

    def scan_form(self, page_url, form):
        action, method, fields = extract_form_fields(page_url, form)
        self.check_plaintext_login(page_url, action, fields)
        self.check_csrf_token(page_url, action, method, fields)
        self.check_username_enumeration(page_url, form)
