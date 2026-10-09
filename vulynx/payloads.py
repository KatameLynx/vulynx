
# --------------------------------------------------------------------------- #
# SQL Injection
# --------------------------------------------------------------------------- #

SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    '"',
    "`",
    "')",
    "';--",
    "' OR '1'='1",
    "' OR '1'='1'--",
    '" OR "1"="1',
    "1' AND '1'='1",
    "1' AND '1'='2",
]

# (true_suffix, false_suffix) appended to the parameter's ORIGINAL value, so the
# "true" request should look like the normal page and the "false" one should not.
SQLI_BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
    ('" AND "1"="1', '" AND "1"="2'),
]

SQLI_TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",   # MSSQL
    "' OR SLEEP(5)-- -",             # MySQL
    "' OR pg_sleep(5)--",            # PostgreSQL
]
SQLI_TIME_DELAY_THRESHOLD_SEC = 4.5  # response must take at least this long

SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"sqlite3\.OperationalError",
    r"sqlite3\.Warning",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"ORA-\d{5}",
    r"microsoft ole db provider for odbc drivers",
    r"microsoft ole db provider for sql server",
    r"incorrect syntax near",
    r"unterminated quoted string",
    r"django\.db\.utils\.\w*Error",
    r"unrecognized token",
    r"near \"[^\"]*\": syntax error",
    r"syntax error at or near",
    r"sql syntax.*error",
    r"invalid query",
    r"mysql_fetch",
    r"odbc sql server driver",
    r"sqlexception",
    r"data source rejected",
    r"exception.*sql",
]


# --------------------------------------------------------------------------- #
# Cross-Site Scripting (XSS)
# --------------------------------------------------------------------------- #

def build_xss_payloads(marker: str):
    return [
        f"<script>/*{marker}*/</script>",
        f"\"><script>/*{marker}*/</script>",
        f"'><img src=x onerror=/*{marker}*/>",
        f"<img src=x onerror=\"/*{marker}*/\">",
        f"<svg onload=/*{marker}*/>",
        f"\"'><{marker}>",
    ]


# --------------------------------------------------------------------------- #
# Broken Authentication
# --------------------------------------------------------------------------- #

LOGIN_FORM_FIELD_HINTS = ("user", "email", "login", "pass", "pwd")

# Field names of a plain search box; such POST forms are not CSRF-relevant.
SEARCH_FIELD_NAMES = ("q", "s", "search", "query", "keyword", "keywords", "term")

# --------------------------------------------------------------------------- #
# Open Redirect
# --------------------------------------------------------------------------- #

REDIRECT_PARAM_HINTS = (
    "next", "url", "redirect", "redirect_uri", "redirect_url",
    "return", "return_to", "return_url", "returnto",
    "goto", "target", "dest", "destination",
    "redir", "continue", "callback", "back", "backurl",
    "forward", "out", "link", "to",
)

OPEN_REDIRECT_TEST_DOMAIN = "evil.attacker.test"