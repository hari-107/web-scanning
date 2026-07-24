"""Cross-Site Scripting detection: reflected and DOM-based.

Reflected: inject a unique marker payload and confirm it is echoed back into
the response body without HTML-encoding. DOM-based: statically inspect inline
JavaScript for tainted source -> dangerous sink flows.
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from scanner.models import Severity

from ..base import ScanContext
from ..payloads import (
    DOM_XSS_SINKS,
    DOM_XSS_SOURCES,
    XSS_MARKER,
    XSS_PAYLOADS,
    XSS_RAW_REFLECTIONS,
)
from .targets import InjectTarget, build_targets, send

_REFERENCES = [
    "https://owasp.org/www-community/attacks/xss/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
]


def run(ctx: ScanContext) -> None:
    ctx.set_phase("XSS testing", 70, "Testing parameters for XSS")
    targets = build_targets(ctx)
    if targets:
        ctx.log(f"Testing {len(targets)} target(s) for reflected XSS",
                phase="XSS testing")
        for t in targets:
            _reflected(ctx, t)
    _dom_based(ctx)


def _reflected(ctx: ScanContext, t: InjectTarget) -> bool:
    for payload in XSS_PAYLOADS:
        resp = send(ctx, t, payload)
        if resp is None:
            continue
        body = resp.text or ""
        if XSS_MARKER not in body:
            continue
        # Confirm a *raw* (unescaped) reflection, not an encoded echo.
        raw_hit = next((r for r in XSS_RAW_REFLECTIONS if r in body), None)
        if not raw_hit:
            continue
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype.lower() and ctype:
            # Reflected into non-HTML (e.g. JSON) -> lower severity/info.
            continue
        ctx.add_finding(
            title="Reflected Cross-Site Scripting (XSS)",
            severity=Severity.HIGH,
            affected_url=t.url,
            http_method=t.method,
            parameter=t.param,
            payload=payload,
            evidence=f"Payload reflected unencoded in the response for "
                     f"'{t.param}'.",
            proof=f"Reflected fragment: {raw_hit}",
            cvss_score=6.1,
            cwe="CWE-79",
            description="User input is reflected into the HTML response without "
                        "proper output encoding, allowing script injection.",
            impact="An attacker can execute arbitrary JavaScript in victims' "
                   "browsers: session theft, credential capture, defacement.",
            remediation="Context-aware output encoding; a strict Content-"
                        "Security-Policy; validate input. Prefer framework "
                        "auto-escaping.",
            detected_by="vulntests.xss",
            confidence="Firm",
            references=_REFERENCES,
        )
        return True
    return False


_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


def _dom_based(ctx: ScanContext) -> None:
    """Scan inline scripts of already-crawled pages for source->sink flows."""
    from scanner.models import Endpoint

    checked = 0
    endpoints = Endpoint.objects.filter(
        scan=ctx.scan, method="GET").exclude(status_code__gte=400)[:40]
    for ep in endpoints:
        resp = ctx.get(ep.url)
        if resp is None or "html" not in resp.headers.get("Content-Type", "").lower():
            continue
        checked += 1
        scripts = _SCRIPT_RE.findall(resp.text or "")
        inline = "\n".join(scripts)
        # Also include on* attributes referencing location.
        soup = BeautifulSoup(resp.text or "", "html.parser")
        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                if attr.startswith("on") and isinstance(val, str):
                    inline += "\n" + val
        found_sources = [s for s in DOM_XSS_SOURCES if s in inline]
        found_sinks = [s for s in DOM_XSS_SINKS if s in inline]
        if found_sources and found_sinks:
            ctx.add_finding(
                title="Potential DOM-based XSS",
                severity=Severity.MEDIUM,
                affected_url=ep.url,
                http_method="GET",
                evidence=f"Sources: {', '.join(found_sources[:4])}; "
                         f"Sinks: {', '.join(found_sinks[:4])}",
                cwe="CWE-79",
                description="Inline JavaScript reads from an attacker-"
                            "controllable source and writes to a dangerous DOM "
                            "sink, a common DOM-XSS pattern.",
                impact="Client-side script injection without server involvement.",
                remediation="Avoid passing untrusted data to innerHTML/eval/"
                            "document.write; use textContent and safe DOM APIs; "
                            "sanitise with a trusted library.",
                detected_by="vulntests.xss.dom",
                confidence="Tentative",
                references=_REFERENCES,
            )
    if checked:
        ctx.log(f"DOM-XSS static analysis over {checked} page(s) complete",
                phase="XSS testing")
