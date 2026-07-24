"""Miscellaneous injection/misconfiguration tests.

Covers: LFI/path traversal, command injection (marker + time based), open
redirect, SSTI, CORS misconfiguration, clickjacking, insecure HTTP methods,
and HTTP parameter pollution indicators. All probes are non-destructive.
"""
from __future__ import annotations

import time
from urllib.parse import urljoin

from scanner.models import Severity

from ..base import ScanContext
from ..payloads import (
    CMDI_MARKER,
    CMDI_PARAM_HINTS,
    CMDI_PAYLOADS,
    CMDI_TIME_PAYLOADS,
    LFI_PARAM_HINTS,
    LFI_PAYLOADS,
    LFI_SIGNATURES,
    OPEN_REDIRECT_PAYLOADS,
    REDIRECT_PARAM_HINTS,
    SSTI_PROBES,
)
from ..wordlists import HTTP_METHODS
from .targets import InjectTarget, build_targets, send


def run(ctx: ScanContext) -> None:
    ctx.set_phase("Injection & misconfig testing", 78,
                  "LFI / CMDi / redirect / SSTI / CORS / methods")
    targets = build_targets(ctx)
    for t in targets:
        _lfi(ctx, t)
        _command_injection(ctx, t)
        _open_redirect(ctx, t)
        _ssti(ctx, t)
    _cors(ctx)
    _clickjacking(ctx)
    _http_methods(ctx)


def _param_hint(param: str, hints: set[str]) -> bool:
    p = param.lower()
    return any(h in p for h in hints)


def _lfi(ctx: ScanContext, t: InjectTarget) -> None:
    # Prioritise likely-vulnerable parameter names but still test others lightly.
    payloads = LFI_PAYLOADS if _param_hint(t.param, LFI_PARAM_HINTS) \
        else LFI_PAYLOADS[:3]
    for payload in payloads:
        resp = send(ctx, t, payload)
        if resp is None:
            continue
        body = resp.text or ""
        for sig in LFI_SIGNATURES:
            if sig.search(body):
                ctx.add_finding(
                    title="Local File Inclusion / Path Traversal",
                    severity=Severity.HIGH,
                    affected_url=t.url,
                    http_method=t.method,
                    parameter=t.param,
                    payload=payload,
                    evidence=f"System file contents returned for '{t.param}'.",
                    proof=body[max(0, sig.search(body).start()):
                              sig.search(body).start() + 120].strip(),
                    cvss_score=7.5,
                    cwe="CWE-98",
                    description="A traversal/inclusion payload caused the "
                                "application to return local file contents.",
                    impact="Disclosure of source code, credentials, and system "
                           "files; may escalate to RCE via log poisoning.",
                    remediation="Never pass user input to file APIs; use "
                                "allow-lists of permitted files; canonicalise "
                                "and validate paths.",
                    detected_by="vulntests.misc.lfi",
                    confidence="Firm",
                    references=[
                        "https://owasp.org/www-community/attacks/Path_Traversal"],
                )
                return


def _command_injection(ctx: ScanContext, t: InjectTarget) -> None:
    prioritise = _param_hint(t.param, CMDI_PARAM_HINTS)
    # Marker-based first.
    for payload in (CMDI_PAYLOADS if prioritise else CMDI_PAYLOADS[:3]):
        resp = send(ctx, t, "1" + payload)
        if resp is None:
            continue
        body = resp.text or ""
        # Real execution echoes the bare marker but NOT the literal
        # "echo MARKER" command text. If the whole payload is reflected
        # verbatim (marker preceded by "echo "), it is reflection, not RCE.
        if CMDI_MARKER in body and f"echo {CMDI_MARKER}" not in body:
            ctx.add_finding(
                title="OS Command Injection",
                severity=Severity.CRITICAL,
                affected_url=t.url,
                http_method=t.method,
                parameter=t.param,
                payload=payload,
                evidence=f"Injected command output ('{CMDI_MARKER}') appeared "
                         f"in the response for '{t.param}'.",
                proof=f"Marker {CMDI_MARKER} echoed back.",
                cvss_score=9.8,
                cwe="CWE-78",
                description="User input is passed to a system shell, allowing "
                            "arbitrary command execution.",
                impact="Full server compromise.",
                remediation="Avoid shell calls with user input; use language "
                            "APIs; if unavoidable, use strict allow-lists and "
                            "argument arrays, never string concatenation.",
                detected_by="vulntests.misc.cmdi",
                confidence="Firm",
                references=[
                    "https://owasp.org/www-community/attacks/Command_Injection"],
            )
            return
    # Time-based (only for hinted params to limit load).
    if not prioritise:
        return
    t0 = time.perf_counter()
    b = send(ctx, t, "1")
    baseline = time.perf_counter() - t0 if b is not None else 0
    for tpl in CMDI_TIME_PAYLOADS:
        payload = tpl.format(n=5)
        start = time.perf_counter()
        resp = send(ctx, t, "1" + payload)
        elapsed = time.perf_counter() - start
        if resp is not None and elapsed >= baseline + 4:
            ctx.add_finding(
                title="OS Command Injection (time-based)",
                severity=Severity.CRITICAL,
                affected_url=t.url, http_method=t.method, parameter=t.param,
                payload=payload,
                evidence=f"Injected sleep delayed the response to {elapsed:.1f}s "
                         f"(baseline {baseline:.1f}s).",
                cvss_score=9.8, cwe="CWE-78",
                description="A time-delay command payload slowed the response, "
                            "indicating blind command injection.",
                impact="Full server compromise.",
                remediation="Avoid shell calls with user input; use safe APIs.",
                detected_by="vulntests.misc.cmdi",
                confidence="Firm",
                references=[
                    "https://owasp.org/www-community/attacks/Command_Injection"],
            )
            return


def _open_redirect(ctx: ScanContext, t: InjectTarget) -> None:
    if not _param_hint(t.param, REDIRECT_PARAM_HINTS):
        return
    for payload in OPEN_REDIRECT_PAYLOADS:
        resp = send(ctx, t, payload, allow_redirects=False)
        if resp is None:
            continue
        loc = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and \
                ("example.org" in loc and loc.strip().lower().startswith(
                    ("http", "//", "https:example"))):
            ctx.add_finding(
                title="Open Redirect",
                severity=Severity.MEDIUM,
                affected_url=t.url,
                http_method=t.method,
                parameter=t.param,
                payload=payload,
                evidence=f"Redirects to attacker-controlled Location: {loc}",
                cvss_score=5.4,
                cwe="CWE-601",
                description="The application redirects to a URL taken from user "
                            "input without validation.",
                impact="Phishing, OAuth token theft, and filter bypass.",
                remediation="Use an allow-list of redirect targets or relative "
                            "paths only; never redirect to raw user input.",
                detected_by="vulntests.misc.redirect",
                confidence="Firm",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
            )
            return


def _ssti(ctx: ScanContext, t: InjectTarget) -> None:
    for probe, expected in SSTI_PROBES:
        resp = send(ctx, t, probe)
        if resp is None:
            continue
        body = resp.text or ""
        # Confirm the evaluated result appears but the literal probe does not
        # (guards against plain reflection).
        if expected in body and probe not in body:
            ctx.add_finding(
                title="Server-Side Template Injection (SSTI) indicator",
                severity=Severity.HIGH,
                affected_url=t.url,
                http_method=t.method,
                parameter=t.param,
                payload=probe,
                evidence=f"Template expression evaluated: '{probe}' -> "
                         f"'{expected}'.",
                cvss_score=8.6,
                cwe="CWE-1336",
                description="A template expression injected into the parameter "
                            "was evaluated server-side.",
                impact="SSTI frequently escalates to remote code execution.",
                remediation="Do not embed user input in templates; use sandboxed "
                            "rendering and logic-less templates.",
                detected_by="vulntests.misc.ssti",
                confidence="Firm",
                references=[
                    "https://portswigger.net/web-security/server-side-template-injection"],
            )
            return


def _cors(ctx: ScanContext) -> None:
    evil = "https://evil.example.com"
    resp = ctx.get(ctx.scan.target_url, headers={"Origin": evil})
    if resp is None:
        return
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    if acao == evil or acao == "*":
        reflects_creds = acac.lower() == "true"
        if acao == "*" and not reflects_creds:
            sev = Severity.LOW
            detail = "Wildcard ACAO without credentials."
        else:
            sev = Severity.HIGH if reflects_creds else Severity.MEDIUM
            detail = ("Origin reflected with credentials allowed."
                      if reflects_creds else "Arbitrary Origin reflected.")
        ctx.add_finding(
            title="Insecure CORS configuration",
            severity=sev,
            affected_url=ctx.scan.target_url,
            evidence=f"Access-Control-Allow-Origin: {acao}; "
                     f"Allow-Credentials: {acac or 'unset'}",
            cwe="CWE-942",
            description=f"The server returns a permissive CORS policy. {detail}",
            impact="Cross-origin theft of authenticated responses/data.",
            remediation="Reflect only trusted origins from an allow-list; never "
                        "combine wildcard/reflected origin with "
                        "Allow-Credentials: true.",
            detected_by="vulntests.misc.cors",
            confidence="Firm",
            references=[
                "https://portswigger.net/web-security/cors"],
        )


def _clickjacking(ctx: ScanContext) -> None:
    resp = ctx.get(ctx.scan.target_url)
    if resp is None:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    framed_ok = bool(xfo) or "frame-ancestors" in csp.lower()
    if not framed_ok and "html" in headers.get("content-type", "").lower():
        ctx.add_finding(
            title="Clickjacking: no framing protection",
            severity=Severity.MEDIUM,
            affected_url=ctx.scan.target_url,
            evidence="Neither X-Frame-Options nor CSP frame-ancestors present.",
            cwe="CWE-1021",
            description="The page can be embedded in a frame on any origin.",
            impact="UI-redress attacks can trick users into unintended actions.",
            remediation="Set 'X-Frame-Options: DENY' or CSP "
                        "'frame-ancestors 'self''.",
            detected_by="vulntests.misc.clickjacking",
            confidence="Firm",
            references=[
                "https://owasp.org/www-community/attacks/Clickjacking"],
        )


def _http_methods(ctx: ScanContext) -> None:
    resp = ctx.request("OPTIONS", ctx.scan.target_url)
    allowed = ""
    if resp is not None:
        allowed = resp.headers.get("Allow", "") or resp.headers.get(
            "Access-Control-Allow-Methods", "")
    risky = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
    present = {m.strip().upper() for m in allowed.split(",") if m.strip()}
    dangerous = present & risky
    if dangerous:
        sev = Severity.MEDIUM if {"PUT", "DELETE"} & dangerous else Severity.LOW
        ctx.add_finding(
            title="Potentially dangerous HTTP methods enabled",
            severity=sev,
            affected_url=ctx.scan.target_url,
            http_method="OPTIONS",
            evidence=f"Allow: {allowed}",
            cwe="CWE-650",
            description=f"The server advertises risky methods: "
                        f"{', '.join(sorted(dangerous))}.",
            impact="Methods like PUT/DELETE may allow file upload/removal; "
                   "TRACE enables Cross-Site Tracing.",
            remediation="Disable unused HTTP methods at the web server/framework.",
            detected_by="vulntests.misc.methods",
            confidence="Firm",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/"],
        )
