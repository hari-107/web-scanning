"""SQL Injection detection: error-based, boolean-based, and time-based.

Non-destructive: payloads only read/compare responses or induce a short server
sleep. Never uses stacked write/DDL statements against data.
"""
from __future__ import annotations

import time
from difflib import SequenceMatcher

from scanner.models import Severity

from ..base import ScanContext
from ..payloads import (
    SQL_ERROR_RE,
    SQLI_BOOLEAN_PAIRS,
    SQLI_ERROR_PAYLOADS,
    SQLI_TIME_PAYLOADS,
)
from .targets import InjectTarget, build_targets, send

_REFERENCES = [
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
]
_TIME_DELAY = 5
_SIMILARITY_TRUE = 0.97   # true-payload response ~ original
_SIMILARITY_FALSE = 0.90  # false-payload response clearly differs


def run(ctx: ScanContext) -> None:
    ctx.set_phase("SQL injection testing", 62, "Testing parameters for SQLi")
    targets = build_targets(ctx)
    if not targets:
        ctx.log("No injectable parameters/forms for SQLi", phase="SQL injection testing")
        return
    ctx.log(f"Testing {len(targets)} target(s) for SQL injection",
            phase="SQL injection testing")

    for t in targets:
        if _error_based(ctx, t):
            continue
        if _boolean_based(ctx, t):
            continue
        _time_based(ctx, t)


def _error_based(ctx: ScanContext, t: InjectTarget) -> bool:
    for payload in SQLI_ERROR_PAYLOADS:
        resp = send(ctx, t, payload)
        if resp is None:
            continue
        m = SQL_ERROR_RE.search(resp.text or "")
        if m:
            snippet = _context(resp.text, m.start())
            ctx.add_finding(
                title="SQL Injection (error-based)",
                severity=Severity.CRITICAL,
                affected_url=t.url,
                http_method=t.method,
                parameter=t.param,
                payload=payload,
                evidence=f"Database error triggered by payload in '{t.param}'.",
                proof=f"...{snippet}...",
                cvss_score=9.8,
                cwe="CWE-89",
                description="Injecting SQL metacharacters produced a database "
                            "error message, indicating unsanitised input reaches "
                            "a SQL query.",
                impact="An attacker may read, modify, or delete database "
                       "contents and potentially achieve remote code execution.",
                remediation="Use parameterised queries / prepared statements; "
                            "validate and escape input; apply least-privilege DB "
                            "accounts.",
                detected_by="vulntests.sqli",
                confidence="Firm",
                references=_REFERENCES,
            )
            return True
    return False


def _boolean_based(ctx: ScanContext, t: InjectTarget) -> bool:
    base = send(ctx, t, "1")
    if base is None or not base.text:
        return False
    base_text = base.text
    for true_p, false_p in SQLI_BOOLEAN_PAIRS:
        rt = send(ctx, t, "1" + true_p)
        rf = send(ctx, t, "1" + false_p)
        if rt is None or rf is None:
            continue
        sim_true = _ratio(base_text, rt.text)
        sim_false = _ratio(base_text, rf.text)
        # True condition stays similar to baseline; false diverges clearly.
        if sim_true >= _SIMILARITY_TRUE and sim_false <= _SIMILARITY_FALSE \
                and (sim_true - sim_false) >= 0.06:
            ctx.add_finding(
                title="SQL Injection (boolean-based blind)",
                severity=Severity.CRITICAL,
                affected_url=t.url,
                http_method=t.method,
                parameter=t.param,
                payload=f"TRUE: {true_p} | FALSE: {false_p}",
                evidence=f"Response similarity true={sim_true:.2f} vs "
                         f"false={sim_false:.2f} for '{t.param}'.",
                proof="Boolean condition changes the response, indicating the "
                      "input is evaluated inside a SQL statement.",
                cvss_score=9.1,
                cwe="CWE-89",
                description="The response differs predictably between a true and "
                            "false SQL condition injected into the parameter.",
                impact="Blind SQL injection permits full extraction of database "
                       "contents given time.",
                remediation="Use parameterised queries; do not build SQL from "
                            "user input.",
                detected_by="vulntests.sqli",
                confidence="Firm",
                references=_REFERENCES,
            )
            return True
    return False


def _time_based(ctx: ScanContext, t: InjectTarget) -> bool:
    # Baseline latency.
    t0 = time.perf_counter()
    base = send(ctx, t, "1")
    if base is None:
        return False
    baseline = time.perf_counter() - t0
    for tpl in SQLI_TIME_PAYLOADS:
        payload = tpl.format(n=_TIME_DELAY)
        t1 = time.perf_counter()
        resp = send(ctx, t, "1" + payload)
        elapsed = time.perf_counter() - t1
        if resp is None:
            continue
        # Require the delay to clearly exceed baseline; confirm with a re-test.
        if elapsed >= baseline + _TIME_DELAY * 0.8:
            t2 = time.perf_counter()
            confirm = send(ctx, t, "1" + payload)
            confirm_elapsed = time.perf_counter() - t2
            if confirm is not None and confirm_elapsed >= baseline + _TIME_DELAY * 0.8:
                ctx.add_finding(
                    title="SQL Injection (time-based blind)",
                    severity=Severity.CRITICAL,
                    affected_url=t.url,
                    http_method=t.method,
                    parameter=t.param,
                    payload=payload,
                    evidence=f"Injected sleep delayed responses to "
                             f"{elapsed:.1f}s / {confirm_elapsed:.1f}s "
                             f"(baseline {baseline:.1f}s).",
                    proof="A time-delay payload reproducibly slowed the response.",
                    cvss_score=9.1,
                    cwe="CWE-89",
                    description="Injecting a database sleep function delayed the "
                                "response, indicating time-based blind SQLi.",
                    impact="Attackers can extract data bit-by-bit via timing.",
                    remediation="Use parameterised queries and input validation.",
                    detected_by="vulntests.sqli",
                    confidence="Firm",
                    references=_REFERENCES,
                )
                return True
    return False


def _ratio(a: str, b: str) -> float:
    # Cap length for performance on large pages.
    return SequenceMatcher(None, a[:6000], (b or "")[:6000]).ratio()


def _context(text: str, pos: int, width: int = 90) -> str:
    start = max(0, pos - width // 2)
    return text[start:start + width].replace("\n", " ").strip()
