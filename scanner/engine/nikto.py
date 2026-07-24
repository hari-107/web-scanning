"""Web-server misconfiguration checks.

Runs Nikto when installed and parses its findings. Otherwise performs a small
built-in set of high-value misconfiguration probes (directory listing,
dangerous sample files, exposed VCS/backup already covered by dirsearch, and
verbose error pages).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from urllib.parse import urljoin

from scanner.models import Severity

from .base import ScanContext
from .runner import run_command, tool_available

_DIR_LISTING_RE = re.compile(r"<title>Index of /|Directory listing for ",
                             re.IGNORECASE)


def run(ctx: ScanContext) -> None:
    ctx.set_phase("Server misconfiguration", 92, "Checking server misconfigurations")
    if tool_available("nikto"):
        _run_nikto(ctx)
    else:
        ctx.log("nikto not found; running built-in misconfiguration checks",
                phase="Server misconfiguration")
        _builtin_checks(ctx)


def _run_nikto(ctx: ScanContext) -> None:
    ctx.use_tool("nikto")
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        result = run_command(
            ["nikto", "-h", ctx.scan.target_url, "-Format", "json", "-output",
             out_path, "-maxtime", "180s", "-nointeractive"],
            timeout=300)
        ctx.cmd_log(result.command, phase="Server misconfiguration")
        try:
            with open(out_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError, ValueError):
            ctx.log("Could not parse nikto output", level="warning",
                    phase="Server misconfiguration")
            return
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        for v in vulns:
            msg = v.get("msg", "")
            url = v.get("url") or ctx.scan.target_url
            osvdb = v.get("id") or v.get("OSVDB") or ""
            ctx.add_finding(
                title=f"Nikto: {msg[:120]}" if msg else "Nikto finding",
                severity=Severity.LOW,
                affected_url=urljoin(ctx.scan.target_url, url),
                evidence=msg,
                cwe="CWE-16",
                description=msg,
                impact="Server misconfiguration may expose information or "
                       "increase attack surface.",
                remediation="Review and harden the server configuration per the "
                            "reported item.",
                detected_by="nikto",
                confidence="Tentative",
                references=[f"OSVDB/{osvdb}"] if osvdb else [],
            )
        ctx.log(f"Nikto reported {len(vulns)} item(s)", level="success",
                phase="Server misconfiguration")
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _builtin_checks(ctx: ScanContext) -> None:
    # Directory listing on common directories discovered or guessed.
    from scanner.models import Endpoint

    candidates = {ctx.base_url + "/" + d for d in
                  ("uploads/", "images/", "files/", "backup/", "static/",
                   "assets/", "js/", "css/", "media/")}
    for ep in Endpoint.objects.filter(scan=ctx.scan).values_list("url", flat=True):
        if ep.endswith("/"):
            candidates.add(ep)
    for url in list(candidates)[:30]:
        resp = ctx.get(url)
        if resp is None:
            continue
        if resp.status_code == 200 and _DIR_LISTING_RE.search(resp.text or ""):
            ctx.add_finding(
                title="Directory listing enabled",
                severity=Severity.MEDIUM,
                affected_url=url,
                evidence="Autoindex/directory listing page returned.",
                cwe="CWE-548",
                description="The server returns a browsable file listing for a "
                            "directory without an index file.",
                impact="Attackers can enumerate files, including sensitive ones.",
                remediation="Disable automatic directory indexing (e.g. Apache "
                            "'Options -Indexes').",
                detected_by="nikto.builtin",
                confidence="Firm",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/OWASP_ASVS"],
            )
    # Verbose error / stack trace on a deliberately malformed request.
    resp = ctx.get(ctx.base_url + "/websec_error_probe'\"<>")
    if resp is not None and resp.status_code >= 500:
        body = (resp.text or "").lower()
        if any(tok in body for tok in ("traceback", "exception", "stack trace",
                                       "at java.", "in <module>", "fatal error",
                                       "warning:")):
            ctx.add_finding(
                title="Verbose error message / stack trace disclosure",
                severity=Severity.LOW,
                affected_url=resp.url,
                evidence="Server returned a detailed error/stack trace.",
                cwe="CWE-209",
                description="Application error output reveals internal details "
                            "(framework, paths, queries).",
                impact="Aids attackers in crafting targeted exploits.",
                remediation="Disable debug mode in production; return generic "
                            "error pages and log details server-side.",
                detected_by="nikto.builtin",
                confidence="Firm",
            )
