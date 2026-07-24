"""Directory / file content enumeration.

Prefers Gobuster or FFUF when available; otherwise a threaded HTTP prober over
the built-in wordlist. Discovered paths are recorded as Endpoints, and
high-signal hits (.git, .env, backups, admin panels...) raise findings.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from django.conf import settings

from scanner.models import Endpoint, Severity

from .base import ScanContext
from .runner import run_command, tool_available
from .wordlists import COMMON_PATHS, INTERESTING_MARKERS

SCAN = settings.SCAN_SETTINGS

_INTERESTING_SEVERITY = {
    "Exposed Git repository": Severity.HIGH,
    "Exposed SVN repository": Severity.HIGH,
    "Exposed environment file": Severity.CRITICAL,
    "Exposed environment backup": Severity.CRITICAL,
    "Exposed WordPress config backup": Severity.CRITICAL,
    "Database backup": Severity.HIGH,
    "Backup archive": Severity.HIGH,
    "Backup resource": Severity.MEDIUM,
    "Exposed htpasswd": Severity.HIGH,
    "PHP info disclosure": Severity.MEDIUM,
    "Apache server-status exposed": Severity.MEDIUM,
    "Spring Actuator env exposed": Severity.HIGH,
    "Exposed .DS_Store (directory listing leak)": Severity.LOW,
    "API schema exposed": Severity.LOW,
    "Potential configuration file": Severity.MEDIUM,
    "Admin panel": Severity.INFO,
    "WordPress admin": Severity.INFO,
    "Login portal": Severity.INFO,
    "Dashboard": Severity.INFO,
}


def run(ctx: ScanContext) -> list[dict]:
    ctx.set_phase("Directory enumeration", 40, "Enumerating directories & files")
    base = ctx.base_url + "/"

    if tool_available("ffuf"):
        hits = _run_ffuf(ctx, base)
    elif tool_available("gobuster"):
        hits = _run_gobuster(ctx, base)
    else:
        ctx.log("gobuster/ffuf not found; using built-in HTTP enumerator",
                phase="Directory enumeration")
        hits = _python_enum(ctx, base)

    for hit in hits:
        _record(ctx, hit)

    ctx.log(f"Directory enumeration found {len(hits)} path(s)",
            level="success", phase="Directory enumeration")
    return hits


def _classify(path: str) -> str | None:
    key = path.strip("/").lower()
    if key in INTERESTING_MARKERS:
        return INTERESTING_MARKERS[key]
    for marker, label in INTERESTING_MARKERS.items():
        if key.endswith(marker) or key == marker:
            return label
    return None


def _record(ctx: ScanContext, hit: dict) -> None:
    url = hit["url"]
    status = hit.get("status")
    interesting_label = _classify(hit.get("path", url))
    ctx.note_url(url)
    Endpoint.objects.get_or_create(
        scan=ctx.scan, url=url, method="GET",
        defaults={
            "status_code": status,
            "content_type": hit.get("content_type", ""),
            "content_length": hit.get("length"),
            "source": "dirsearch",
            "interesting": bool(interesting_label),
        },
    )
    if interesting_label and status in (200, 301, 302, 401, 403):
        severity = _INTERESTING_SEVERITY.get(interesting_label, Severity.LOW)
        # 401/403 lowers severity for content-exposure classes (present but gated).
        if status in (401, 403) and severity in (Severity.CRITICAL, Severity.HIGH):
            severity = Severity.MEDIUM
        ctx.add_finding(
            title=f"{interesting_label} discovered",
            severity=severity,
            affected_url=url,
            http_method="GET",
            evidence=f"HTTP {status} at {url}",
            cwe="CWE-538" if "Exposed" in interesting_label else "CWE-200",
            description=f"A sensitive resource was reachable: {interesting_label}.",
            impact="Exposed source, secrets, or backups can lead to full "
                   "compromise; admin/login panels widen the attack surface.",
            remediation="Remove the resource from the web root or enforce strict "
                        "access control; never deploy VCS metadata, backups, or "
                        "env files to production.",
            detected_by="dirsearch",
            confidence="Firm" if status == 200 else "Tentative",
        )


# --- fallbacks ---------------------------------------------------------------
def _python_enum(ctx: ScanContext, base: str) -> list[dict]:
    ctx.use_tool("http-enum (python)")
    words = COMMON_PATHS[: SCAN["DIR_WORDLIST_LIMIT"]]
    # Establish a baseline for a random path to detect soft-404s.
    baseline = _soft_404_signature(ctx, base)
    hits: list[dict] = []

    def probe(path: str):
        url = urljoin(base, path)
        resp = ctx.get(url, allow_redirects=False)
        if resp is None:
            return None
        status = resp.status_code
        if status in (404, 400):
            return None
        length = len(resp.content)
        # Soft-404 filter: 200 that matches the fake-path baseline.
        if status == 200 and baseline and abs(length - baseline["length"]) < 32 \
                and baseline["length"] > 0:
            return None
        if status in (200, 201, 204, 301, 302, 307, 401, 403, 500):
            return {
                "url": url, "path": path, "status": status,
                "length": length,
                "content_type": resp.headers.get("Content-Type", ""),
            }
        return None

    with ThreadPoolExecutor(max_workers=SCAN["HTTP_THREADS"]) as ex:
        futures = {ex.submit(probe, w): w for w in words}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                hits.append(res)
                ctx.log(f"[{res['status']}] {res['url']}",
                        phase="Directory enumeration")
    return hits


def _soft_404_signature(ctx: ScanContext, base: str) -> dict | None:
    probe_url = urljoin(base, "websec_nonexistent_%s" % os.urandom(4).hex())
    resp = ctx.get(probe_url, allow_redirects=False)
    if resp is None:
        return None
    return {"status": resp.status_code, "length": len(resp.content)}


def _run_ffuf(ctx: ScanContext, base: str) -> list[dict]:
    ctx.use_tool("ffuf")
    wordlist_path = _write_temp_wordlist()
    out_fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(out_fd)
    try:
        result = run_command([
            "ffuf", "-u", urljoin(base, "FUZZ"), "-w", wordlist_path,
            "-mc", "200,201,204,301,302,307,401,403,500", "-of", "json",
            "-o", out_path, "-t", "40", "-s",
        ], timeout=300)
        ctx.cmd_log(result.command, phase="Directory enumeration")
        hits = []
        try:
            with open(out_path, encoding="utf-8") as fh:
                data = json.load(fh)
            for r in data.get("results", []):
                hits.append({
                    "url": r.get("url", ""),
                    "path": r.get("input", {}).get("FUZZ", ""),
                    "status": r.get("status"),
                    "length": r.get("length"),
                    "content_type": r.get("content-type", ""),
                })
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        return hits
    finally:
        _safe_unlink(wordlist_path)
        _safe_unlink(out_path)


_GOBUSTER_LINE = re.compile(r"^(\/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")


def _run_gobuster(ctx: ScanContext, base: str) -> list[dict]:
    ctx.use_tool("gobuster")
    wordlist_path = _write_temp_wordlist()
    try:
        result = run_command([
            "gobuster", "dir", "-u", base.rstrip("/"), "-w", wordlist_path,
            "-q", "-t", "40", "-s", "200,201,204,301,302,307,401,403,500",
            "-b", "",
        ], timeout=300)
        ctx.cmd_log(result.command, phase="Directory enumeration")
        hits = []
        for line in result.stdout.splitlines():
            m = _GOBUSTER_LINE.match(line.strip())
            if m:
                path = m.group(1).lstrip("/")
                hits.append({
                    "url": urljoin(base, path), "path": path,
                    "status": int(m.group(2)),
                    "length": int(m.group(3)) if m.group(3) else None,
                    "content_type": "",
                })
        return hits
    finally:
        _safe_unlink(wordlist_path)


def _write_temp_wordlist() -> str:
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="websec_wl_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(COMMON_PATHS))
    return path


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
