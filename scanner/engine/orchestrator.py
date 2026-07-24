"""Sequential pipeline that runs every module against one target.

Fault-tolerant: if a module raises, the error is logged and the pipeline
continues with the next module. Progress/phase are updated throughout so the
frontend can render a live indicator.
"""
from __future__ import annotations

import traceback

from django.utils import timezone

from scanner.models import ScanStatus

from . import (
    crawler,
    dirsearch,
    nikto,
    ports,
    recon,
    scoring,
    ssl_analysis,
    tech,
)
from .base import ScanContext
from .runner import tool_available
from .validator import is_private_host
from .vulntests import auth as auth_tests
from .vulntests import misc as misc_tests
from .vulntests import sqli as sqli_tests
from .vulntests import xss as xss_tests

# (label, callable) in execution order. Discovery precedes vuln testing.
PIPELINE = [
    ("Reconnaissance", recon.run),
    ("SSL/TLS analysis", ssl_analysis.run),
    ("Technology detection", tech.run),
    ("Port scanning", ports.run),
    ("Directory enumeration", dirsearch.run),
    ("Crawling", crawler.run),
    ("SQL injection testing", sqli_tests.run),
    ("XSS testing", xss_tests.run),
    ("Injection & misconfig testing", misc_tests.run),
    ("Authentication testing", auth_tests.run),
    ("Server misconfiguration", nikto.run),
]


def run_pipeline(scan) -> None:
    ctx = ScanContext(scan)
    scan.status = ScanStatus.RUNNING
    scan.started_at = timezone.now()
    scan.total_tasks = len(PIPELINE)
    scan.save(update_fields=["status", "started_at", "total_tasks"])

    ctx.log(f"Scan started against {scan.target_url}", level="success",
            phase="Initialisation")
    _log_environment(ctx)
    if is_private_host(ctx.hostname):
        ctx.log("Target resolves to a private/loopback address (local lab).",
                level="warning", phase="Initialisation")

    for index, (label, func) in enumerate(PIPELINE):
        try:
            func(ctx)
        except Exception as exc:  # fault tolerance: never abort the whole run
            ctx.log(f"Module '{label}' failed: {exc}", level="error", phase=label)
            ctx.log(traceback.format_exc().splitlines()[-1], level="error",
                    phase=label)
        finally:
            scan.completed_tasks = index + 1
            scan.save(update_fields=["completed_tasks"])

    # Finalise metrics and scoring.
    ctx.set_phase("Reporting", 98, "Correlating results and scoring")
    scan.total_requests = ctx.request_count
    scan.total_urls_discovered = ctx.url_count
    scan.tools_used = sorted(ctx.tools_used)
    scan.save(update_fields=["total_requests", "total_urls_discovered",
                             "tools_used"])
    scoring.finalize(scan)

    scan.status = ScanStatus.COMPLETED
    scan.phase = "Completed"
    scan.progress = 100
    scan.current_task = ""
    scan.finished_at = timezone.now()
    scan.save(update_fields=["status", "phase", "progress", "current_task",
                             "finished_at"])
    ctx.log(f"Scan completed. Score {scan.security_score}/100, "
            f"risk {scan.get_risk_rating_display()}.", level="success",
            phase="Completed")


def _log_environment(ctx: ScanContext) -> None:
    detected = [t for t in ("nmap", "gobuster", "ffuf", "nikto", "whatweb")
                if tool_available(t)]
    if detected:
        ctx.log("External tools detected: " + ", ".join(detected),
                phase="Initialisation")
    missing = [t for t in ("nmap", "gobuster", "ffuf", "nikto", "whatweb")
               if not tool_available(t)]
    if missing:
        ctx.log("Using built-in fallbacks for: " + ", ".join(missing),
                phase="Initialisation")
