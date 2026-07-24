"""Launch a scan pipeline in a background thread.

No Celery/Docker: a daemon thread runs the orchestrator while the request
returns immediately. The DB is the single source of truth for progress, so any
number of browser tabs can poll status independently. Each thread opens and
closes its own DB connection to avoid sharing Django's thread-local connection.
"""
from __future__ import annotations

import threading

from django.db import connection

from scanner.models import Scan, ScanStatus

from . import orchestrator


def _worker(scan_id: int) -> None:
    try:
        scan = Scan.objects.get(pk=scan_id)
    except Scan.DoesNotExist:
        return
    try:
        orchestrator.run_pipeline(scan)
    except Exception as exc:  # pragma: no cover - last-resort guard
        try:
            scan.status = ScanStatus.FAILED
            scan.error = str(exc)
            scan.phase = "Failed"
            from django.utils import timezone
            scan.finished_at = timezone.now()
            scan.save(update_fields=["status", "error", "phase", "finished_at"])
        except Exception:
            pass
    finally:
        # Release this thread's DB connection.
        connection.close()


def start_scan(scan: Scan) -> None:
    thread = threading.Thread(target=_worker, args=(scan.pk,), daemon=True,
                              name=f"scan-{scan.pk}")
    thread.start()
