"""Shared context, logging, HTTP helper and de-duplication for the engine."""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.utils import timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from scanner.models import Finding, LogLine, Scan, Severity

SCAN = settings.SCAN_SETTINGS


class ScanContext:
    """Carries per-scan state through the pipeline.

    Holds the DB row, a configured ``requests.Session``, request/URL counters,
    a de-dup set for findings, and an abort flag. All mutation is guarded by a
    lock because the crawler and vuln modules touch the counters from worker
    threads.
    """

    def __init__(self, scan: Scan):
        self.scan = scan
        self.parsed = urlparse(scan.target_url)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.hostname = self.parsed.hostname or ""
        self._lock = threading.Lock()
        self._seen_findings: set[str] = set()
        self._request_count = 0
        self._url_set: set[str] = set()
        self.tools_used: set[str] = set()
        self.session = self._build_session()

        # Populated by discovery phases, consumed by later phases.
        self.endpoints: dict[str, dict] = {}   # url -> metadata
        self.forms: list[dict] = []
        self.params: dict[str, set] = {}       # url -> set(param names)

    # -- HTTP -------------------------------------------------------------
    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": SCAN["USER_AGENT"], "Accept": "*/*"})
        retry = Retry(total=1, backoff_factor=0.3,
                      status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=32,
                              pool_maxsize=32)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.verify = False  # assessment target certs are frequently invalid
        return s

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Perform an HTTP request, counting it and swallowing errors."""
        kwargs.setdefault("timeout", SCAN["REQUEST_TIMEOUT"])
        kwargs.setdefault("allow_redirects", kwargs.pop("allow_redirects", True))
        with self._lock:
            self._request_count += 1
        try:
            return self.session.request(method, url, **kwargs)
        except requests.RequestException:
            return None

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    # -- counters ---------------------------------------------------------
    def note_url(self, url: str) -> None:
        with self._lock:
            self._url_set.add(url)

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def url_count(self) -> int:
        return len(self._url_set)

    def use_tool(self, name: str) -> None:
        self.tools_used.add(name)

    # -- logging ----------------------------------------------------------
    def log(self, message: str, level: str = "info", phase: str = "") -> None:
        phase = phase or self.scan.phase
        LogLine.objects.create(
            scan=self.scan, level=level, phase=phase, message=message
        )

    def cmd_log(self, command: str, phase: str = "") -> None:
        self.log(f"$ {command}", level="cmd", phase=phase)

    # -- progress ---------------------------------------------------------
    def set_phase(self, phase: str, progress: int, current_task: str = "") -> None:
        self.scan.phase = phase
        self.scan.progress = max(0, min(100, progress))
        if current_task:
            self.scan.current_task = current_task
        self.scan.total_requests = self.request_count
        self.scan.total_urls_discovered = self.url_count
        self.scan.tools_used = sorted(self.tools_used)
        self.scan.save(update_fields=[
            "phase", "progress", "current_task", "total_requests",
            "total_urls_discovered", "tools_used",
        ])

    # -- findings ---------------------------------------------------------
    def add_finding(self, **kwargs: Any) -> Optional[Finding]:
        """Create a Finding, de-duplicating on (title, url, parameter, payload)."""
        key_src = "|".join([
            kwargs.get("title", ""),
            kwargs.get("affected_url", ""),
            kwargs.get("parameter", ""),
            str(kwargs.get("payload", "")),
        ])
        dedup = hashlib.sha256(key_src.encode("utf-8", "ignore")).hexdigest()
        with self._lock:
            if dedup in self._seen_findings:
                return None
            self._seen_findings.add(dedup)
        kwargs["dedup_key"] = dedup
        refs = kwargs.get("references") or []
        kwargs["references"] = refs
        finding = Finding.objects.create(scan=self.scan, **kwargs)
        sev_label = dict(Severity.choices).get(finding.severity, finding.severity)
        self.log(f"[{sev_label}] {finding.title}"
                 + (f"  ({finding.affected_url})" if finding.affected_url else ""),
                 level="warning" if finding.severity in {
                     Severity.CRITICAL, Severity.HIGH} else "info")
        return finding


@dataclass
class ModuleResult:
    name: str
    ok: bool = True
    error: str = ""
    data: dict = field(default_factory=dict)
