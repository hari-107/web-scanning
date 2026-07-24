"""Database models for the Web Security Assessment Platform.

The schema is intentionally denormalised-friendly: a single ``Scan`` row owns
every artefact produced by the pipeline (findings, ports, technologies,
endpoints, forms, headers, cookies, and streaming log lines). No user accounts
are involved -- anyone can browse, search, rescan, or delete reports.
"""
from __future__ import annotations

import shlex
from urllib.parse import quote, urlencode

from django.db import models
from django.utils import timezone


class Severity(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    INFO = "info", "Informational"


# Numeric weights used for the overall security score and ordering.
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ScanStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    CANCELLED = "cancelled", "Cancelled"


class RiskRating(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    MINIMAL = "minimal", "Minimal"


class Scan(models.Model):
    """One assessment run against a single target URL."""

    target_url = models.URLField(max_length=2048)
    hostname = models.CharField(max_length=512, blank=True)
    ip_address = models.CharField(max_length=64, blank=True)

    status = models.CharField(
        max_length=16, choices=ScanStatus.choices, default=ScanStatus.QUEUED
    )
    # Live progress fields, updated by the orchestrator as it runs.
    phase = models.CharField(max_length=120, blank=True, default="Queued")
    progress = models.PositiveSmallIntegerField(default=0)  # 0-100
    current_task = models.CharField(max_length=255, blank=True)
    completed_tasks = models.PositiveIntegerField(default=0)
    total_tasks = models.PositiveIntegerField(default=0)

    # Aggregate metrics for the report header / dashboard.
    total_requests = models.PositiveIntegerField(default=0)
    total_urls_discovered = models.PositiveIntegerField(default=0)
    security_score = models.PositiveSmallIntegerField(default=100)  # 0-100
    risk_rating = models.CharField(
        max_length=16, choices=RiskRating.choices, default=RiskRating.MINIMAL
    )
    executive_summary = models.TextField(blank=True)

    # Free-form structured recon output that does not deserve its own table
    # (DNS records, SSL analysis, robots/sitemap, server/OS fingerprint...).
    recon = models.JSONField(default=dict, blank=True)
    tools_used = models.JSONField(default=list, blank=True)
    error = models.TextField(blank=True)

    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        # NB: target_url is a long URLField; an index on it would exceed
        # InnoDB's 3072-byte key limit, so we index only short/scalar columns.
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"Scan #{self.pk} {self.target_url} ({self.status})"

    # -- convenience -------------------------------------------------------
    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        if self.started_at:
            return (timezone.now() - self.started_at).total_seconds()
        return None

    @property
    def duration_display(self) -> str:
        secs = self.duration_seconds
        if secs is None:
            return "-"
        secs = int(secs)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for row in (
            self.findings.values("severity")
            .order_by("severity")
            .annotate(n=models.Count("id"))
        ):
            counts[row["severity"]] = row["n"]
        return counts

    @property
    def is_active(self) -> bool:
        return self.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}


class Finding(models.Model):
    """A single vulnerability or informational observation."""

    scan = models.ForeignKey(Scan, related_name="findings", on_delete=models.CASCADE)
    title = models.CharField(max_length=300)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    confidence = models.CharField(max_length=32, default="Firm")  # Certain/Firm/Tentative

    affected_url = models.URLField(max_length=2048, blank=True)
    http_method = models.CharField(max_length=10, blank=True)
    parameter = models.CharField(max_length=255, blank=True)

    evidence = models.TextField(blank=True)
    proof = models.TextField(blank=True)
    payload = models.TextField(blank=True)

    cvss_score = models.FloatField(null=True, blank=True)
    cwe = models.CharField(max_length=32, blank=True)  # e.g. "CWE-89"
    description = models.TextField(blank=True)
    impact = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    references = models.JSONField(default=list, blank=True)

    detected_by = models.CharField(max_length=120, blank=True)  # tool/module
    # Stable hash used to de-duplicate identical findings within a scan.
    dedup_key = models.CharField(max_length=64, db_index=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["scan", "id"]
        indexes = [models.Index(fields=["scan", "severity"])]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}"

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)

    # -- reproducible proof-of-concept ------------------------------------
    # These are computed from method/url/parameter/payload so they work on
    # findings that were stored before PoCs existed (no migration needed).
    @property
    def poc_url(self) -> str:
        """For GET findings, the full URL with the payload in the parameter."""
        if not self.affected_url:
            return ""
        if (self.http_method or "GET").upper() != "GET" or not self.parameter:
            return self.affected_url
        sep = "&" if "?" in self.affected_url else "?"
        return f"{self.affected_url}{sep}{quote(self.parameter)}=" \
               f"{quote(self.payload or '')}"

    @property
    def poc_body(self) -> str:
        """For POST findings, the url-encoded request body."""
        method = (self.http_method or "GET").upper()
        if method != "POST" or not self.parameter:
            return ""
        # A finding may cover several fields (e.g. "username/password").
        fields = [p.strip() for p in self.parameter.split("/") if p.strip()]
        return urlencode({f: self.payload or "" for f in fields})

    @property
    def poc_curl(self) -> str:
        """A copy-paste curl command that reproduces the finding."""
        if not self.affected_url:
            return ""
        method = (self.http_method or "GET").upper()
        if method == "POST":
            body = self.poc_body or urlencode(
                {self.parameter or "param": self.payload or ""})
            return (f"curl -i -X POST {shlex.quote(self.affected_url)} "
                    f"-d {shlex.quote(body)}")
        # GET (and OPTIONS etc.) -- include -X for non-GET verbs.
        verb = "" if method == "GET" else f"-X {method} "
        return f"curl -i {verb}{shlex.quote(self.poc_url or self.affected_url)}"


class Port(models.Model):
    scan = models.ForeignKey(Scan, related_name="ports", on_delete=models.CASCADE)
    number = models.PositiveIntegerField()
    protocol = models.CharField(max_length=8, default="tcp")
    state = models.CharField(max_length=16, default="open")
    service = models.CharField(max_length=64, blank=True)
    product = models.CharField(max_length=128, blank=True)
    version = models.CharField(max_length=128, blank=True)

    class Meta:
        ordering = ["number"]
        unique_together = ("scan", "number", "protocol")

    def __str__(self) -> str:
        return f"{self.number}/{self.protocol} {self.service}"


class Technology(models.Model):
    scan = models.ForeignKey(
        Scan, related_name="technologies", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=128)
    version = models.CharField(max_length=64, blank=True)
    category = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["category", "name"]
        unique_together = ("scan", "name")

    def __str__(self) -> str:
        return f"{self.name} {self.version}".strip()


class Endpoint(models.Model):
    """A URL discovered by crawling or directory enumeration."""

    scan = models.ForeignKey(Scan, related_name="endpoints", on_delete=models.CASCADE)
    url = models.URLField(max_length=2048)
    method = models.CharField(max_length=10, default="GET")
    status_code = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=128, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    source = models.CharField(max_length=64, blank=True)  # crawler / dirsearch / ...
    interesting = models.BooleanField(default=False)  # admin panel, git, env, backup

    class Meta:
        ordering = ["url"]
        # No DB unique constraint: url is a long URLField that would blow the
        # InnoDB key-length limit. De-duplication is done in code via
        # get_or_create (SELECT then INSERT).

    def __str__(self) -> str:
        return f"{self.method} {self.url} ({self.status_code})"


class Form(models.Model):
    scan = models.ForeignKey(Scan, related_name="forms", on_delete=models.CASCADE)
    page_url = models.URLField(max_length=2048)
    action = models.URLField(max_length=2048, blank=True)
    method = models.CharField(max_length=10, default="GET")
    # List of {"name":..., "type":..., "value":...} dicts.
    fields = models.JSONField(default=list, blank=True)
    form_kind = models.CharField(max_length=32, blank=True)  # login/search/upload/...

    class Meta:
        ordering = ["page_url"]

    def __str__(self) -> str:
        return f"{self.method} form @ {self.page_url}"


class HttpHeader(models.Model):
    scan = models.ForeignKey(Scan, related_name="headers", on_delete=models.CASCADE)
    name = models.CharField(max_length=128)
    value = models.TextField(blank=True)
    is_security_header = models.BooleanField(default=False)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name}: {self.value[:40]}"


class Cookie(models.Model):
    scan = models.ForeignKey(Scan, related_name="cookies", on_delete=models.CASCADE)
    name = models.CharField(max_length=128)
    secure = models.BooleanField(default=False)
    http_only = models.BooleanField(default=False)
    same_site = models.CharField(max_length=16, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class LogLine(models.Model):
    """Streaming execution log shown live and stored with the report."""

    LEVELS = [
        ("info", "info"),
        ("success", "success"),
        ("warning", "warning"),
        ("error", "error"),
        ("cmd", "cmd"),
    ]
    scan = models.ForeignKey(Scan, related_name="logs", on_delete=models.CASCADE)
    ts = models.DateTimeField(default=timezone.now)
    level = models.CharField(max_length=10, choices=LEVELS, default="info")
    phase = models.CharField(max_length=120, blank=True)
    message = models.TextField()

    class Meta:
        ordering = ["id"]

    def __str__(self) -> str:
        return f"[{self.level}] {self.message[:60]}"
