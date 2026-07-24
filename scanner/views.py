"""Views for the Web Security Assessment Platform (no authentication)."""
from __future__ import annotations

from django.contrib import messages
from django.db.models import Avg, Count, Q
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from .engine.background import start_scan
from .engine.validator import is_private_host, validate_target
from .models import (
    Finding,
    LogLine,
    RiskRating,
    Scan,
    ScanStatus,
    Severity,
    SEVERITY_ORDER,
)


def _severity_ordered(qs):
    return sorted(qs, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.id))


def dashboard(request):
    scans = Scan.objects.all()
    completed = scans.filter(status=ScanStatus.COMPLETED)

    # Aggregate severity counts across all findings.
    sev_rows = (Finding.objects.values("severity")
                .annotate(n=Count("id")))
    severity_stats = {s.value: 0 for s in Severity}
    for row in sev_rows:
        severity_stats[row["severity"]] = row["n"]

    # Risk-rating distribution across completed scans.
    risk_rows = (completed.values("risk_rating").annotate(n=Count("id")))
    risk_stats = {r.value: 0 for r in RiskRating}
    for row in risk_rows:
        risk_stats[row["risk_rating"]] = row["n"]

    context = {
        "total_scans": scans.count(),
        "completed_scans": completed.count(),
        "active_scans": scans.filter(
            status__in=[ScanStatus.QUEUED, ScanStatus.RUNNING]).count(),
        "total_findings": Finding.objects.count(),
        "severity_stats": severity_stats,
        "risk_stats": risk_stats,
        "avg_score": round(completed.aggregate(a=Avg("security_score"))["a"] or 0),
        "recent_scans": scans[:8],
        "recent_findings": _severity_ordered(
            Finding.objects.select_related("scan")
            .filter(severity__in=[Severity.CRITICAL, Severity.HIGH])[:200])[:10],
        "severity_choices": Severity.choices,
    }
    return render(request, "scanner/dashboard.html", context)


@require_POST
def start(request):
    raw = (request.POST.get("target_url") or "").strip()
    consent = request.POST.get("authorized") == "on"
    if not consent:
        messages.error(request, "You must confirm you are authorised to scan "
                                "the target before starting.")
        return redirect("dashboard")

    result = validate_target(raw)
    if not result.ok:
        messages.error(request, f"Invalid target: {result.reason}")
        return redirect("dashboard")

    scan = Scan.objects.create(
        target_url=result.url,
        hostname=result.hostname,
        status=ScanStatus.QUEUED,
        phase="Queued",
    )
    if is_private_host(result.hostname):
        messages.warning(request, f"'{result.hostname}' is a private/local "
                                  "address; scanning local lab target.")
    start_scan(scan)
    messages.success(request, f"Scan #{scan.pk} started for {result.url}.")
    return redirect("scan_progress", pk=scan.pk)


def scan_progress(request, pk: int):
    scan = get_object_or_404(Scan, pk=pk)
    return render(request, "scanner/progress.html", {"scan": scan})


def scan_status(request, pk: int):
    """JSON polled by the progress page."""
    scan = get_object_or_404(Scan, pk=pk)
    after = int(request.GET.get("after", 0) or 0)
    logs = list(
        LogLine.objects.filter(scan=scan, id__gt=after)
        .values("id", "level", "phase", "message", "ts")[:500]
    )
    for entry in logs:
        entry["ts"] = timezone.localtime(entry["ts"]).strftime("%H:%M:%S")
    return JsonResponse({
        "status": scan.status,
        "phase": scan.phase,
        "progress": scan.progress,
        "current_task": scan.current_task,
        "completed_tasks": scan.completed_tasks,
        "total_tasks": scan.total_tasks,
        "total_requests": scan.total_requests,
        "total_urls": scan.total_urls_discovered,
        "duration": scan.duration_display,
        "severity_counts": scan.severity_counts(),
        "logs": logs,
        "done": scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED,
                                ScanStatus.CANCELLED],
        "report_url": reverse("report", args=[scan.pk]),
    })


def report(request, pk: int):
    scan = get_object_or_404(
        Scan.objects.prefetch_related(
            "findings", "ports", "technologies", "endpoints", "forms",
            "headers", "cookies"),
        pk=pk,
    )
    findings = _severity_ordered(scan.findings.all())
    context = {
        "scan": scan,
        "findings": findings,
        "severity_counts": scan.severity_counts(),
        "ports": scan.ports.all(),
        "technologies": scan.technologies.all(),
        "endpoints": scan.endpoints.all(),
        "interesting_endpoints": scan.endpoints.filter(interesting=True),
        "forms": scan.forms.all(),
        "headers": scan.headers.all(),
        "security_headers": scan.headers.filter(is_security_header=True),
        "cookies": scan.cookies.all(),
        "recon": scan.recon or {},
        "severity_labels": dict(Severity.choices),
    }
    return render(request, "scanner/report.html", context)


def report_list(request):
    q = (request.GET.get("q") or "").strip()
    severity = (request.GET.get("severity") or "").strip()
    status = (request.GET.get("status") or "").strip()
    scans = Scan.objects.all()
    if q:
        scans = scans.filter(Q(target_url__icontains=q) |
                             Q(hostname__icontains=q) |
                             Q(ip_address__icontains=q))
    if status:
        scans = scans.filter(status=status)
    if severity:
        scans = scans.filter(findings__severity=severity).distinct()
    return render(request, "scanner/report_list.html", {
        "scans": scans,
        "q": q,
        "severity": severity,
        "status": status,
        "severity_choices": Severity.choices,
        "status_choices": ScanStatus.choices,
    })


@require_POST
def rescan(request, pk: int):
    old = get_object_or_404(Scan, pk=pk)
    scan = Scan.objects.create(
        target_url=old.target_url,
        hostname=old.hostname,
        status=ScanStatus.QUEUED,
        phase="Queued",
    )
    start_scan(scan)
    messages.success(request, f"Rescan started as scan #{scan.pk}.")
    return redirect("scan_progress", pk=scan.pk)


@require_POST
def delete_scan(request, pk: int):
    scan = get_object_or_404(Scan, pk=pk)
    sid = scan.pk
    scan.delete()
    messages.success(request, f"Scan #{sid} deleted.")
    return redirect("report_list")


def compare(request):
    ids = request.GET.getlist("scan")
    scans = list(Scan.objects.filter(pk__in=ids)[:4])
    for s in scans:
        s.sev = s.severity_counts()
    return render(request, "scanner/compare.html", {
        "scans": scans,
        "all_scans": Scan.objects.filter(status=ScanStatus.COMPLETED)[:100],
        "severity_labels": dict(Severity.choices),
    })


def download_pdf(request, pk: int):
    scan = get_object_or_404(
        Scan.objects.prefetch_related(
            "findings", "ports", "technologies", "endpoints"),
        pk=pk,
    )
    from .reporting.pdf import build_pdf
    try:
        pdf_bytes = build_pdf(scan)
    except Exception as exc:  # pragma: no cover
        raise Http404(f"Could not generate PDF: {exc}")
    resp = HttpResponse(pdf_bytes, content_type="application/pdf")
    fname = f"websec_report_scan_{scan.pk}.pdf"
    resp["Content-Disposition"] = f'attachment; filename="{fname}"'
    return resp
