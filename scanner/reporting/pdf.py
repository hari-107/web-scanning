"""Professional PDF report generation with ReportLab."""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from scanner.models import Scan, Severity, SEVERITY_ORDER

_SEV_COLOR = {
    "critical": colors.HexColor("#c0392b"),
    "high": colors.HexColor("#e67e22"),
    "medium": colors.HexColor("#d4ac0d"),
    "low": colors.HexColor("#2980b9"),
    "info": colors.HexColor("#7f8c8d"),
}
_RISK_COLOR = {
    "critical": colors.HexColor("#c0392b"),
    "high": colors.HexColor("#e67e22"),
    "medium": colors.HexColor("#d4ac0d"),
    "low": colors.HexColor("#2980b9"),
    "minimal": colors.HexColor("#27ae60"),
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("WSTitle", parent=ss["Title"], fontSize=22,
                          textColor=colors.HexColor("#1a2332")))
    ss.add(ParagraphStyle("WSH2", parent=ss["Heading2"], fontSize=14,
                          textColor=colors.HexColor("#1f6feb"), spaceBefore=10))
    ss.add(ParagraphStyle("WSH3", parent=ss["Heading3"], fontSize=11,
                          textColor=colors.HexColor("#24292f"), spaceBefore=6))
    ss.add(ParagraphStyle("WSBody", parent=ss["BodyText"], fontSize=9,
                          leading=13))
    ss.add(ParagraphStyle("WSSmall", parent=ss["BodyText"], fontSize=8,
                          textColor=colors.HexColor("#57606a")))
    ss.add(ParagraphStyle("WSMono", parent=ss["BodyText"], fontSize=8,
                          fontName="Courier", leading=11))
    ss.add(ParagraphStyle("WSCenter", parent=ss["BodyText"], alignment=TA_CENTER))
    return ss


def build_pdf(scan: Scan) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
        leftMargin=16 * mm, rightMargin=16 * mm,
        title=f"WebSec Report #{scan.pk}",
    )
    ss = _styles()
    story = []
    _cover(story, ss, scan)
    _summary(story, ss, scan)
    _findings(story, ss, scan)
    _appendix(story, ss, scan)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#8b949e"))
    canvas.drawString(16 * mm, 10 * mm,
                      "WebSec Scanner - Confidential - For authorised use only")
    canvas.drawRightString(A4[0] - 16 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _cover(story, ss, scan: Scan):
    story.append(Spacer(1, 30 * mm))
    story.append(Paragraph("Web Security Assessment Report", ss["WSTitle"]))
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#1f6feb")))
    story.append(Spacer(1, 8 * mm))

    risk = scan.risk_rating
    meta = [
        ["Target", scan.target_url],
        ["Hostname", scan.hostname or "-"],
        ["IP Address", scan.ip_address or "-"],
        ["Scan ID", f"#{scan.pk}"],
        ["Date", scan.created_at.strftime("%Y-%m-%d %H:%M UTC")],
        ["Duration", scan.duration_display],
        ["Security Score", f"{scan.security_score} / 100"],
        ["Risk Rating", scan.get_risk_rating_display()],
    ]
    t = Table(meta, colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#57606a")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#d0d7de")),
        ("TEXTCOLOR", (1, 7), (1, 7), _RISK_COLOR.get(risk, colors.black)),
        ("FONTNAME", (1, 6), (1, 7), "Helvetica-Bold"),
    ]))
    story.append(t)
    story.append(PageBreak())


def _summary(story, ss, scan: Scan):
    story.append(Paragraph("Executive Summary", ss["WSH2"]))
    story.append(Paragraph(scan.executive_summary or "No summary available.",
                           ss["WSBody"]))
    story.append(Spacer(1, 4 * mm))

    counts = scan.severity_counts()
    header = ["Critical", "High", "Medium", "Low", "Info"]
    keys = ["critical", "high", "medium", "low", "info"]
    row = [str(counts.get(k, 0)) for k in keys]
    t = Table([header, row], colWidths=[33 * mm] * 5)
    style = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("TOPPADDING", (0, 1), (-1, 1), 8),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.white),
    ]
    for i, k in enumerate(keys):
        style.append(("BACKGROUND", (i, 0), (i, 0), _SEV_COLOR[k]))
        style.append(("BACKGROUND", (i, 1), (i, 1), colors.HexColor("#f6f8fa")))
    t.setStyle(TableStyle(style))
    story.append(t)
    story.append(Spacer(1, 4 * mm))

    # Metrics line.
    metrics = [
        ["URLs Discovered", str(scan.total_urls_discovered),
         "Requests Made", str(scan.total_requests)],
        ["Open Ports", str(scan.ports.count()),
         "Technologies", str(scan.technologies.count())],
        ["Forms", str(scan.forms.count()),
         "Endpoints", str(scan.endpoints.count())],
    ]
    mt = Table(metrics, colWidths=[40 * mm, 42 * mm, 40 * mm, 42 * mm])
    mt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#57606a")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#57606a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(mt)
    if scan.tools_used:
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("Tools used: " + ", ".join(scan.tools_used),
                               ss["WSSmall"]))
    story.append(PageBreak())


def _findings(story, ss, scan: Scan):
    story.append(Paragraph("Detailed Findings", ss["WSH2"]))
    findings = sorted(scan.findings.all(),
                      key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.id))
    if not findings:
        story.append(Paragraph("No findings were recorded for this scan.",
                               ss["WSBody"]))
        return

    for i, f in enumerate(findings, 1):
        sev = f.severity
        badge = Table([[f"{f.get_severity_display().upper()}"]],
                      colWidths=[26 * mm])
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _SEV_COLOR.get(sev, colors.grey)),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        title_tbl = Table([[badge, Paragraph(f"<b>{i}. {_esc(f.title)}</b>",
                                             ss["WSBody"])]],
                          colWidths=[28 * mm, 137 * mm])
        title_tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (1, 0), (1, 0), 4),
        ]))
        story.append(Spacer(1, 3 * mm))
        story.append(title_tbl)

        detail_rows = []
        if f.affected_url:
            detail_rows.append(["Affected URL", f.affected_url])
        if f.http_method:
            detail_rows.append(["Method", f.http_method])
        if f.parameter:
            detail_rows.append(["Parameter", f.parameter])
        if f.cvss_score:
            detail_rows.append(["CVSS", str(f.cvss_score)])
        if f.cwe:
            detail_rows.append(["CWE", f.cwe])
        detail_rows.append(["Confidence", f.confidence])
        detail_rows.append(["Detected by", f.detected_by])
        dt = Table([[k, Paragraph(_esc(v), ss["WSMono"])] for k, v in detail_rows],
                   colWidths=[30 * mm, 135 * mm])
        dt.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#57606a")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(dt)

        for label, val in (("Description", f.description), ("Impact", f.impact),
                           ("Remediation", f.remediation)):
            if val:
                story.append(Paragraph(f"<b>{label}.</b> {_esc(val)}", ss["WSBody"]))
        for label, val in (("Evidence", f.evidence), ("Proof", f.proof),
                           ("Payload", f.payload)):
            if val:
                story.append(Paragraph(f"<b>{label}:</b>", ss["WSSmall"]))
                story.append(Paragraph(_esc(val)[:900], ss["WSMono"]))
        if f.references:
            refs = "<br/>".join(_esc(r) for r in f.references)
            story.append(Paragraph(f"<b>References:</b><br/>{refs}", ss["WSSmall"]))
        story.append(HRFlowable(width="100%", thickness=0.4,
                                color=colors.HexColor("#d0d7de")))


def _appendix(story, ss, scan: Scan):
    story.append(PageBreak())
    story.append(Paragraph("Appendix", ss["WSH2"]))

    ports = list(scan.ports.all())
    if ports:
        story.append(Paragraph("Open Ports & Services", ss["WSH3"]))
        data = [["Port", "Proto", "Service", "Product", "Version"]] + [
            [str(p.number), p.protocol, p.service, p.product, p.version]
            for p in ports]
        story.append(_grid(data, [18 * mm, 18 * mm, 40 * mm, 45 * mm, 44 * mm]))
        story.append(Spacer(1, 4 * mm))

    techs = list(scan.technologies.all())
    if techs:
        story.append(Paragraph("Detected Technologies", ss["WSH3"]))
        data = [["Name", "Version", "Category"]] + [
            [t.name, t.version, t.category] for t in techs]
        story.append(_grid(data, [70 * mm, 40 * mm, 55 * mm]))
        story.append(Spacer(1, 4 * mm))

    interesting = list(scan.endpoints.filter(interesting=True))
    if interesting:
        story.append(Paragraph("Interesting Endpoints", ss["WSH3"]))
        data = [["URL", "Status"]] + [
            [e.url, str(e.status_code or "-")] for e in interesting[:40]]
        story.append(_grid(data, [140 * mm, 25 * mm]))


def _grid(data, col_widths):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f6f8fa")]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d0d7de")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _esc(text) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
