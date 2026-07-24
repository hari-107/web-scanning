"""Breadth-first crawler that builds the site map and extracts forms/params.

Stays on the target host, honours page/depth caps from settings, and records
Endpoints and Forms. Extracted forms are classified (login/search/upload/…) so
the vulnerability modules can test them intelligently.
"""
from __future__ import annotations

from collections import deque
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup
from django.conf import settings

from scanner.models import Endpoint, Form

from .base import ScanContext

SCAN = settings.SCAN_SETTINGS

_SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".pdf",
    ".zip", ".gz", ".tar", ".rar", ".7z", ".dmg", ".exe", ".msi",
)


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc.split(":")[0] == urlparse(b).netloc.split(":")[0]


def _classify_form(action: str, fields: list[dict]) -> str:
    names = {(f.get("name") or "").lower() for f in fields}
    types = {(f.get("type") or "").lower() for f in fields}
    act = (action or "").lower()
    if "password" in types:
        if any(k in names for k in ("confirm", "email", "repeat", "confirm_password")) \
                or "register" in act or "signup" in act:
            return "registration"
        return "login"
    if "file" in types:
        return "upload"
    if any(k in names for k in ("q", "query", "search", "s", "keyword")):
        return "search"
    if any(k in names for k in ("email", "message", "contact", "subject")):
        return "contact"
    return "generic"


def run(ctx: ScanContext) -> dict:
    ctx.set_phase("Crawling", 52, "Crawling and mapping the site")
    start = ctx.scan.target_url
    max_pages = SCAN["MAX_CRAWL_PAGES"]
    max_depth = SCAN["MAX_CRAWL_DEPTH"]

    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    # Seed from robots/sitemap discoveries already on the scan.
    for u in (ctx.scan.recon.get("sitemap", {}).get("urls") or [])[:50]:
        if _same_host(u, start):
            queue.append((u, 1))
    pages_crawled = 0
    forms_found = 0

    while queue and pages_crawled < max_pages:
        url, depth = queue.popleft()
        url, _ = urldefrag(url)
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        if any(urlparse(url).path.lower().endswith(ext) for ext in _SKIP_EXT):
            continue

        resp = ctx.get(url)
        if resp is None:
            continue
        pages_crawled += 1
        ctx.note_url(url)
        ctype = resp.headers.get("Content-Type", "")
        Endpoint.objects.get_or_create(
            scan=ctx.scan, url=url, method="GET",
            defaults={"status_code": resp.status_code, "content_type": ctype,
                      "content_length": len(resp.content), "source": "crawler"},
        )
        # Record query params for later parameter testing.
        qs = parse_qs(urlparse(url).query)
        if qs:
            ctx.params.setdefault(url, set()).update(qs.keys())

        if "html" not in ctype.lower():
            continue
        if pages_crawled % 5 == 0:
            ctx.log(f"Crawled {pages_crawled} pages...", phase="Crawling")

        soup = BeautifulSoup(resp.text, "html.parser")
        forms_found += _extract_forms(ctx, url, soup)

        if depth < max_depth:
            for a in soup.find_all("a", href=True):
                nxt = urljoin(url, a["href"])
                nxt, _ = urldefrag(nxt)
                if nxt.startswith(("http://", "https://")) and _same_host(nxt, start) \
                        and nxt not in seen:
                    queue.append((nxt, depth + 1))

    ctx.scan.total_urls_discovered = ctx.url_count
    ctx.scan.save(update_fields=["total_urls_discovered"])
    ctx.log(f"Crawl complete: {pages_crawled} pages, {forms_found} forms, "
            f"{len(ctx.params)} parameterised URLs", level="success",
            phase="Crawling")
    return {"pages": pages_crawled, "forms": forms_found}


def _extract_forms(ctx: ScanContext, page_url: str, soup: BeautifulSoup) -> int:
    count = 0
    for form in soup.find_all("form"):
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "GET").upper()
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            fields.append({
                "name": name,
                "type": (inp.get("type") or inp.name or "text").lower(),
                "value": inp.get("value") or "",
            })
        if not fields:
            continue
        kind = _classify_form(action, fields)
        Form.objects.create(
            scan=ctx.scan, page_url=page_url, action=action, method=method,
            fields=fields, form_kind=kind,
        )
        ctx.forms.append({
            "page_url": page_url, "action": action, "method": method,
            "fields": fields, "kind": kind,
        })
        count += 1
    return count
