"""Technology / framework / CMS / language fingerprinting.

Uses WhatWeb when available; otherwise applies a built-in signature engine
against headers, cookies, HTML markup, meta tags, and script/link URLs.
"""
from __future__ import annotations

import json
import re

from scanner.models import Technology

from .base import ScanContext
from .runner import run_command, tool_available

# name -> (category, list of compiled matchers keyed by source)
# Matchers are (source, regex, optional version-group).
_SIGNATURES = [
    ("WordPress", "CMS", [
        ("html", r"wp-content|wp-includes"),
        ("meta_generator", r"WordPress\s*([\d.]+)?"),
    ]),
    ("Joomla", "CMS", [("html", r"/media/jui/|com_content|Joomla")]),
    ("Drupal", "CMS", [("html", r"Drupal|sites/default/files"),
                        ("header:x-generator", r"Drupal\s*([\d.]+)?")]),
    ("Magento", "CMS", [("html", r"Mage\.|/skin/frontend/|magento")]),
    ("Shopify", "CMS", [("html", r"cdn\.shopify\.com|Shopify")]),
    ("Django", "Framework", [("cookie", r"csrftoken|sessionid"),
                              ("header:server", r"WSGIServer")]),
    ("Ruby on Rails", "Framework", [("cookie", r"_session_id"),
                                     ("header:x-powered-by", r"Phusion Passenger")]),
    ("Laravel", "Framework", [("cookie", r"laravel_session|XSRF-TOKEN")]),
    ("ASP.NET", "Framework", [("header:x-powered-by", r"ASP\.NET"),
                               ("cookie", r"ASP\.NET_SessionId"),
                               ("header:x-aspnet-version", r"([\d.]+)")]),
    ("Express", "Framework", [("header:x-powered-by", r"Express")]),
    ("Flask", "Framework", [("header:server", r"Werkzeug"),
                             ("cookie", r"session=")]),
    ("Spring", "Framework", [("header:x-application-context", r".+"),
                              ("html", r"Whitelabel Error Page")]),
    ("React", "JS library", [("html", r"data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js")]),
    ("Vue.js", "JS library", [("html", r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-")]),
    ("Angular", "JS library", [("html", r"ng-version|angular(?:\.min)?\.js")]),
    ("jQuery", "JS library", [("html", r"jquery[.-]?([\d.]+)?(?:\.min)?\.js")]),
    ("Bootstrap", "UI framework", [("html", r"bootstrap(?:\.min)?\.(?:css|js)")]),
    ("Nginx", "Web server", [("header:server", r"nginx/?([\d.]+)?")]),
    ("Apache", "Web server", [("header:server", r"Apache/?([\d.]+)?")]),
    ("Microsoft-IIS", "Web server", [("header:server", r"Microsoft-IIS/?([\d.]+)?")]),
    ("LiteSpeed", "Web server", [("header:server", r"LiteSpeed")]),
    ("PHP", "Language", [("header:x-powered-by", r"PHP/?([\d.]+)?"),
                          ("html", r"\.php(?:\?|\"|')")]),
    ("Cloudflare", "CDN/WAF", [("header:server", r"cloudflare"),
                                ("header:cf-ray", r".+")]),
    ("Varnish", "Cache", [("header:via", r"varnish"),
                           ("header:x-varnish", r".+")]),
    ("Google Analytics", "Analytics", [("html", r"google-analytics\.com|gtag\(")]),
]

_META_GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                          re.IGNORECASE)


def run(ctx: ScanContext) -> list[dict]:
    ctx.set_phase("Technology detection", 26, "Fingerprinting technologies")
    resp = ctx.get(ctx.scan.target_url)
    detected: dict[str, dict] = {}

    if tool_available("whatweb"):
        detected.update(_run_whatweb(ctx))

    if resp is not None:
        detected.update(_signature_scan(ctx, resp))

    # Persist unique technologies.
    for name, meta in detected.items():
        Technology.objects.get_or_create(
            scan=ctx.scan, name=name,
            defaults={"version": meta.get("version", ""),
                      "category": meta.get("category", "")},
        )
    if detected:
        ctx.log("Technologies: " + ", ".join(sorted(detected.keys())),
                level="success", phase="Technology detection")
    else:
        ctx.log("No technologies fingerprinted", phase="Technology detection")
    ctx.scan.recon["technologies"] = [
        {"name": n, **m} for n, m in detected.items()
    ]
    ctx.scan.save(update_fields=["recon"])
    return list(detected.values())


def _run_whatweb(ctx: ScanContext) -> dict:
    ctx.use_tool("whatweb")
    result = run_command(
        ["whatweb", "--no-errors", "-a", "3", "--log-json=-",
         ctx.scan.target_url], timeout=90)
    ctx.cmd_log(result.command, phase="Technology detection")
    out: dict = {}
    if not result.stdout:
        return out
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        for plugin, info in (data.get("plugins") or {}).items():
            version = ""
            if isinstance(info, dict):
                v = info.get("version")
                if isinstance(v, list) and v:
                    version = str(v[0])
                elif v:
                    version = str(v)
            out[plugin] = {"category": "whatweb", "version": version}
    return out


def _signature_scan(ctx: ScanContext, resp) -> dict:
    html = resp.text or ""
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
    meta_gen_match = _META_GEN_RE.search(html)
    meta_generator = meta_gen_match.group(1) if meta_gen_match else ""

    detected: dict[str, dict] = {}
    for name, category, matchers in _SIGNATURES:
        for source, pattern, *_ in matchers:
            hay = ""
            if source == "html":
                hay = html
            elif source == "cookie":
                hay = cookies
            elif source == "meta_generator":
                hay = meta_generator
            elif source.startswith("header:"):
                hay = headers.get(source.split(":", 1)[1], "")
            if not hay:
                continue
            m = re.search(pattern, hay, re.IGNORECASE)
            if m:
                version = ""
                if m.groups():
                    version = next((g for g in m.groups() if g), "")
                detected.setdefault(name, {"category": category, "version": version})
                if version and not detected[name].get("version"):
                    detected[name]["version"] = version
                break

    if meta_generator and meta_generator not in detected:
        detected[meta_generator.split(" ")[0]] = {
            "category": "Generator", "version": ""}
    return detected
