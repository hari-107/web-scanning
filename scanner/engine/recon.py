"""Passive/active reconnaissance: DNS, IP, server & OS fingerprint, headers,
cookies, robots.txt and sitemap.xml.

Records structured data onto ``scan.recon`` and creates HttpHeader / Cookie
rows, plus low-severity findings for missing security headers and insecure
cookie flags.
"""
from __future__ import annotations

import socket
from urllib.parse import urljoin
from xml.etree import ElementTree as ET

from scanner.models import Cookie, HttpHeader, Severity

from .base import ScanContext

try:
    import dns.resolver  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False


SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "Missing HTTP Strict Transport Security (HSTS) header",
        "severity": Severity.LOW,
        "cwe": "CWE-319",
        "remediation": "Send 'Strict-Transport-Security: max-age=31536000; "
                       "includeSubDomains' over HTTPS to force secure transport.",
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy header",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-693",
        "remediation": "Define a restrictive Content-Security-Policy to mitigate "
                       "XSS and data-injection attacks.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options header (clickjacking)",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-1021",
        "remediation": "Set 'X-Frame-Options: DENY' or a CSP frame-ancestors "
                       "directive to prevent framing.",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": Severity.LOW,
        "cwe": "CWE-693",
        "remediation": "Set 'X-Content-Type-Options: nosniff' to stop MIME "
                       "sniffing.",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "severity": Severity.INFO,
        "cwe": "CWE-200",
        "remediation": "Set a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy header",
        "severity": Severity.INFO,
        "cwe": "CWE-693",
        "remediation": "Define a Permissions-Policy to restrict powerful browser "
                       "features.",
    },
}


def _resolve_dns(ctx: ScanContext) -> dict:
    host = ctx.hostname
    info: dict = {"hostname": host, "a": [], "aaaa": [], "mx": [], "ns": [],
                  "txt": [], "cname": []}
    # Basic A record via socket (always available).
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        info["a"] = ips
    except (socket.gaierror, socket.herror):
        pass
    if _HAVE_DNS:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                answers = resolver.resolve(host, rtype)
                vals = [r.to_text().strip('"') for r in answers]
                info[rtype.lower()] = vals
            except Exception:
                continue
    if info["a"]:
        ctx.scan.ip_address = info["a"][0]
    return info


def _fingerprint_os(server: str, headers: dict) -> str:
    s = (server or "").lower()
    powered = (headers.get("x-powered-by") or "").lower()
    blob = s + " " + powered
    if "win" in blob or "iis" in blob or "asp.net" in blob:
        return "Windows (inferred)"
    if any(k in blob for k in ("ubuntu", "debian")):
        return "Debian/Ubuntu Linux (inferred)"
    if any(k in blob for k in ("centos", "red hat", "rhel", "fedora")):
        return "RHEL/CentOS Linux (inferred)"
    if "unix" in blob:
        return "Unix (inferred)"
    if any(k in blob for k in ("apache", "nginx", "openssl")):
        return "Unix-like (inferred)"
    return "Unknown"


def run(ctx: ScanContext) -> dict:
    ctx.set_phase("Reconnaissance", 8, "Resolving DNS and IP")
    ctx.log("Starting reconnaissance", phase="Reconnaissance")

    dns_info = _resolve_dns(ctx)
    if dns_info["a"]:
        ctx.log(f"Resolved {ctx.hostname} -> {', '.join(dns_info['a'])}",
                level="success", phase="Reconnaissance")

    # Fetch the base URL once and analyse the response.
    resp = ctx.get(ctx.scan.target_url)
    headers = {}
    server = ""
    os_guess = "Unknown"
    if resp is not None:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        server = headers.get("server", "")
        os_guess = _fingerprint_os(server, headers)
        ctx.note_url(ctx.scan.target_url)

        # Persist every response header; flag security-relevant ones.
        sec_keys = set(SECURITY_HEADERS.keys()) | {
            "x-xss-protection", "cross-origin-opener-policy",
            "cross-origin-resource-policy", "access-control-allow-origin"}
        rows = [
            HttpHeader(scan=ctx.scan, name=k, value=str(v),
                       is_security_header=k.lower() in sec_keys)
            for k, v in resp.headers.items()
        ]
        HttpHeader.objects.bulk_create(rows)

        # Missing security headers -> findings.
        for key, meta in SECURITY_HEADERS.items():
            if key not in headers:
                ctx.add_finding(
                    title=meta["title"],
                    severity=meta["severity"],
                    affected_url=ctx.scan.target_url,
                    http_method="GET",
                    cwe=meta["cwe"],
                    description=f"The response did not include the '{key}' header.",
                    impact="Missing hardening headers make client-side attacks "
                           "easier to carry out.",
                    remediation=meta["remediation"],
                    detected_by="recon.headers",
                    confidence="Certain",
                    references=["https://owasp.org/www-project-secure-headers/"],
                )

        # Server banner disclosure.
        if server:
            ctx.add_finding(
                title="Web server banner discloses software/version",
                severity=Severity.INFO,
                affected_url=ctx.scan.target_url,
                evidence=f"Server: {server}",
                cwe="CWE-200",
                description="The Server header reveals the web server software "
                            "and possibly its version.",
                impact="Version disclosure helps attackers target known CVEs.",
                remediation="Suppress or genericise the Server/X-Powered-By headers.",
                detected_by="recon.headers",
                confidence="Certain",
            )

        # Cookie flags.
        _analyse_cookies(ctx, resp)

    ctx.set_phase("Reconnaissance", 12, "Fetching robots.txt / sitemap.xml")
    robots = _fetch_robots(ctx)
    sitemap = _fetch_sitemap(ctx)

    recon_data = {
        "dns": dns_info,
        "server": server,
        "os_fingerprint": os_guess,
        "x_powered_by": headers.get("x-powered-by", ""),
        "status_code": resp.status_code if resp is not None else None,
        "final_url": resp.url if resp is not None else ctx.scan.target_url,
        "robots": robots,
        "sitemap": sitemap,
    }
    ctx.scan.recon.update(recon_data)
    ctx.scan.save(update_fields=["ip_address", "recon"])
    ctx.log(f"OS fingerprint: {os_guess}; Server: {server or 'unknown'}",
            phase="Reconnaissance")
    return recon_data


def _analyse_cookies(ctx: ScanContext, resp) -> None:
    for c in resp.cookies:
        secure = bool(c.secure)
        http_only = bool(c._rest.get("HttpOnly") or c._rest.get("httponly"))
        same_site = c._rest.get("SameSite") or c._rest.get("samesite") or ""
        Cookie.objects.create(scan=ctx.scan, name=c.name, secure=secure,
                              http_only=http_only, same_site=str(same_site))
        problems = []
        if not secure:
            problems.append("missing Secure")
        if not http_only:
            problems.append("missing HttpOnly")
        if not same_site:
            problems.append("missing SameSite")
        if problems:
            ctx.add_finding(
                title=f"Cookie '{c.name}' set without recommended flags",
                severity=Severity.LOW,
                affected_url=ctx.scan.target_url,
                evidence=f"Set-Cookie {c.name}: {', '.join(problems)}",
                cwe="CWE-614",
                description="A cookie was issued without one or more of the "
                            "Secure, HttpOnly, or SameSite attributes.",
                impact="Cookies without these flags are exposed to theft over "
                       "plaintext channels, script access, or CSRF.",
                remediation="Set Secure, HttpOnly and SameSite=Lax/Strict on "
                            "session and sensitive cookies.",
                detected_by="recon.cookies",
                confidence="Certain",
            )


def _fetch_robots(ctx: ScanContext) -> dict:
    url = urljoin(ctx.base_url + "/", "robots.txt")
    resp = ctx.get(url)
    out = {"present": False, "url": url, "disallow": [], "sitemaps": [],
           "content": ""}
    if resp is not None and resp.status_code == 200 and "html" not in \
            resp.headers.get("Content-Type", "").lower():
        out["present"] = True
        out["content"] = resp.text[:8000]
        for line in resp.text.splitlines():
            low = line.strip().lower()
            if low.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    out["disallow"].append(path)
            elif low.startswith("sitemap:"):
                out["sitemaps"].append(line.split(":", 1)[1].strip())
        ctx.log(f"robots.txt found with {len(out['disallow'])} Disallow entries",
                level="success", phase="Reconnaissance")
        if out["disallow"]:
            ctx.add_finding(
                title="robots.txt reveals disallowed paths",
                severity=Severity.INFO,
                affected_url=url,
                evidence="Disallow: " + "; ".join(out["disallow"][:20]),
                cwe="CWE-200",
                description="robots.txt enumerates paths the site does not want "
                            "indexed, which can guide an attacker.",
                impact="Sensitive or administrative paths may be revealed.",
                remediation="Do not rely on robots.txt to hide sensitive paths; "
                            "enforce access control instead.",
                detected_by="recon.robots",
                confidence="Certain",
            )
    return out


def _fetch_sitemap(ctx: ScanContext) -> dict:
    url = urljoin(ctx.base_url + "/", "sitemap.xml")
    resp = ctx.get(url)
    out = {"present": False, "url": url, "urls": []}
    if resp is not None and resp.status_code == 200:
        try:
            root = ET.fromstring(resp.content)
            locs = [el.text.strip() for el in root.iter()
                    if el.tag.endswith("loc") and el.text]
            out["present"] = bool(locs)
            out["urls"] = locs[:500]
            for u in out["urls"]:
                ctx.note_url(u)
            if locs:
                ctx.log(f"sitemap.xml lists {len(locs)} URLs", level="success",
                        phase="Reconnaissance")
        except ET.ParseError:
            pass
    return out
