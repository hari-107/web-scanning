"""TCP port scanning + service/version detection.

Uses Nmap (``-sV``) when installed for authoritative results. Otherwise falls
back to a threaded Python socket scanner over a curated port list with light
banner grabbing to guess the service.
"""
from __future__ import annotations

import re
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.conf import settings

from scanner.models import Port, Severity

from .base import ScanContext
from .runner import run_command, tool_available

SCAN = settings.SCAN_SETTINGS

# Curated set for the fallback scanner: common + high-signal service ports.
_FALLBACK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
    587, 993, 995, 1433, 1521, 2049, 2082, 2083, 2222, 3000, 3128, 3306,
    3389, 4444, 5000, 5432, 5601, 5900, 5985, 6379, 7001, 8000, 8008, 8080,
    8081, 8088, 8090, 8443, 8888, 9000, 9200, 9300, 11211, 27017,
]

_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 3000: "http", 5000: "http",
    8000: "http", 8888: "http", 9000: "http",
}

# Services that are risky to expose to the internet.
_RISKY_SERVICES = {
    23: ("Telnet service exposed", Severity.HIGH,
         "Telnet transmits credentials in cleartext."),
    21: ("FTP service exposed", Severity.MEDIUM,
         "FTP often transmits credentials in cleartext."),
    3306: ("MySQL database port exposed", Severity.HIGH,
           "Direct database exposure invites brute-force and data theft."),
    5432: ("PostgreSQL database port exposed", Severity.HIGH,
           "Direct database exposure invites brute-force and data theft."),
    6379: ("Redis port exposed", Severity.HIGH,
           "Redis frequently lacks authentication by default."),
    27017: ("MongoDB port exposed", Severity.HIGH,
            "MongoDB has historically shipped without authentication."),
    9200: ("Elasticsearch port exposed", Severity.HIGH,
           "Elasticsearch often lacks authentication and leaks data."),
    3389: ("RDP exposed", Severity.MEDIUM,
           "Exposed RDP is a common ransomware entry point."),
    11211: ("Memcached port exposed", Severity.MEDIUM,
            "Memcached can be abused for amplification and data leakage."),
    445: ("SMB port exposed", Severity.MEDIUM,
          "SMB exposure has led to major worm outbreaks."),
}


def run(ctx: ScanContext) -> list[dict]:
    ctx.set_phase("Port scanning", 32, "Scanning TCP ports")
    host = ctx.scan.ip_address or ctx.hostname
    if not host:
        ctx.log("No host to port scan", level="warning", phase="Port scanning")
        return []

    if tool_available("nmap"):
        ports = _nmap_scan(ctx, host)
    else:
        ctx.log("nmap not found; using built-in socket scanner",
                phase="Port scanning")
        ports = _socket_scan(ctx, host)

    for p in ports:
        Port.objects.get_or_create(
            scan=ctx.scan, number=p["number"], protocol=p.get("protocol", "tcp"),
            defaults={
                "state": p.get("state", "open"),
                "service": p.get("service", ""),
                "product": p.get("product", ""),
                "version": p.get("version", ""),
            },
        )
        _flag_risky(ctx, p)

    ctx.log(f"Found {len(ports)} open port(s)", level="success",
            phase="Port scanning")
    return ports


def _flag_risky(ctx: ScanContext, p: dict) -> None:
    meta = _RISKY_SERVICES.get(p["number"])
    if not meta:
        return
    title, severity, impact = meta
    svc = p.get("service") or _SERVICE_NAMES.get(p["number"], "")
    ver = (p.get("product", "") + " " + p.get("version", "")).strip()
    ctx.add_finding(
        title=title,
        severity=severity,
        affected_url=f"{ctx.hostname}:{p['number']}",
        evidence=f"Port {p['number']}/tcp open"
                 + (f" ({svc} {ver})".rstrip() if svc else ""),
        cwe="CWE-668",
        description=f"Port {p['number']} ({svc}) is reachable.",
        impact=impact,
        remediation="Restrict access via firewall/VPN; disable the service if "
                    "not required; enforce authentication and encryption.",
        detected_by="ports.nmap" if tool_available("nmap") else "ports.socket",
        confidence="Firm",
    )


def _nmap_scan(ctx: ScanContext, host: str) -> list[dict]:
    ctx.use_tool("nmap")
    result = run_command(
        ["nmap", "-Pn", "-T4", "-sV", "--top-ports", "200", "-oX", "-", host],
        timeout=300)
    ctx.cmd_log(result.command, phase="Port scanning")
    if not result.stdout:
        if result.timed_out:
            ctx.log("nmap timed out", level="warning", phase="Port scanning")
        return []
    return _parse_nmap_xml(result.stdout)


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    ports: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ports
    for host_el in root.iter("host"):
        for port_el in host_el.iter("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port_el.find("service")
            ports.append({
                "number": int(port_el.get("portid")),
                "protocol": port_el.get("protocol", "tcp"),
                "state": "open",
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
    return ports


def _socket_scan(ctx: ScanContext, host: str) -> list[dict]:
    ctx.use_tool("socket (python)")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        ctx.log(f"Could not resolve {host}", level="error", phase="Port scanning")
        return []

    open_ports: list[dict] = []
    max_workers = min(SCAN["PORT_SCAN_THREADS"], len(_FALLBACK_PORTS))

    def probe(port: int):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.2)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = _grab_banner(ip, port)
            return {
                "number": port, "protocol": "tcp", "state": "open",
                "service": _SERVICE_NAMES.get(port, ""),
                "product": banner.get("product", ""),
                "version": banner.get("version", ""),
            }

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, p): p for p in _FALLBACK_PORTS}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)
                ctx.log(f"Open: {res['number']}/tcp {res['service']}".rstrip(),
                        phase="Port scanning")
    open_ports.sort(key=lambda p: p["number"])
    return open_ports


_BANNER_VERSION_RE = re.compile(r"([A-Za-z][\w\-]+)[/ ]([\d][\w.\-]*)")


def _grab_banner(ip: str, port: int) -> dict:
    """Best-effort banner grab; sends a benign probe for HTTP-ish ports."""
    out: dict = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((ip, port))
            if port in (80, 8080, 8000, 8888, 8081, 3000, 5000, 9000, 8443, 443):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(256)
            text = data.decode("latin-1", "replace")
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    m = _BANNER_VERSION_RE.search(server)
                    out["product"] = m.group(1) if m else server[:40]
                    out["version"] = m.group(2) if m else ""
                    return out
            m = _BANNER_VERSION_RE.search(text)
            if m:
                out["product"] = m.group(1)
                out["version"] = m.group(2)
    except (socket.timeout, OSError):
        pass
    return out
