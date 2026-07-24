"""SSL/TLS configuration and certificate analysis (pure-Python via ssl)."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from scanner.models import Severity

from .base import ScanContext

# Protocols we can attempt to negotiate to flag deprecated ones.
_LEGACY_PROTOCOLS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}

_WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon")


def run(ctx: ScanContext) -> dict:
    ctx.set_phase("SSL/TLS analysis", 20, "Inspecting TLS certificate and ciphers")
    out: dict = {"enabled": ctx.parsed.scheme == "https", "host": ctx.hostname}

    if ctx.parsed.scheme != "https":
        ctx.log("Target is HTTP; no TLS to analyse", phase="SSL/TLS analysis")
        # Site served over plain HTTP -> finding.
        ctx.add_finding(
            title="Site served over unencrypted HTTP",
            severity=Severity.MEDIUM,
            affected_url=ctx.scan.target_url,
            cwe="CWE-319",
            description="The target is accessed over HTTP without transport "
                        "encryption.",
            impact="Traffic can be intercepted or modified in transit.",
            remediation="Serve all content over HTTPS and redirect HTTP to HTTPS.",
            detected_by="ssl.analysis",
            confidence="Certain",
        )
        return out

    port = ctx.parsed.port or 443
    ctx.use_tool("ssl (python)")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ctx.hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=ctx.hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                out["protocol"] = ssock.version()
                out["cipher"] = {"name": cipher[0], "protocol": cipher[1],
                                 "bits": cipher[2]} if cipher else {}
    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError) as exc:
        out["error"] = str(exc)
        ctx.log(f"TLS handshake failed: {exc}", level="error",
                phase="SSL/TLS analysis")
        return out

    # Certificate details (need verify to parse dates reliably; re-fetch verified).
    cert = _get_verified_cert(ctx.hostname, port)
    if cert:
        out["certificate"] = _summarise_cert(ctx, cert)

    # Weak cipher check on negotiated suite.
    negotiated = out.get("cipher", {}).get("name", "")
    if any(tok in negotiated.upper() for tok in _WEAK_CIPHER_TOKENS):
        ctx.add_finding(
            title="Weak TLS cipher negotiated",
            severity=Severity.MEDIUM,
            affected_url=ctx.scan.target_url,
            evidence=f"Negotiated cipher: {negotiated}",
            cwe="CWE-327",
            description="The server negotiated a cipher suite considered weak.",
            impact="Weak ciphers may allow decryption of intercepted traffic.",
            remediation="Disable RC4/3DES/DES/EXPORT/NULL ciphers; prefer AEAD "
                        "suites (AES-GCM, ChaCha20).",
            detected_by="ssl.analysis",
            confidence="Firm",
        )

    # Deprecated protocol support.
    weak_protocols = _probe_legacy_protocols(ctx.hostname, port)
    out["legacy_protocols"] = weak_protocols
    if weak_protocols:
        ctx.add_finding(
            title="Deprecated TLS protocol version supported",
            severity=Severity.MEDIUM,
            affected_url=ctx.scan.target_url,
            evidence="Supported: " + ", ".join(weak_protocols),
            cwe="CWE-327",
            description="The server accepts TLS 1.0/1.1 which are deprecated.",
            impact="Legacy protocols are vulnerable to known downgrade/crypto "
                   "attacks.",
            remediation="Disable TLS 1.0 and 1.1; require TLS 1.2 or higher.",
            detected_by="ssl.analysis",
            confidence="Firm",
        )

    ctx.log(f"TLS: {out.get('protocol')} / {negotiated}", level="success",
            phase="SSL/TLS analysis")
    ctx.scan.recon["ssl"] = out
    ctx.scan.save(update_fields=["recon"])
    return out


def _get_verified_cert(host: str, port: int) -> dict | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


def _summarise_cert(ctx: ScanContext, cert: dict) -> dict:
    def _name(seq):
        return dict(x[0] for x in seq) if seq else {}

    subject = _name(cert.get("subject"))
    issuer = _name(cert.get("issuer"))
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    summary = {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("commonName", ""),
        "not_before": not_before,
        "not_after": not_after,
        "san": [v for (k, v) in cert.get("subjectAltName", [])],
    }
    # Expiry check.
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            summary["days_remaining"] = (exp - datetime.now(timezone.utc)).days
            if summary["days_remaining"] < 0:
                ctx.add_finding(
                    title="Expired TLS certificate",
                    severity=Severity.HIGH,
                    affected_url=ctx.scan.target_url,
                    evidence=f"notAfter: {not_after}",
                    cwe="CWE-298",
                    description="The server's TLS certificate has expired.",
                    impact="Clients receive security warnings; MITM risk rises.",
                    remediation="Renew the certificate and automate renewal.",
                    detected_by="ssl.analysis",
                    confidence="Certain",
                )
            elif summary["days_remaining"] < 15:
                ctx.add_finding(
                    title="TLS certificate expiring soon",
                    severity=Severity.LOW,
                    affected_url=ctx.scan.target_url,
                    evidence=f"{summary['days_remaining']} days remaining",
                    cwe="CWE-298",
                    description="The TLS certificate will expire shortly.",
                    impact="Imminent outage / trust warnings if not renewed.",
                    remediation="Renew the certificate before expiry.",
                    detected_by="ssl.analysis",
                    confidence="Certain",
                )
        except ValueError:
            pass
    return summary


def _probe_legacy_protocols(host: str, port: int) -> list[str]:
    supported = []
    for label, version in _LEGACY_PROTOCOLS.items():
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = version
            c.maximum_version = version
            with socket.create_connection((host, port), timeout=6) as sock:
                with c.wrap_socket(sock, server_hostname=host):
                    supported.append(label)
        except Exception:
            continue
    return supported
