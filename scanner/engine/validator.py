"""Target validation and normalisation."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


@dataclass
class ValidationResult:
    ok: bool
    url: str = ""
    hostname: str = ""
    reason: str = ""


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return ""
    # Drop fragments; keep path/query.
    return urlunparse((scheme, parsed.netloc, parsed.path or "/", parsed.params,
                       parsed.query, ""))


def validate_target(raw: str) -> ValidationResult:
    """Normalise and sanity-check a target, and confirm DNS resolves.

    Rejects empty/malformed input and unresolvable hosts. Loopback and private
    addresses are allowed (local lab testing) but flagged by the caller.
    """
    url = normalize_url(raw)
    if not url:
        return ValidationResult(False, reason="Enter a valid http(s) URL or hostname.")
    host = urlparse(url).hostname or ""
    if not host:
        return ValidationResult(False, reason="Could not determine hostname from URL.")
    # If it's an IP literal, it's already 'resolved'.
    try:
        ipaddress.ip_address(host)
        return ValidationResult(True, url=url, hostname=host)
    except ValueError:
        pass
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return ValidationResult(False, url=url, hostname=host,
                                reason=f"DNS resolution failed for '{host}'.")
    return ValidationResult(True, url=url, hostname=host)


def is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except (socket.gaierror, ValueError):
            return False
