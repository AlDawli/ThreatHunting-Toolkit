"""
core/ioc_detector.py
─────────────────────
Auto-detects the type of an IOC (Indicator of Compromise)
from its string value using regex matching.

Supported types: IP, MD5, SHA1, SHA256, Domain, URL, Email
"""
import re
from enum import Enum


class IOCType(str, Enum):
    IP      = "ip"
    MD5     = "md5"
    SHA1    = "sha1"
    SHA256  = "sha256"
    DOMAIN  = "domain"
    URL     = "url"
    EMAIL   = "email"
    UNKNOWN = "unknown"


# ── Compiled patterns (order matters — more specific first) ───────────────────
_PATTERNS: list[tuple[IOCType, re.Pattern]] = [
    # URL — must precede domain check
    (IOCType.URL,    re.compile(r'^https?://', re.IGNORECASE)),

    # Email — must precede domain check
    (IOCType.EMAIL,  re.compile(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    )),

    # Hashes — matched by exact hex length
    (IOCType.SHA256, re.compile(r'^[a-fA-F0-9]{64}$')),
    (IOCType.SHA1,   re.compile(r'^[a-fA-F0-9]{40}$')),
    (IOCType.MD5,    re.compile(r'^[a-fA-F0-9]{32}$')),

    # IPv4 (validated further below)
    (IOCType.IP,     re.compile(
        r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    )),

    # Domain
    (IOCType.DOMAIN, re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )),
]


def detect_ioc_type(value: str) -> IOCType:
    """Return the IOCType that best matches *value*, or IOCType.UNKNOWN."""
    value = value.strip()
    if not value:
        return IOCType.UNKNOWN

    for ioc_type, pattern in _PATTERNS:
        m = pattern.match(value)
        if not m:
            continue

        # Extra validation for IPv4 octets
        if ioc_type == IOCType.IP:
            if all(0 <= int(g) <= 255 for g in m.groups()):
                return IOCType.IP
            continue  # Looks like IP but invalid octets → try domain

        return ioc_type

    return IOCType.UNKNOWN


def is_hash(ioc_type: IOCType) -> bool:
    return ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)


def friendly_name(ioc_type: IOCType) -> str:
    """Human-readable label for display."""
    return {
        IOCType.IP:      "IP Address",
        IOCType.MD5:     "MD5 Hash",
        IOCType.SHA1:    "SHA-1 Hash",
        IOCType.SHA256:  "SHA-256 Hash",
        IOCType.DOMAIN:  "Domain",
        IOCType.URL:     "URL",
        IOCType.EMAIL:   "Email",
        IOCType.UNKNOWN: "Unknown",
    }[ioc_type]
