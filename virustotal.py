"""
core/virustotal.py
───────────────────
VirusTotal Public API v3 wrapper.

Covers
------
  check_hash(hash)     →  MD5 / SHA-1 / SHA-256 file reputation
  check_domain(domain) →  Domain reputation
  check_ip(ip)         →  IP-address reputation
  check_url(url)       →  URL reputation (submits + polls if new)

All methods return a unified ParsedResult dict.
Free-tier rate limit (4 req/min) is handled transparently.
"""
import base64
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from config.settings import VIRUSTOTAL_API_KEY, VT_REQUEST_DELAY
from core.ioc_detector import IOCType


# ── Custom exceptions ─────────────────────────────────────────────────────────

class VTError(Exception):
    """Raised when the VirusTotal API returns an error."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


class VTAuthError(VTError):
    def __init__(self):
        super().__init__("Invalid or missing VirusTotal API key.", 401)


class VTNotFoundError(VTError):
    def __init__(self, query: str):
        super().__init__(f"'{query}' not found in VirusTotal database.", 404)


class VTRateLimitError(VTError):
    def __init__(self):
        super().__init__("VirusTotal rate limit reached. Please wait.", 429)


# ── Result container ──────────────────────────────────────────────────────────

@dataclass
class ParsedResult:
    """Structured, interface-ready result from a VT lookup."""
    ioc_type:    IOCType
    query:       str
    verdict:     str                          # MALICIOUS | SUSPICIOUS | CLEAN | UNKNOWN
    malicious:   int   = 0
    suspicious:  int   = 0
    undetected:  int   = 0
    harmless:    int   = 0
    total:       int   = 0
    detections:  list  = field(default_factory=list)   # [{engine, result, category}]
    tags:        list  = field(default_factory=list)
    reputation:  int   = 0
    extra:       dict  = field(default_factory=dict)   # type-specific fields
    raw:         dict  = field(default_factory=dict)   # full VT response

    def to_dict(self) -> dict:
        return {
            "ioc_type":   self.ioc_type.value,
            "query":      self.query,
            "verdict":    self.verdict,
            "stats": {
                "malicious":  self.malicious,
                "suspicious": self.suspicious,
                "undetected": self.undetected,
                "harmless":   self.harmless,
                "total":      self.total,
            },
            "detections":  self.detections,
            "tags":        self.tags,
            "reputation":  self.reputation,
            "extra":       self.extra,
        }


# ── API client ────────────────────────────────────────────────────────────────

class VirusTotalAPI:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = VIRUSTOTAL_API_KEY):
        if not api_key:
            raise VTAuthError()
        self._headers = {"x-apikey": api_key, "Accept": "application/json"}
        self._last_call: float = 0.0

    # ── Rate-limit throttle ───────────────────────────────────────────────────

    def _wait(self) -> None:
        elapsed = time.time() - self._last_call
        if elapsed < VT_REQUEST_DELAY:
            time.sleep(VT_REQUEST_DELAY - elapsed)
        self._last_call = time.time()

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str) -> dict:
        self._wait()
        r = requests.get(f"{self.BASE}/{path}",
                         headers=self._headers, timeout=30)
        self._raise_for_status(r)
        return r.json()

    def _post(self, path: str, data: dict) -> dict:
        self._wait()
        r = requests.post(f"{self.BASE}/{path}",
                          headers=self._headers, data=data, timeout=30)
        self._raise_for_status(r)
        return r.json()

    @staticmethod
    def _raise_for_status(r: requests.Response) -> None:
        if r.status_code == 200:
            return
        if r.status_code == 401:
            raise VTAuthError()
        if r.status_code == 404:
            raise VTNotFoundError("requested resource")
        if r.status_code == 429:
            raise VTRateLimitError()
        try:
            msg = r.json().get("error", {}).get("message", r.text)
        except Exception:
            msg = r.text
        raise VTError(f"VT API error {r.status_code}: {msg}", r.status_code)

    # ── Public lookup methods ─────────────────────────────────────────────────

    def check_hash(self, file_hash: str) -> ParsedResult:
        """File / hash reputation."""
        try:
            raw = self._get(f"files/{file_hash}")
        except VTNotFoundError:
            raise VTNotFoundError(file_hash)
        return self._parse(raw, IOCType.SHA256 if len(file_hash) == 64
                           else IOCType.SHA1 if len(file_hash) == 40
                           else IOCType.MD5, file_hash)

    def check_domain(self, domain: str) -> ParsedResult:
        """Domain reputation."""
        try:
            raw = self._get(f"domains/{domain}")
        except VTNotFoundError:
            raise VTNotFoundError(domain)
        return self._parse(raw, IOCType.DOMAIN, domain)

    def check_ip(self, ip: str) -> ParsedResult:
        """IP address reputation."""
        try:
            raw = self._get(f"ip_addresses/{ip}")
        except VTNotFoundError:
            raise VTNotFoundError(ip)
        return self._parse(raw, IOCType.IP, ip)

    def check_url(self, url: str) -> ParsedResult:
        """
        URL reputation.
        Tries a cached lookup first; if not found, submits the URL
        and retrieves the analysis result.
        """
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            raw = self._get(f"urls/{url_id}")
            return self._parse(raw, IOCType.URL, url)
        except VTNotFoundError:
            pass  # URL not in cache — submit it

        # Submit URL for scanning
        submitted = self._post("urls", {"url": url})
        analysis_id = submitted.get("data", {}).get("id", "")
        if not analysis_id:
            raise VTError("URL submission failed — no analysis ID returned.")

        # Poll for result (up to 3 attempts)
        for attempt in range(3):
            time.sleep(5 + attempt * 5)
            try:
                analysis = self._get(f"analyses/{analysis_id}")
                status = (analysis.get("data", {})
                                  .get("attributes", {})
                                  .get("status", ""))
                if status == "completed":
                    # Fetch the full URL report now that it exists
                    raw = self._get(f"urls/{url_id}")
                    return self._parse(raw, IOCType.URL, url)
            except Exception:
                continue

        raise VTError("URL analysis timed out. Try again in a moment.")

    # ── Result parser ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse(raw: dict, ioc_type: IOCType, query: str) -> ParsedResult:
        attrs = raw.get("data", {}).get("attributes", {})
        s     = attrs.get("last_analysis_stats", {})

        malicious  = s.get("malicious",  0)
        suspicious = s.get("suspicious", 0)
        undetected = s.get("undetected", 0)
        harmless   = s.get("harmless",   0)
        total      = malicious + suspicious + undetected + harmless

        if malicious > 0:
            verdict = "MALICIOUS"
        elif suspicious > 0:
            verdict = "SUSPICIOUS"
        elif total > 0:
            verdict = "CLEAN"
        else:
            verdict = "UNKNOWN"

        # Top detections (malicious + suspicious engines only)
        detections = [
            {
                "engine":   engine,
                "result":   detail.get("result") or "—",
                "category": detail.get("category", ""),
            }
            for engine, detail in attrs.get("last_analysis_results", {}).items()
            if detail.get("category") in ("malicious", "suspicious")
        ][:15]

        # Type-specific extra fields
        extra: dict[str, Any] = {}
        if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            extra = {
                "name":     attrs.get("meaningful_name") or attrs.get("name", "—"),
                "size":     attrs.get("size", 0),
                "type":     attrs.get("type_description", "—"),
                "md5":      attrs.get("md5", ""),
                "sha1":     attrs.get("sha1", ""),
                "sha256":   attrs.get("sha256", ""),
                "magic":    attrs.get("magic", ""),
                "first_submission": attrs.get("first_submission_date", ""),
                "times_submitted":  attrs.get("times_submitted", 0),
            }
        elif ioc_type == IOCType.DOMAIN:
            extra = {
                "registrar":     attrs.get("registrar", "—"),
                "creation_date": attrs.get("creation_date", ""),
                "categories":    attrs.get("categories", {}),
                "country":       attrs.get("country", "—"),
                "whois":         attrs.get("whois", "")[:500],
            }
        elif ioc_type == IOCType.IP:
            extra = {
                "country":  attrs.get("country", "—"),
                "asn":      attrs.get("asn", "—"),
                "as_owner": attrs.get("as_owner", "—"),
                "network":  attrs.get("network", "—"),
                "continent": attrs.get("continent", "—"),
            }
        elif ioc_type == IOCType.URL:
            extra = {
                "final_url":   attrs.get("last_final_url", query),
                "title":       attrs.get("title", "—"),
                "status_code": attrs.get("last_http_response_code", "—"),
                "categories":  attrs.get("categories", {}),
            }

        return ParsedResult(
            ioc_type   = ioc_type,
            query      = query,
            verdict    = verdict,
            malicious  = malicious,
            suspicious = suspicious,
            undetected = undetected,
            harmless   = harmless,
            total      = total,
            detections = detections,
            tags       = attrs.get("tags", []),
            reputation = attrs.get("reputation", 0),
            extra      = extra,
            raw        = raw,
        )
