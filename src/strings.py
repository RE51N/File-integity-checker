"""
Printable-string extraction and interesting-pattern detection.

Used to scan raw binary data (especially appended bytes) for human-readable
content that might indicate hidden messages, credentials, or embedded files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ─── Interesting-pattern regexes (operate on bytes) ──────────────────────────

_URL_RE = re.compile(rb"https?://[\x21-\x7e]+|ftp://[\x21-\x7e]+", re.IGNORECASE)
_EMAIL_RE = re.compile(rb"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Base64: min 40 chars to cut down on pixel-data false positives
_BASE64_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
# PEM markers
_PEM_RE = re.compile(rb"-----BEGIN [A-Z ]+-----")
# Long hex strings: 64+ hex chars = 256-bit (avoids short UUIDs)
_HEX_RE = re.compile(rb"[0-9a-fA-F]{64,}")
# Sensitive keywords
_KEYWORD_RE = re.compile(
    rb"\b(password|passwd|secret|token|apikey|api.key|private.key|auth|credential)\b",
    re.IGNORECASE,
)


@dataclass
class StringFind:
    """A single interesting string found within binary data."""

    offset: int
    value: str
    reason: str


def extract_strings(data: bytes, min_length: int = 6) -> list[str]:
    """Extract all printable ASCII runs of at least *min_length* from *data*.

    Useful for a raw dump of human-readable content embedded in binary files.
    """
    results: list[str] = []
    current: list[int] = []

    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
        else:
            if len(current) >= min_length:
                results.append(bytes(current).decode("ascii"))
            current = []

    if len(current) >= min_length:
        results.append(bytes(current).decode("ascii"))

    return results


def find_interesting(data: bytes) -> list[StringFind]:
    """Scan *data* for patterns that warrant attention.

    Returns a deduplicated list of :class:`StringFind` objects sorted by
    byte offset.
    """
    findings: list[StringFind] = []

    def _add(match: re.Match, reason: str) -> None:
        findings.append(
            StringFind(
                offset=match.start(),
                value=match.group().decode("ascii", errors="replace"),
                reason=reason,
            )
        )

    for m in _URL_RE.finditer(data):
        _add(m, "embedded URL")
    for m in _EMAIL_RE.finditer(data):
        _add(m, "email address")
    for m in _IP_RE.finditer(data):
        _add(m, "IP address")
    for m in _BASE64_RE.finditer(data):
        _add(m, "base64-like string")
    for m in _PEM_RE.finditer(data):
        _add(m, "PEM key/certificate marker")
    for m in _HEX_RE.finditer(data):
        _add(m, "long hex string (possible key or hash)")
    for m in _KEYWORD_RE.finditer(data):
        _add(m, "sensitive keyword")

    # Deduplicate by (truncated value, reason) to suppress near-identical hits
    seen: set[tuple[str, str]] = set()
    deduped: list[StringFind] = []
    for f in sorted(findings, key=lambda x: x.offset):
        key = (f.value[:80], f.reason)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped
