"""
EXIF, comment, and embedded-text metadata extraction.

Reads metadata via Pillow (pure-Python, no external tools required).
Flags values that look suspicious: embedded URLs, base64 blobs,
sensitive keywords, or unusually long strings.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

try:
    from PIL import Image
    from PIL.ExifTags import TAGS

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    log.warning("Pillow not installed — metadata extraction disabled. Run: pip install Pillow")

# ─── Suspicious-content patterns ─────────────────────────────────────────────

_SENSITIVE_RE = re.compile(
    r"\b(password|passwd|pass|secret|token|apikey|api[_-]key|private|auth|credential|key)\b",
    re.IGNORECASE,
)
# Base64: 40+ consecutive valid chars followed by optional padding
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_URL_RE = re.compile(r"https?://\S+|ftp://\S+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# EXIF tags worth always reporting even if not suspicious
_NOTABLE_TAGS = frozenset(
    {
        "Comment", "UserComment", "ImageDescription", "Artist",
        "Copyright", "Software", "Make", "Model", "GPSInfo",
        "XPComment", "XPAuthor", "XPKeywords", "XPSubject", "XPTitle",
    }
)


@dataclass
class MetadataField:
    """A single metadata key/value pair with optional suspicion flag."""

    tag: str
    value: str
    is_suspicious: bool = False
    reason: str = ""


def extract(path: Path) -> list[MetadataField]:
    """Extract all available metadata fields from *path*.

    Returns an empty list if Pillow is not installed or the file cannot
    be opened.
    """
    if not PIL_AVAILABLE:
        return []

    fields: list[MetadataField] = []

    try:
        img = Image.open(path)
    except Exception as exc:
        log.debug("Pillow cannot open %s: %s", path, exc)
        return []

    # ── EXIF / IFD data ───────────────────────────────────────────────────────
    try:
        exif_raw = img._getexif()  # type: ignore[attr-defined]
        if exif_raw:
            for tag_id, value in exif_raw.items():
                tag_name = TAGS.get(tag_id, f"EXIF:{tag_id}")
                fields.append(_make_field(str(tag_name), _to_str(value)))
    except (AttributeError, Exception):
        pass  # Not a JPEG or no EXIF

    # ── PNG tEXt / zTXt / iTXt chunks ────────────────────────────────────────
    if hasattr(img, "text") and img.text:
        for key, value in img.text.items():
            fields.append(_make_field(f"PNG:{key}", str(value)))

    # ── Generic info dict (works for GIF, BMP, WebP, etc.) ───────────────────
    _skip = {"exif", "icc_profile", "photoshop", "thumbnail"}  # binary blobs
    for key, value in (img.info or {}).items():
        if str(key).lower() in _skip:
            continue
        if isinstance(value, (str, int, float)):
            fields.append(_make_field(f"Info:{key}", str(value)))

    img.close()
    return fields


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_field(tag: str, value: str) -> MetadataField:
    """Analyse a metadata field value and return a MetadataField."""
    reasons: list[str] = []

    if _SENSITIVE_RE.search(value):
        reasons.append("sensitive keyword")
    if _BASE64_RE.search(value):
        reasons.append("base64-like content")
    if _URL_RE.search(value):
        reasons.append("embedded URL")
    if _IP_RE.search(value):
        reasons.append("IP address")
    if len(value) > 500:
        reasons.append("unusually long value")

    return MetadataField(
        tag=tag,
        value=value,
        is_suspicious=bool(reasons),
        reason=", ".join(reasons),
    )


def _to_str(value: object) -> str:
    """Convert an arbitrary EXIF value to a readable string."""
    if isinstance(value, bytes):
        # Strip null-byte prefix common in UserComment
        cleaned = value.lstrip(b"\x00").lstrip(b"ASCII\x00\x00\x00")
        try:
            return cleaned.decode("utf-8", errors="replace").strip()
        except Exception:
            return value.hex()
    if isinstance(value, tuple):
        return str(value)
    return str(value)
