"""
Image format end-of-data detection.

Each supported format has a known end marker or header-declared size.
Bytes found *after* that boundary are considered appended (foreign) data.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional

# File extensions this scanner understands
SUPPORTED_EXTENSIONS: frozenset[str] = frozenset(
    {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
)


def find_data_end(path: Path) -> Optional[int]:
    """Return the byte offset immediately after the image's legitimate data.

    Any bytes at or beyond this offset are *appended* and not part of the
    image format.  Returns ``None`` if the format is unsupported or the file
    cannot be parsed.
    """
    suffix = path.suffix.lower()
    try:
        data = path.read_bytes()
    except OSError:
        return None

    handlers = {
        ".jpg": _jpeg_end,
        ".jpeg": _jpeg_end,
        ".png": _png_end,
        ".gif": _gif_end,
        ".bmp": _bmp_end,
        ".webp": _webp_end,
    }
    handler = handlers.get(suffix)
    return handler(data) if handler else None


# ─── Format-specific parsers ──────────────────────────────────────────────────


def _jpeg_end(data: bytes) -> Optional[int]:
    """JPEG ends with the FF D9 End-of-Image marker.

    We use the *rightmost* occurrence because some corrupt or edited files
    contain duplicate markers mid-stream.
    """
    pos = data.rfind(b"\xff\xd9")
    return (pos + 2) if pos != -1 else None


def _png_end(data: bytes) -> Optional[int]:
    """PNG ends with the IEND chunk.

    The IEND chunk is always: length(4)=0x00000000 + "IEND" + CRC(4)=0xAE426082
    Total: 12 bytes with a fixed pattern.
    """
    marker = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    pos = data.find(marker)
    return (pos + len(marker)) if pos != -1 else None


def _gif_end(data: bytes) -> Optional[int]:
    """GIF ends with a single 0x3B (semicolon) trailer byte."""
    pos = data.rfind(b"\x3b")
    return (pos + 1) if pos != -1 else None


def _bmp_end(data: bytes) -> Optional[int]:
    """BMP stores its intended file size as a LE uint32 at bytes 2–5."""
    if len(data) < 6:
        return None
    stated: int = struct.unpack_from("<I", data, 2)[0]
    return stated


def _webp_end(data: bytes) -> Optional[int]:
    """WebP is RIFF-based: 'RIFF' + 4-byte LE payload size + 'WEBP'.

    Total legitimate file size = 8 + payload_size.
    """
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    payload_size: int = struct.unpack_from("<I", data, 4)[0]
    return 8 + payload_size
