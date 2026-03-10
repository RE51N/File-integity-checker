"""Tests for src/formats.py — image end-of-data detection."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from src.formats import find_data_end, SUPPORTED_EXTENSIONS

# ─── Minimal valid image bytes ────────────────────────────────────────────────

# A 1×1 red JPEG (hand-crafted minimal file)
_JPEG_BYTES = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xd9"
)

# Minimal PNG: signature + IHDR (1×1 px) + IDAT + IEND
_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"                          # PNG signature (8 bytes)
    b"\x00\x00\x00\rIHDR"                         # IHDR chunk length + type
    b"\x00\x00\x00\x01\x00\x00\x00\x01"           # width=1, height=1
    b"\x08\x02\x00\x00\x00"                        # bit depth, colour type, …
    b"\x90wS\xde"                                  # CRC
    b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"             # IEND chunk (12 bytes)
)

# Minimal GIF89a (1×1 pixel, single colour)
_GIF_BYTES = (
    b"GIF89a\x01\x00\x01\x00\x00\x00\x00"
    b"!\xf9\x04\x00\x00\x00\x00\x00"
    b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00"
    b"\x3b"  # GIF trailer
)

# BMP file header for a 1×1 image (54-byte header + 4 bytes pixel data = 58)
_BMP_SIZE = 58
_BMP_BYTES = (
    b"BM"
    + struct.pack("<I", _BMP_SIZE)  # file size
    + b"\x00\x00\x00\x00"           # reserved
    + struct.pack("<I", 54)         # pixel data offset
    + b"\x28\x00\x00\x00"          # BITMAPINFOHEADER size (40)
    + b"\x01\x00\x00\x00"          # width = 1
    + b"\x01\x00\x00\x00"          # height = 1
    + b"\x01\x00"                   # colour planes = 1
    + b"\x18\x00"                   # bits per pixel = 24
    + b"\x00" * 24                  # rest of header
    + b"\xff\x00\x00\x00"          # pixel data (1 pixel, padded)
)

# WebP: RIFF header + WEBP marker + minimal VP8 chunk
_WEBP_PAYLOAD = b"WEBP" + b"VP8 " + b"\x08\x00\x00\x00" + b"\x00" * 8
_WEBP_BYTES = b"RIFF" + struct.pack("<I", len(_WEBP_PAYLOAD)) + _WEBP_PAYLOAD

_JUNK = b"EXTRA_HIDDEN_DATA"


# ─── Helpers ──────────────────────────────────────────────────────────────────


def write_image(tmp_path: Path, name: str, data: bytes, extra: bytes = b"") -> Path:
    p = tmp_path / name
    p.write_bytes(data + extra)
    return p


# ─── Tests: JPEG ─────────────────────────────────────────────────────────────


def test_jpeg_clean_returns_end_of_file(tmp_path: Path) -> None:
    p = write_image(tmp_path, "clean.jpg", _JPEG_BYTES)
    assert find_data_end(p) == len(_JPEG_BYTES)


def test_jpeg_with_appended_data_detects_boundary(tmp_path: Path) -> None:
    p = write_image(tmp_path, "dirty.jpg", _JPEG_BYTES, _JUNK)
    end = find_data_end(p)
    assert end == len(_JPEG_BYTES)
    content = p.read_bytes()
    assert content[end:] == _JUNK


# ─── Tests: PNG ──────────────────────────────────────────────────────────────


def test_png_clean_returns_end_of_file(tmp_path: Path) -> None:
    p = write_image(tmp_path, "clean.png", _PNG_BYTES)
    assert find_data_end(p) == len(_PNG_BYTES)


def test_png_with_appended_data_detects_boundary(tmp_path: Path) -> None:
    p = write_image(tmp_path, "dirty.png", _PNG_BYTES, _JUNK)
    end = find_data_end(p)
    assert end == len(_PNG_BYTES)
    assert p.read_bytes()[end:] == _JUNK


# ─── Tests: GIF ──────────────────────────────────────────────────────────────


def test_gif_clean_returns_end_of_file(tmp_path: Path) -> None:
    p = write_image(tmp_path, "clean.gif", _GIF_BYTES)
    assert find_data_end(p) == len(_GIF_BYTES)


def test_gif_with_appended_data_detects_boundary(tmp_path: Path) -> None:
    p = write_image(tmp_path, "dirty.gif", _GIF_BYTES, _JUNK)
    end = find_data_end(p)
    assert end == len(_GIF_BYTES)
    assert p.read_bytes()[end:] == _JUNK


# ─── Tests: BMP ──────────────────────────────────────────────────────────────


def test_bmp_clean_returns_stated_size(tmp_path: Path) -> None:
    p = write_image(tmp_path, "clean.bmp", _BMP_BYTES)
    assert find_data_end(p) == _BMP_SIZE


def test_bmp_with_appended_data_detects_boundary(tmp_path: Path) -> None:
    p = write_image(tmp_path, "dirty.bmp", _BMP_BYTES, _JUNK)
    end = find_data_end(p)
    assert end == _BMP_SIZE
    assert p.read_bytes()[end:] == _JUNK


# ─── Tests: WebP ─────────────────────────────────────────────────────────────


def test_webp_clean_returns_riff_size(tmp_path: Path) -> None:
    p = write_image(tmp_path, "clean.webp", _WEBP_BYTES)
    assert find_data_end(p) == len(_WEBP_BYTES)


def test_webp_with_appended_data_detects_boundary(tmp_path: Path) -> None:
    p = write_image(tmp_path, "dirty.webp", _WEBP_BYTES, _JUNK)
    end = find_data_end(p)
    assert end == len(_WEBP_BYTES)
    assert p.read_bytes()[end:] == _JUNK


# ─── Tests: unsupported format ───────────────────────────────────────────────


def test_unsupported_format_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "image.svg"
    p.write_bytes(b"<svg/>")
    assert find_data_end(p) is None


def test_nonexistent_file_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "no_such_file.jpg"
    assert find_data_end(p) is None


# ─── Tests: supported extensions set ─────────────────────────────────────────


def test_supported_extensions_contains_common_formats() -> None:
    for ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"):
        assert ext in SUPPORTED_EXTENSIONS
