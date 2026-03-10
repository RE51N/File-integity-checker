"""Tests for src/magic.py — file-type identification from magic bytes."""

from __future__ import annotations

import pytest

from src.magic import identify, is_high_risk


# ─── Identification tests ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "data, expected_desc_fragment, expected_category",
    [
        # Archives
        (b"PK\x03\x04" + b"\x00" * 10,        "ZIP",          "archive"),
        (b"Rar!\x1a\x07\x00" + b"\x00" * 4,   "RAR",          "archive"),
        (b"7z\xbc\xaf\x27\x1c",                "7-Zip",        "archive"),
        (b"\x1f\x8b\x08",                       "Gzip",         "archive"),
        (b"BZh9",                                "Bzip2",        "archive"),
        (b"\xfd7zXZ\x00",                        "XZ",           "archive"),
        # Executables
        (b"MZ" + b"\x00" * 10,                  "Windows PE",   "executable"),
        (b"\x7fELF" + b"\x00" * 8,              "ELF",          "executable"),
        (b"#!" + b"/bin/bash",                   "shebang",      "executable"),
        # Images
        (b"\xff\xd8\xff\xe0",                    "JPEG",         "image"),
        (b"\x89PNG\r\n\x1a\n",                   "PNG",          "image"),
        (b"GIF89a",                               "GIF",          "image"),
        (b"GIF87a",                               "GIF",          "image"),
        (b"BM\x36\x00\x00\x00",                  "BMP",          "image"),
        # Documents
        (b"%PDF-1.7",                             "PDF",          "document"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",   "OLE",          "document"),
        # Crypto / keys
        (b"-----BEGIN PRIVATE KEY-----",          "PEM",          "crypto"),
        (b"-----BEGIN RSA PRIVATE KEY-----",      "PEM",          "crypto"),
        # Databases
        (b"SQLite format 3\x00",                  "SQLite",       "database"),
        # Media
        (b"ID3\x03\x00",                          "MP3",          "media"),
        (b"OggS",                                  "OGG",          "media"),
        (b"fLaC",                                  "FLAC",         "media"),
    ],
)
def test_identify_known_types(
    data: bytes,
    expected_desc_fragment: str,
    expected_category: str,
) -> None:
    desc, cat = identify(data)
    assert expected_desc_fragment.lower() in desc.lower(), (
        f"Expected '{expected_desc_fragment}' in description '{desc}'"
    )
    assert cat == expected_category


def test_identify_riff_webp() -> None:
    data = b"RIFF\x20\x00\x00\x00WEBP" + b"\x00" * 20
    desc, cat = identify(data)
    assert "webp" in desc.lower()
    assert cat == "image"


def test_identify_riff_wav() -> None:
    data = b"RIFF\x20\x00\x00\x00WAVE" + b"\x00" * 20
    desc, cat = identify(data)
    assert "wav" in desc.lower()
    assert cat == "media"


def test_identify_plain_text() -> None:
    data = b"Hello, world! This is a plain text message.\n"
    desc, cat = identify(data)
    assert cat == "text"
    assert "text" in desc.lower()


def test_identify_empty_data() -> None:
    desc, cat = identify(b"")
    assert cat == "unknown"


def test_identify_random_binary() -> None:
    # Random-looking binary data that matches nothing
    data = bytes(range(256))
    desc, cat = identify(data)
    # Should either be unknown or text; definitely not a known format
    assert cat in ("unknown", "text")


# ─── High-risk category tests ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "category, expected",
    [
        ("executable", True),
        ("crypto",     True),
        ("database",   True),
        ("disk",       True),
        ("archive",    False),
        ("image",      False),
        ("media",      False),
        ("text",       False),
        ("unknown",    False),
    ],
)
def test_is_high_risk(category: str, expected: bool) -> None:
    assert is_high_risk(category) is expected
