"""
File-type identification from magic bytes (file signatures).

Used to determine *what* has been appended to an image file.
"""

from __future__ import annotations

# Each entry: (byte_offset, signature_bytes, human_description, category)
# category is one of: archive, executable, image, document, media,
#                     database, crypto, code, disk, text, unknown
_SIGNATURES: list[tuple[int, bytes, str, str]] = [
    # ── Archives ──────────────────────────────────────────────────────────────
    (0,   b"PK\x03\x04",                    "ZIP archive",                  "archive"),
    (0,   b"PK\x05\x06",                    "ZIP archive (empty)",           "archive"),
    (0,   b"Rar!\x1a\x07\x00",              "RAR archive (v1.5+)",           "archive"),
    (0,   b"Rar!\x1a\x07\x01\x00",          "RAR archive (v5+)",             "archive"),
    (0,   b"7z\xbc\xaf\x27\x1c",            "7-Zip archive",                 "archive"),
    (0,   b"\x1f\x8b",                       "Gzip compressed data",          "archive"),
    (0,   b"BZh",                             "Bzip2 compressed data",         "archive"),
    (0,   b"\xfd7zXZ\x00",                   "XZ compressed data",            "archive"),
    (257, b"ustar",                           "TAR archive",                   "archive"),
    (0,   b"\x04\x22\x4d\x18",               "LZ4 frame",                     "archive"),
    (0,   b"\x28\xb5\x2f\xfd",               "Zstandard compressed data",     "archive"),
    (0,   b"MSCF",                            "Microsoft Cabinet (.cab)",      "archive"),
    # ── Executables ───────────────────────────────────────────────────────────
    (0,   b"MZ",                              "Windows PE executable/DLL",     "executable"),
    (0,   b"\x7fELF",                         "Linux ELF executable",          "executable"),
    (0,   b"\xca\xfe\xba\xbe",               "Mach-O / Java class file",      "executable"),
    (0,   b"\xfe\xed\xfa\xce",               "Mach-O 32-bit (LE)",            "executable"),
    (0,   b"\xfe\xed\xfa\xcf",               "Mach-O 64-bit (LE)",            "executable"),
    (0,   b"\xce\xfa\xed\xfe",               "Mach-O 32-bit (BE)",            "executable"),
    (0,   b"\xcf\xfa\xed\xfe",               "Mach-O 64-bit (BE)",            "executable"),
    (0,   b"#!",                               "Script with shebang line",     "executable"),
    # ── Images ────────────────────────────────────────────────────────────────
    (0,   b"\xff\xd8\xff",                    "JPEG image",                    "image"),
    (0,   b"\x89PNG\r\n\x1a\n",              "PNG image",                     "image"),
    (0,   b"GIF87a",                           "GIF image (87a)",               "image"),
    (0,   b"GIF89a",                           "GIF image (89a)",               "image"),
    (0,   b"BM",                               "BMP image",                     "image"),
    (0,   b"II*\x00",                          "TIFF image (little-endian)",    "image"),
    (0,   b"MM\x00*",                          "TIFF image (big-endian)",       "image"),
    (0,   b"\x00\x00\x01\x00",                "Windows ICO icon",              "image"),
    # RIFF-based formats (WebP, WAV, AVI) detected below via subtype
    # ── Documents ─────────────────────────────────────────────────────────────
    (0,   b"%PDF",                             "PDF document",                  "document"),
    (0,   b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS Office legacy (OLE)",     "document"),
    (0,   b"{\x5c rtf",                        "RTF document",                  "document"),
    (0,   b"<?xml",                             "XML document",                  "document"),
    (0,   b"<html",                             "HTML document",                 "document"),
    (0,   b"<!DOCTYPE",                         "HTML document",                 "document"),
    # ── Media ─────────────────────────────────────────────────────────────────
    (0,   b"ID3",                               "MP3 audio (ID3 tag)",           "media"),
    (0,   b"\xff\xfb",                          "MP3 audio frame",               "media"),
    (0,   b"\xff\xf3",                          "MP3 audio frame",               "media"),
    (0,   b"\xff\xf2",                          "MP3 audio frame",               "media"),
    (0,   b"OggS",                              "OGG container",                 "media"),
    (0,   b"fLaC",                              "FLAC audio",                    "media"),
    (0,   b"\x1aE\xdf\xa3",                    "Matroska / WebM video",         "media"),
    (4,   b"ftyp",                              "MP4 / MOV / M4A video",         "media"),
    # ── Databases ─────────────────────────────────────────────────────────────
    (0,   b"SQLite format 3\x00",              "SQLite database",               "database"),
    # ── Crypto / Keys ─────────────────────────────────────────────────────────
    (0,   b"-----BEGIN ",                       "PEM-encoded key or certificate","crypto"),
    (0,   b"\x30\x82",                          "DER-encoded certificate or key","crypto"),
    # ── Disk images ───────────────────────────────────────────────────────────
    (0,   b"KDMV",                              "VMware VMDK disk image",        "disk"),
    (0,   b"conectix",                          "VHD virtual disk image",        "disk"),
    # ── Code / bytecode ───────────────────────────────────────────────────────
    (0,   b"\x1b\x4c\x75\x61",                 "Lua bytecode",                  "code"),
    # ── ISO 9660 disc image ───────────────────────────────────────────────────
    # Primary Volume Descriptor magic at sector 16 (offset 32768 + 1)
    (32769, b"CD001",                           "ISO 9660 disc image",           "disk"),
]

# RIFF sub-type lookup (bytes 8–12 of the file)
_RIFF_SUBTYPES: dict[bytes, tuple[str, str]] = {
    b"WEBP": ("WebP image",  "image"),
    b"AVI ": ("AVI video",   "media"),
    b"WAVE": ("WAV audio",   "media"),
}

# Categories considered high-risk when found appended to an image
_HIGH_RISK_CATEGORIES: frozenset[str] = frozenset(
    {"executable", "crypto", "database", "disk"}
)


def identify(data: bytes) -> tuple[str, str]:
    """Identify a block of bytes from its magic signature.

    Returns a ``(description, category)`` tuple.  ``category`` is one of:
    ``archive``, ``executable``, ``image``, ``document``, ``media``,
    ``database``, ``crypto``, ``code``, ``disk``, ``text``, or ``unknown``.
    """
    if not data:
        return ("Empty data", "unknown")

    # RIFF sub-type detection
    if data[:4] == b"RIFF" and len(data) >= 12:
        sub = data[8:12]
        if sub in _RIFF_SUBTYPES:
            return _RIFF_SUBTYPES[sub]

    for offset, sig, description, category in _SIGNATURES:
        end = offset + len(sig)
        if len(data) >= end and data[offset:end] == sig:
            return (description, category)

    # Heuristic: is it mostly printable ASCII?
    sample = data[:512]
    if sample:
        printable = sum(
            1 for b in sample if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D)
        )
        if printable / len(sample) > 0.80:
            return ("Plain text data", "text")

    return ("Unknown binary data", "unknown")


def is_high_risk(category: str) -> bool:
    """Return True if *category* is considered high-risk when appended to an image."""
    return category in _HIGH_RISK_CATEGORIES
