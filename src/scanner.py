"""
Core scanning orchestrator.

Ties together format detection, magic-byte identification, metadata
extraction, string searching, and optional external-tool output into a
single ScanResult per image file.
"""

from __future__ import annotations

import hashlib
import logging
import time
import datetime
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from . import formats, magic, metadata, strings, external

log = logging.getLogger(__name__)


# ─── Scan depth levels ────────────────────────────────────────────────────────


class ScanLevel(Enum):
    """Controls how thoroughly each image is examined."""

    QUICK = auto()
    """Fast check: metadata fields + detect whether any appended data exists."""

    STANDARD = auto()
    """Recommended: magic-byte identification of appended data + string search
    inside the appended bytes only."""

    DEEP = auto()
    """Thorough: everything in STANDARD, plus a full-file string sweep and
    output from ExifTool / binwalk if installed."""


# ─── Result data classes ──────────────────────────────────────────────────────


@dataclass
class AppendedData:
    """Describes data found beyond the image's legitimate end marker."""

    offset: int         # Byte offset where appended data begins
    size: int           # Number of appended bytes
    file_type: str      # Human-readable file type (from magic bytes)
    category: str       # Broad category (archive, executable, image, …)
    is_high_risk: bool  # True for executables, crypto keys, disk images, etc.
    preview: bytes = field(repr=False, default=b"")  # First 32 raw bytes


@dataclass
class ScanResult:
    """All findings produced by scanning a single image file."""

    path: Path
    file_size: int
    image_format: str
    sha256: str
    scan_level: ScanLevel
    scanned_at: datetime.datetime
    duration_s: float
    appended: Optional[AppendedData]
    metadata_fields: list[metadata.MetadataField]
    interesting_strings: list[strings.StringFind]
    external_lines: list[str]
    errors: list[str]

    # ── Convenience properties ────────────────────────────────────────────────

    @property
    def has_findings(self) -> bool:
        """True when the scan produced any result worth reporting."""
        return bool(
            self.appended
            or any(f.is_suspicious for f in self.metadata_fields)
            or self.interesting_strings
            or self.external_lines
        )

    @property
    def is_high_risk(self) -> bool:
        """True when a high-risk file type is appended (executable, key, etc.)."""
        return bool(self.appended and self.appended.is_high_risk)

    @property
    def suspicious_metadata(self) -> list[metadata.MetadataField]:
        """Subset of metadata_fields that were flagged as suspicious."""
        return [f for f in self.metadata_fields if f.is_suspicious]


# ─── Scanner ─────────────────────────────────────────────────────────────────


class ImageScanner:
    """Scans image files for hidden or appended data."""

    def scan(self, path: Path, level: ScanLevel) -> ScanResult:
        """Scan *path* at the given *level* and return a :class:`ScanResult`."""
        t0 = time.perf_counter()
        errors: list[str] = []
        appended_info: Optional[AppendedData] = None
        meta_fields: list[metadata.MetadataField] = []
        interesting: list[strings.StringFind] = []
        ext_lines: list[str] = []

        # ── Read file ─────────────────────────────────────────────────────────
        try:
            raw = path.read_bytes()
        except OSError as exc:
            errors.append(f"Cannot read file: {exc}")
            return self._empty_result(path, level, t0, errors)

        sha256 = hashlib.sha256(raw).hexdigest()
        image_format = path.suffix.upper().lstrip(".")

        # ── Locate end of image data ──────────────────────────────────────────
        end_offset = formats.find_data_end(path)

        if end_offset is not None and end_offset < len(raw):
            tail = raw[end_offset:]
            file_type, category = magic.identify(tail[:512])
            appended_info = AppendedData(
                offset=end_offset,
                size=len(tail),
                file_type=file_type,
                category=category,
                is_high_risk=magic.is_high_risk(category),
                preview=tail[:32],
            )
            # Search the appended bytes for interesting strings (STANDARD+)
            if level != ScanLevel.QUICK:
                interesting.extend(strings.find_interesting(tail))

        # ── Metadata extraction ───────────────────────────────────────────────
        meta_fields = metadata.extract(path)

        # ── Deep scan extras ──────────────────────────────────────────────────
        if level == ScanLevel.DEEP:
            # Search the entire file (catches hidden data inside image body)
            interesting.extend(strings.find_interesting(raw))
            # Deduplicate after merging full-file + appended results
            seen: set[tuple[str, str]] = set()
            deduped: list[strings.StringFind] = []
            for f in interesting:
                key = (f.value[:80], f.reason)
                if key not in seen:
                    seen.add(key)
                    deduped.append(f)
            interesting = deduped

            ext_lines.extend(external.ExifToolWrapper.run(path))
            ext_lines.extend(external.BinwalkWrapper.run(path))

        duration = time.perf_counter() - t0

        return ScanResult(
            path=path,
            file_size=len(raw),
            image_format=image_format,
            sha256=sha256,
            scan_level=level,
            scanned_at=datetime.datetime.now(),
            duration_s=duration,
            appended=appended_info,
            metadata_fields=meta_fields,
            interesting_strings=interesting,
            external_lines=ext_lines,
            errors=errors,
        )

    def strip_appended(self, result: ScanResult, reports_dir: Path) -> bool:
        """Remove appended data from the image file.

        The extracted bytes are saved to *reports_dir* before the original
        file is truncated, so the data is never permanently lost.

        Returns True on success, False if an error occurred.
        """
        if not result.appended:
            return False

        src = result.path
        ts = result.scanned_at.strftime("%Y%m%d_%H%M%S")
        save_path = reports_dir / f"{src.stem}_appended_{ts}.bin"

        try:
            raw = src.read_bytes()
            reports_dir.mkdir(parents=True, exist_ok=True)
            save_path.write_bytes(raw[result.appended.offset :])
            src.write_bytes(raw[: result.appended.offset])
            log.info(
                "Stripped %d bytes from %s; saved to %s",
                result.appended.size,
                src.name,
                save_path,
            )
            return True
        except OSError as exc:
            log.error("Strip failed for %s: %s", src, exc)
            return False

    @staticmethod
    def _empty_result(
        path: Path,
        level: ScanLevel,
        t0: float,
        errors: list[str],
    ) -> ScanResult:
        return ScanResult(
            path=path,
            file_size=0,
            image_format=path.suffix.upper().lstrip("."),
            sha256="",
            scan_level=level,
            scanned_at=datetime.datetime.now(),
            duration_s=time.perf_counter() - t0,
            appended=None,
            metadata_fields=[],
            interesting_strings=[],
            external_lines=[],
            errors=errors,
        )
