"""
Persistent scan-history log.

Tracks which image files have already been scanned so that repeat runs
can skip them.  Stored as a plain JSON file next to scan.py.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_LOG_PATH = Path(__file__).parent.parent / "scan_log.json"


class ScanLog:
    """JSON-backed persistent log of scan history."""

    def __init__(self, log_path: Path = DEFAULT_LOG_PATH) -> None:
        self._path = log_path
        self._data: dict[str, Any] = self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def is_scanned(self, path: Path) -> bool:
        """Return True if *path* already appears in the scan log."""
        return str(path.resolve()) in self._data.get("scans", {})

    def record(self, result: Any) -> None:  # result: ScanResult (duck-typed to avoid circular import)
        """Persist a scan result entry for *result.path*."""
        key = str(result.path.resolve())
        self._data.setdefault("scans", {})[key] = {
            "name": result.path.name,
            "sha256": result.sha256,
            "size": result.file_size,
            "level": result.scan_level.name,
            "time": result.scanned_at.isoformat(timespec="seconds"),
            "had_appended": result.appended is not None,
            "is_high_risk": result.is_high_risk,
            "findings": int(result.has_findings),
        }
        self._save()

    def get_all(self) -> list[dict]:
        """Return all recorded entries as a list of dicts (oldest first)."""
        return list(self._data.get("scans", {}).values())

    def get_stats(self) -> dict[str, int]:
        """Return aggregate counts across all scans."""
        scans = self.get_all()
        return {
            "total": len(scans),
            "with_appended": sum(1 for s in scans if s.get("had_appended")),
            "high_risk": sum(1 for s in scans if s.get("is_high_risk")),
        }

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _load(self) -> dict[str, Any]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception as exc:
                log.warning("Could not read scan log (%s); starting fresh.", exc)
        return {"version": 1, "scans": {}}

    def _save(self) -> None:
        try:
            self._path.write_text(
                json.dumps(self._data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            log.error("Cannot write scan log to %s: %s", self._path, exc)
