"""
Wrappers for optional external analysis tools.

Both wrappers degrade gracefully — if the tool is not installed the scanner
continues with pure-Python analysis only.

Recommended free tools:
  ExifTool  https://exiftool.org/  (single .exe for Windows)
  binwalk   pip install binwalk    (or system package on Linux/macOS)
"""

from __future__ import annotations

import shutil
import subprocess
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class ExifToolWrapper:
    """Calls Phil Harvey's ExifTool if it is present on PATH."""

    _cmd: str = ""  # cached executable path

    @classmethod
    def is_available(cls) -> bool:
        """Return True if exiftool is found on the system PATH."""
        if not cls._cmd:
            cls._cmd = (
                shutil.which("exiftool")
                or shutil.which("exiftool.exe")
                or ""
            )
        return bool(cls._cmd)

    @classmethod
    def run(cls, path: Path) -> list[str]:
        """Return a list of ``'Tag : Value'`` strings from ExifTool.

        Returns an empty list if ExifTool is unavailable or fails.
        """
        if not cls.is_available():
            return []
        try:
            result = subprocess.run(
                [cls._cmd, str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return [
                line.strip()
                for line in result.stdout.splitlines()
                if ":" in line
            ]
        except Exception as exc:
            log.debug("ExifTool failed on %s: %s", path, exc)
            return []


class BinwalkWrapper:
    """Calls binwalk to detect embedded files and compression signatures."""

    _cmd: str = ""

    @classmethod
    def is_available(cls) -> bool:
        """Return True if binwalk is found on the system PATH."""
        if not cls._cmd:
            cls._cmd = shutil.which("binwalk") or ""
        return bool(cls._cmd)

    @classmethod
    def run(cls, path: Path) -> list[str]:
        """Return binwalk scan lines (header and separator lines stripped).

        Returns an empty list if binwalk is unavailable or fails.
        """
        if not cls.is_available():
            return []
        try:
            result = subprocess.run(
                [cls._cmd, "--quiet", str(path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            lines = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip()
            ]
            # Skip the DECIMAL/HEXADECIMAL header and dashed separator
            return [
                line
                for line in lines
                if not line.startswith(("DECIMAL", "---"))
            ]
        except Exception as exc:
            log.debug("binwalk failed on %s: %s", path, exc)
            return []
