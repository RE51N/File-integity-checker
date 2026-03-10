"""
Console output and file-report generation.

Console output uses ANSI colours via colorama (Windows-compatible).
If colorama is not installed the output falls back to plain text.

Detailed reports are saved as UTF-8 text files under the ``reports/``
directory so you can review them later.
"""

from __future__ import annotations

from pathlib import Path

try:
    import colorama
    from colorama import Fore, Style

    colorama.init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False

from .scanner import ScanResult, ScanLevel

REPORTS_DIR = Path(__file__).parent.parent / "reports"


# ─── Colour helpers ───────────────────────────────────────────────────────────


def _c(text: str, code: str) -> str:
    return f"{code}{text}{Style.RESET_ALL}" if _COLOR else text


def _green(t: str) -> str:
    return _c(t, Fore.GREEN)


def _yellow(t: str) -> str:
    return _c(t, Fore.YELLOW)


def _red(t: str) -> str:
    return _c(t, Fore.RED)


def _cyan(t: str) -> str:
    return _c(t, Fore.CYAN)


# ─── Reporter ─────────────────────────────────────────────────────────────────


class Reporter:
    """Prints one-line console summaries and saves full text reports."""

    def __init__(self, reports_dir: Path = REPORTS_DIR) -> None:
        self.reports_dir = reports_dir

    # ── Console output ────────────────────────────────────────────────────────

    def print_result(self, result: ScanResult) -> None:
        """Print a compact summary line to stdout."""
        if result.errors:
            print(_red(f"  [ERROR] {result.errors[0]}"))
            return

        if result.is_high_risk:
            status = _red("[HIGH RISK]")
        elif result.has_findings:
            status = _yellow("[FINDINGS ]")
        else:
            status = _green("[  CLEAN  ]")

        parts: list[str] = [status]

        if result.appended:
            a = result.appended
            risk_tag = " *** HIGH RISK ***" if a.is_high_risk else ""
            parts.append(
                _yellow(f"Appended: {a.size:,} B → {a.file_type}{risk_tag}")
            )

        susp = result.suspicious_metadata
        if susp:
            parts.append(_yellow(f"{len(susp)} suspicious metadata field(s)"))

        if result.interesting_strings:
            parts.append(_yellow(f"{len(result.interesting_strings)} interesting string(s)"))

        if result.external_lines:
            parts.append(_cyan(f"External tools: {len(result.external_lines)} finding(s)"))

        print("  " + "  |  ".join(parts))

    # ── File report ───────────────────────────────────────────────────────────

    def save_report(self, result: ScanResult) -> Path:
        """Save a full text report for *result* and return the report path."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        ts = result.scanned_at.strftime("%Y%m%d_%H%M%S")
        report_path = self.reports_dir / f"{result.path.stem}_{ts}.txt"

        lines: list[str] = [
            "=" * 72,
            "  IMAGE HIDDEN DATA SCAN REPORT",
            "=" * 72,
            f"  File      : {result.path}",
            f"  Size      : {result.file_size:,} bytes",
            f"  SHA-256   : {result.sha256}",
            f"  Format    : {result.image_format}",
            f"  Scan level: {result.scan_level.name}",
            f"  Scanned   : {result.scanned_at.isoformat(timespec='seconds')}",
            f"  Duration  : {result.duration_s:.2f} s",
            "=" * 72,
        ]

        # ── Appended data ─────────────────────────────────────────────────────
        lines.append("")
        if result.appended:
            a = result.appended
            risk = "  *** HIGH RISK ***" if a.is_high_risk else ""
            lines += [
                f"[!] APPENDED DATA FOUND{risk}",
                f"    Start offset : {a.offset:,}  (0x{a.offset:08X})",
                f"    Size         : {a.size:,} bytes",
                f"    Identified as: {a.file_type}",
                f"    Category     : {a.category}",
                f"    First 32 B   : {a.preview.hex(' ')}",
            ]
        else:
            lines.append("[OK] No data found beyond the image end marker.")

        # ── Metadata ──────────────────────────────────────────────────────────
        lines += ["", "[METADATA]"]
        if result.metadata_fields:
            for f in result.metadata_fields:
                flag = "  [!]" if f.is_suspicious else "     "
                reason = f"   <- {f.reason}" if f.reason else ""
                val = f.value[:200] + ("…" if len(f.value) > 200 else "")
                lines.append(f"{flag} {f.tag}: {val}{reason}")
        else:
            lines.append("     (no readable metadata found)")

        # ── Interesting strings ───────────────────────────────────────────────
        if result.interesting_strings:
            lines += ["", "[INTERESTING STRINGS IN DATA]"]
            for sf in result.interesting_strings:
                lines.append(f"    0x{sf.offset:08X}  [{sf.reason}]")
                lines.append(f"        {sf.value[:120]}")

        # ── External tools ────────────────────────────────────────────────────
        if result.external_lines:
            lines += ["", "[EXTERNAL TOOLS OUTPUT]"]
            lines.extend(f"    {ln}" for ln in result.external_lines)

        # ── Errors ───────────────────────────────────────────────────────────
        if result.errors:
            lines += ["", "[ERRORS]"]
            lines.extend(f"    {e}" for e in result.errors)

        lines += ["", "=" * 72, ""]
        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path
