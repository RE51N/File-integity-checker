#!/usr/bin/env python3
"""
Image Hidden Data Scanner
=========================
Detects embedded files, hidden text, and suspicious content in image files.

Usage — interactive menu (no arguments):
    python scan.py

Usage — command-line:
    python scan.py --path C:\\Photos\\
    python scan.py --path photo.jpg --level deep
    python scan.py --path downloads\\ --level standard --strip
    python scan.py --path folder\\ --no-recursive --level quick

Scan levels
-----------
  quick    Fast metadata check + detect whether appended data exists.
  standard Recommended. Identifies what the appended data IS (zip, exe, …)
           and searches it for URLs, keys, base64 blobs, etc.
  deep     Everything in standard, plus a full-file string sweep and output
           from ExifTool / binwalk if either is installed.

External tools (optional, free)
--------------------------------
  ExifTool  https://exiftool.org/  — single .exe for Windows, drop anywhere
            on PATH.  Gives the most complete metadata read-out.
  binwalk   pip install binwalk    — finds embedded files inside images using
            a large signature database.
"""

from __future__ import annotations

import sys
import argparse
import logging
from pathlib import Path

# ── Import guard ──────────────────────────────────────────────────────────────

try:
    from src.scanner import ImageScanner, ScanLevel
    from src.scanlog import ScanLog
    from src.reporter import Reporter
    from src.external import ExifToolWrapper, BinwalkWrapper
except ImportError as exc:
    print(f"\n[!] Import error: {exc}")
    print("    Make sure you have installed the requirements:")
    print("        pip install -r requirements.txt\n")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────

IMAGE_EXTENSIONS: frozenset[str] = frozenset(
    {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
)

BANNER = r"""
  ___                  __  __              _
 |_ _|_ __ ___   __ _ |  \/  | ___  ___ (_) __
  | || '_ ` _ \ / _` || |\/| |/ _ \/ __|| |/ _|
  | || | | | | | (_| || |  | |  __/\__ \| | (_
 |___|_| |_| |_|\__,_||_|  |_|\___||___/|_|\__|

  Hidden Data Scanner  v1.0
  Detect embedded files, hidden text & steganographic content
"""

_LEVEL_MAP: dict[str, ScanLevel] = {
    "1":        ScanLevel.QUICK,
    "q":        ScanLevel.QUICK,
    "quick":    ScanLevel.QUICK,
    "2":        ScanLevel.STANDARD,
    "s":        ScanLevel.STANDARD,
    "standard": ScanLevel.STANDARD,
    "3":        ScanLevel.DEEP,
    "d":        ScanLevel.DEEP,
    "deep":     ScanLevel.DEEP,
}

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


# ─── Image discovery ──────────────────────────────────────────────────────────


def find_images(path: Path, recursive: bool = True) -> list[Path]:
    """Return a sorted list of all image files at or under *path*."""
    if path.is_file():
        return [path] if path.suffix.lower() in IMAGE_EXTENSIONS else []

    glob = "**/*" if recursive else "*"
    found: set[Path] = set()
    for ext in IMAGE_EXTENSIONS:
        found.update(path.glob(f"{glob}{ext}"))
        found.update(path.glob(f"{glob}{ext.upper()}"))
    return sorted(found)


# ─── Core scan runner ─────────────────────────────────────────────────────────


def run_scan(
    images: list[Path],
    level: ScanLevel,
    *,
    strip: bool = False,
    force_rescan: bool = False,
    use_log: bool = True,
) -> None:
    """Scan every image in *images* and print results to the console."""
    scanner = ImageScanner()
    reporter = Reporter()
    log_db = ScanLog() if use_log else None

    total = len(images)
    skipped = scanned = with_findings = high_risk = 0

    print(f"\n  Scanning {total} image(s)  |  Level: {level.name}")
    print(f"  {'─' * 66}")

    for i, img_path in enumerate(images, 1):
        # Trim long names for display
        label = img_path.name
        if len(label) > 48:
            label = label[:45] + "..."
        print(f"  [{i:>{len(str(total))}}/{total}]  {label:<48}", end="", flush=True)

        # Skip if already scanned (and not forcing)
        if log_db and not force_rescan and log_db.is_scanned(img_path):
            print("  (already scanned, skipping)")
            skipped += 1
            continue

        result = scanner.scan(img_path, level)
        scanned += 1

        if log_db:
            log_db.record(result)

        reporter.print_result(result)

        if result.has_findings:
            with_findings += 1
            report_path = reporter.save_report(result)
            print(f"           Report saved → {report_path.name}")

        if result.is_high_risk:
            high_risk += 1

        # Interactive strip prompt
        if strip and result.appended:
            ans = (
                input(
                    f"           Strip {result.appended.size:,} bytes of"
                    f" '{result.appended.file_type}' from {img_path.name}? [y/N] "
                )
                .strip()
                .lower()
            )
            if ans == "y":
                ok = scanner.strip_appended(result, reporter.reports_dir)
                print(
                    f"           {'Stripped OK — extracted bytes saved to reports/' if ok else '[!] Strip failed.'}"
                )

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"  {'─' * 66}")
    print(
        f"  Done.  Scanned: {scanned}  |  Skipped: {skipped}"
        f"  |  With findings: {with_findings}  |  High risk: {high_risk}"
    )
    if with_findings:
        print(f"  Detailed reports → {Reporter().reports_dir}/")
    print()


# ─── Interactive mode ─────────────────────────────────────────────────────────


def _tool_status() -> None:
    et = "FOUND — will be used in Deep scans" if ExifToolWrapper.is_available() else "not found (optional, see README)"
    bw = "FOUND — will be used in Deep scans" if BinwalkWrapper.is_available() else "not found (optional, see README)"
    print(f"  ExifTool : {et}")
    print(f"  binwalk  : {bw}")
    print()


def _prompt_path(prompt: str) -> Path | None:
    raw = input(prompt).strip().strip('"').strip("'")
    return Path(raw) if raw else None


def _prompt_level() -> ScanLevel:
    print()
    print("  Scan levels:")
    print("   [1] Quick    — metadata check + detect appended data          (fastest)")
    print("   [2] Standard — + identify what the appended data IS           (recommended)")
    print("   [3] Deep     — + full-file string sweep, ExifTool & binwalk   (thorough)")
    choice = input("  Level [2]: ").strip().lower() or "2"
    return _LEVEL_MAP.get(choice, ScanLevel.STANDARD)


def _show_log() -> None:
    log_db = ScanLog()
    entries = log_db.get_all()
    if not entries:
        print("\n  No scan history recorded yet.\n")
        return
    stats = log_db.get_stats()
    print(
        f"\n  Total scanned : {stats['total']}"
        f"  |  With appended data: {stats['with_appended']}"
        f"  |  High risk: {stats['high_risk']}"
    )
    print()
    print(f"  {'File':<44} {'Level':<10} {'Findings':<10} Scanned at")
    print(f"  {'─' * 44} {'─' * 10} {'─' * 10} {'─' * 19}")
    for entry in entries[-40:]:
        flag = "  !!!" if entry.get("is_high_risk") else ("  *  " if entry.get("had_appended") else "     ")
        print(
            f"  {entry['name']:<44} {entry['level']:<10}"
            f" {str(entry['findings']):<10} {entry['time']}{flag}"
        )
    print()
    print("  Legend:  *   = appended data found    !!! = high-risk file type")
    print()


def _strip_interactive() -> None:
    path = _prompt_path("  Image file path: ")
    if not path or not path.is_file():
        print("  [!] File not found.\n")
        return
    scanner = ImageScanner()
    reporter = Reporter()
    result = scanner.scan(path, ScanLevel.STANDARD)
    if not result.appended:
        print("  [+] No appended data found in that image.\n")
        return
    a = result.appended
    print(f"\n  [!] Found {a.size:,} bytes of '{a.file_type}' (category: {a.category})")
    print(f"      It starts at byte offset {a.offset:,}  (0x{a.offset:08X})")
    print(f"      First bytes: {a.preview.hex(' ')}")
    ans = (
        input(
            "\n  Strip the appended data?\n"
            "  (The extracted bytes will be saved to the reports/ folder first.) [y/N] "
        )
        .strip()
        .lower()
    )
    if ans == "y":
        ok = scanner.strip_appended(result, reporter.reports_dir)
        if ok:
            print(f"  [+] Done. Extracted bytes saved to: {reporter.reports_dir}/")
        else:
            print("  [!] Strip failed — check file permissions.")
    print()


def interactive_mode() -> None:
    print(BANNER)
    _tool_status()

    while True:
        print("  Main Menu")
        print("  ─────────────────────────────────────────────")
        print("  [1]  Scan a single image file")
        print("  [2]  Scan a folder of images")
        print("  [3]  View scan history log")
        print("  [4]  Strip appended data from a file")
        print("  [5]  Exit")
        print()
        choice = input("  Select option: ").strip()
        print()

        if choice == "1":
            path = _prompt_path("  Image file path: ")
            if not path or not path.is_file():
                print("  [!] File not found.\n")
                continue
            level = _prompt_level()
            strip = input("  Strip appended data if found? [y/N]: ").strip().lower() == "y"
            run_scan([path], level, strip=strip)

        elif choice == "2":
            path = _prompt_path("  Folder path: ")
            if not path or not path.is_dir():
                print("  [!] Folder not found.\n")
                continue
            recursive = input("  Include subfolders? [Y/n]: ").strip().lower() != "n"
            images = find_images(path, recursive=recursive)
            if not images:
                print("  [!] No image files found in that folder.\n")
                continue
            print(f"\n  Found {len(images)} image(s).")
            level = _prompt_level()
            skip_done = input("  Skip already-scanned images? [Y/n]: ").strip().lower() != "n"
            strip = input("  Strip appended data when found? [y/N]: ").strip().lower() == "y"
            run_scan(images, level, strip=strip, force_rescan=not skip_done)

        elif choice == "3":
            _show_log()

        elif choice == "4":
            _strip_interactive()

        elif choice == "5":
            print("  Goodbye.\n")
            break

        else:
            print("  [!] Please enter 1–5.\n")


# ─── CLI mode ─────────────────────────────────────────────────────────────────


def cli_mode() -> None:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description="Image Hidden Data Scanner — detect embedded files & hidden content",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python scan.py --path photos\\
  python scan.py --path secret.jpg --level deep
  python scan.py --path downloads\\ --level standard --strip --rescan
  python scan.py --path photo.png --no-log
""",
    )
    parser.add_argument(
        "--path", "-p", type=Path, required=True,
        help="Image file or folder to scan",
    )
    parser.add_argument(
        "--level", "-l", choices=["quick", "standard", "deep"],
        default="standard",
        help="Scan depth: quick / standard / deep  (default: standard)",
    )
    parser.add_argument(
        "--strip", "-s", action="store_true",
        help="Prompt to strip appended data from each affected image",
    )
    parser.add_argument(
        "--rescan", action="store_true",
        help="Re-scan images that are already recorded in the scan log",
    )
    parser.add_argument(
        "--no-log", action="store_true",
        help="Do not update the scan log for this run",
    )
    parser.add_argument(
        "--no-recursive", action="store_true",
        help="Do not descend into subfolders",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug-level logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print(BANNER)
    _tool_status()

    images = find_images(args.path, recursive=not args.no_recursive)
    if not images:
        print(f"  [!] No image files found at: {args.path}\n")
        sys.exit(1)

    run_scan(
        images,
        _LEVEL_MAP[args.level],
        strip=args.strip,
        force_rescan=args.rescan,
        use_log=not args.no_log,
    )


# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
