# CLAUDE.md — Image Hidden Data Scanner

This file provides guidance for AI assistants (Claude and others) working in this repository.

---

## Project Overview

**Image Hidden Data Scanner** is a Windows-compatible command-line tool that examines image files
for hidden, embedded, or appended content — the kind of data that could indicate steganography,
file polyglots (a ZIP hidden inside a JPEG, for example), or tampered images.

Core capabilities:
- **Append detection** — finds data beyond the image's official end marker (FF D9 for JPEG, IEND for PNG, etc.)
- **Magic-byte identification** — classifies appended data: ZIP, EXE, PDF, SQLite, PEM key, plain text, …
- **Metadata analysis** — reads all EXIF, PNG text chunks, and GIF/BMP info fields; flags suspicious values
- **String extraction** — hunts for URLs, email addresses, IP addresses, base64 blobs, PEM markers, and sensitive keywords inside binary data
- **Strip & extract** — removes appended data from images and saves it separately for examination
- **Scan log** — tracks which files have been checked so repeat runs skip them
- **Three scan levels** — Quick (metadata only), Standard (recommended), Deep (full sweep + external tools)
- **ExifTool & binwalk integration** — auto-detected if installed; used in Deep mode for maximum coverage

---

## Repository Structure

```
File-integity-checker/
├── scan.py                # Main entry point — interactive menu OR CLI flags
├── CLAUDE.md              # This file
├── README.md              # Human-facing setup and usage guide
├── requirements.txt       # Runtime deps (Pillow, colorama)
├── requirements-dev.txt   # Dev/test deps (pytest, pytest-cov)
├── scan_log.json          # Auto-created; tracks scanned files (gitignored)
├── src/
│   ├── __init__.py
│   ├── formats.py         # Image end-of-data detection (JPEG, PNG, GIF, BMP, WebP)
│   ├── magic.py           # Magic-byte database + file-type identification
│   ├── metadata.py        # EXIF, PNG text chunks, info-dict extraction via Pillow
│   ├── strings.py         # Printable-string extraction + interesting-pattern detection
│   ├── external.py        # ExifTool and binwalk subprocess wrappers
│   ├── scanner.py         # ScanResult dataclass + ImageScanner orchestrator
│   ├── scanlog.py         # JSON-backed persistent scan history
│   └── reporter.py        # Console output (coloured) + text report files
├── tests/
│   ├── __init__.py
│   ├── test_formats.py    # End-marker detection unit tests
│   ├── test_magic.py      # Magic-byte identification tests
│   └── test_strings.py    # String extraction and pattern detection tests
├── reports/               # Auto-created; one .txt report per image with findings
└── baselines/             # Reserved for future baseline snapshot support
```

> `scan_log.json`, `reports/`, and `baselines/` are listed in `.gitignore`.

---

## Tech Stack

| Layer          | Choice                                          |
|----------------|-------------------------------------------------|
| Language       | Python 3.10+                                    |
| Image I/O      | `Pillow` (EXIF, metadata, format validation)   |
| Binary parsing | `hashlib`, `struct` (stdlib)                   |
| CLI            | `argparse` (stdlib) + interactive `input()` menu |
| Serialisation  | JSON (scan log, reports as plain text)         |
| Console colour | `colorama` (Windows CMD compatible)            |
| Testing        | `pytest`                                        |
| External tools | ExifTool (optional), binwalk (optional)        |

---

## Development Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
.venv\Scripts\activate         # Windows CMD

# 2. Install runtime + dev dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Run tests
pytest

# 4. Run with coverage
pytest --cov=src --cov-report=term-missing
```

---

## Running the Scanner

```bash
# Interactive menu (no arguments)
python scan.py

# Scan a folder — standard level
python scan.py --path C:\Photos\

# Scan a single file — deep level
python scan.py --path suspicious.jpg --level deep

# Scan and strip appended data
python scan.py --path downloads\ --level standard --strip

# Re-scan already-logged files
python scan.py --path C:\Images\ --rescan

# Skip updating the scan log
python scan.py --path photo.jpg --no-log
```

---

## Scan Levels

| Level      | What it checks                                                               | Speed  |
|------------|------------------------------------------------------------------------------|--------|
| `quick`    | Metadata fields + detect whether any appended data exists                   | Fast   |
| `standard` | Everything in quick + magic-byte ID of appended data + string search in it | Medium |
| `deep`     | Everything in standard + full-file string sweep + ExifTool + binwalk       | Slow   |

---

## Code Conventions

### General
- Follow [PEP 8](https://peps.python.org/pep-0008/). Use `black` for formatting (line length: 88).
- All public functions and classes must have docstrings.
- Use type annotations throughout.

### Naming
- Modules: `snake_case.py`
- Classes: `PascalCase`
- Functions / variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Module-level private helpers: `_leading_underscore`

### Error Handling
- Catch only specific exceptions (`OSError`, `ValueError`, etc.); never bare `except:`.
- Use `logging` (not `print`) for diagnostic messages inside `src/`.
- The `scan.py` entry point may use `print()` for user-facing output.
- Degrade gracefully when optional dependencies (Pillow, colorama, ExifTool, binwalk) are absent.

### File I/O
- Always use `pathlib.Path` — never raw strings for paths.
- Open text files with `encoding="utf-8"` explicitly.
- Read binary files with `.read_bytes()` (Pillow opens them internally as needed).

### Binary Analysis
- JPEG end: `FF D9` (rightmost occurrence).
- PNG end: fixed 12-byte IEND-chunk sequence.
- GIF end: `0x3B` trailer (rightmost occurrence).
- BMP end: file size declared in header bytes 2–5 (little-endian uint32).
- WebP end: RIFF header declared payload size + 8.
- When appended data is detected, always save a backup before stripping.

### Scan Log
- Format: `{ "version": 1, "scans": { "<abs_path>": { … } } }`
- Keys: `name`, `sha256`, `size`, `level`, `time`, `had_appended`, `is_high_risk`, `findings`.

---

## Testing Guidelines

- Every public function in `src/` must have at least one test in `tests/`.
- Use `tmp_path` (pytest fixture) for all file I/O in tests — never write to the real filesystem.
- Mock `datetime.datetime.now()` and `time.perf_counter()` in tests that check timing.
- Use minimal hand-crafted binary blobs (not real image files) in unit tests to keep the test suite fast and dependency-free.
- Integration tests that require real images should be marked `@pytest.mark.integration` and skipped by default: `pytest -m "not integration"`.

---

## Git Workflow

- **Main branch:** `main` — always stable.
- **Feature branches:** `feature/<description>`
- **Fix branches:** `fix/<description>`
- **Claude branches:** `claude/<task>-<session-id>` (auto-generated).
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat: add TIFF end-marker support`
  - `fix: handle WebP files with odd-sized RIFF chunks`
  - `test: cover GIF trailer detection edge cases`
  - `docs: update README with binwalk install steps`
- Do not commit `scan_log.json`, `reports/`, or `.venv/`.

---

## Security Considerations

- This tool reads arbitrary files from disk; validate all user-provided paths before use.
- Never follow symlinks automatically — the `find_images()` helper uses `Path.glob()` which does not dereference symlinks by default.
- Do not log file contents — only log file paths, sizes, and hash values.
- When stripping appended data, always write the extracted bytes to `reports/` *before* truncating the source file.
- The scanner reads but never executes appended data — do not change this behaviour.

---

## AI Assistant Notes

When working in this codebase:

1. **Read before editing** — always read a file in full before proposing changes.
2. **Minimal changes** — fix only what was asked; do not refactor unrelated code.
3. **No silent dependencies** — if a new library is needed, add it to `requirements.txt` and note it in the commit.
4. **Preserve conventions** — match existing style (type hints, docstrings, `pathlib`, logging) in every change.
5. **Tests are required** — every new function or bug fix must have a corresponding test.
6. **Never commit secrets** — do not include real filesystem paths, API keys, or passwords.
7. **Branch discipline** — develop on the designated `claude/…` branch; never push to `main` directly.
8. **Graceful degradation** — optional dependencies (Pillow, colorama, ExifTool, binwalk) must never crash the tool; wrap them in `try/except ImportError` or availability checks.
