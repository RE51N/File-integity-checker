# CLAUDE.md — File Integrity Checker

This file provides guidance for AI assistants (Claude and others) working in this repository.

---

## Project Overview

**File-integrity-checker** is a tool that monitors and verifies the integrity of files on disk by computing and comparing cryptographic hashes (e.g. SHA-256). It detects unauthorized modifications, corruptions, or deletions of files in a watched directory tree.

Core capabilities:
- Baseline snapshot creation (scan a directory and record file hashes)
- Integrity verification (compare current state against a saved baseline)
- Change reporting (added, modified, deleted files)
- Optional scheduling/daemon mode for continuous monitoring

---

## Repository Structure

```
File-integity-checker/
├── CLAUDE.md                  # This file
├── README.md                  # Human-facing project documentation
├── .gitignore
├── src/                       # Application source code
│   ├── __init__.py
│   ├── checker.py             # Core integrity-check logic
│   ├── hasher.py              # Hashing utilities (SHA-256, MD5, etc.)
│   ├── reporter.py            # Output/report formatting
│   ├── scheduler.py           # Optional daemon/scheduling support
│   └── cli.py                 # Command-line interface entry point
├── tests/                     # Unit and integration tests
│   ├── __init__.py
│   ├── test_checker.py
│   ├── test_hasher.py
│   └── test_reporter.py
├── baselines/                 # Saved baseline snapshots (gitignored)
├── requirements.txt           # Runtime dependencies
├── requirements-dev.txt       # Dev/test dependencies
├── setup.py / pyproject.toml  # Package configuration
└── Makefile                   # Common task shortcuts
```

> Note: `baselines/` should be listed in `.gitignore` — it contains runtime data, not source code.

---

## Tech Stack

| Layer        | Choice                              |
|--------------|-------------------------------------|
| Language     | Python 3.10+                        |
| Hashing      | `hashlib` (stdlib)                  |
| CLI          | `argparse` or `click`               |
| Serialization| JSON (baselines), optionally SQLite |
| Testing      | `pytest`                            |
| Linting      | `flake8` + `black` (formatting)     |
| Type hints   | `mypy` for static analysis          |

---

## Development Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows

# 2. Install runtime + dev dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Install the package in editable mode
pip install -e .
```

---

## Common Commands

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=term-missing

# Lint code
flake8 src/ tests/

# Format code
black src/ tests/

# Type check
mypy src/

# Run via Makefile shortcuts (if Makefile is present)
make test
make lint
make format
```

---

## CLI Usage (expected interface)

```bash
# Create a baseline snapshot of a directory
python -m src.cli baseline --path /target/dir --output baselines/snapshot.json

# Verify integrity against a baseline
python -m src.cli verify --baseline baselines/snapshot.json --path /target/dir

# Watch a directory continuously (daemon mode)
python -m src.cli watch --path /target/dir --interval 60
```

---

## Code Conventions

### General
- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines.
- Use `black` for auto-formatting (line length: 88).
- All public functions and classes must have docstrings.
- Use type annotations throughout (`def compute_hash(path: str) -> str:`).

### Naming
- Modules: `snake_case.py`
- Classes: `PascalCase`
- Functions/variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`

### Error Handling
- Raise specific exceptions (e.g. `FileNotFoundError`, `PermissionError`); do not swallow exceptions silently.
- Use `logging` (not `print`) for diagnostic output. Configure log level via CLI flag or env var `LOG_LEVEL`.

### File I/O
- Always use `pathlib.Path` for file paths instead of raw strings.
- Open files with explicit `encoding="utf-8"` unless binary mode is required.
- Handle `PermissionError` and `OSError` gracefully when scanning directories.

### Hashing
- Default algorithm: **SHA-256**.
- Read files in chunks (`8192` bytes) to handle large files without memory issues.
- Store hashes as lowercase hex strings.

### Baselines
- Stored as JSON: `{ "path": "<abs_path>", "created_at": "<ISO8601>", "files": { "<rel_path>": "<hash>", ... } }`
- Paths inside a baseline are stored as **relative** to the baseline root to keep snapshots portable.

---

## Testing Guidelines

- Every public function in `src/` must have at least one corresponding test in `tests/`.
- Use `tmp_path` (pytest fixture) to create temporary directories/files in tests — never write to the real filesystem.
- Mock `time.time()` and datetime calls when testing timestamp-sensitive code.
- Integration tests that perform real file I/O should be marked `@pytest.mark.integration` and can be skipped with `pytest -m "not integration"`.

---

## Git Workflow

- **Main branch:** `main` — always stable, never commit directly.
- **Feature branches:** `feature/<short-description>` (e.g. `feature/add-md5-support`).
- **Fix branches:** `fix/<issue-description>` (e.g. `fix/symlink-handling`).
- **Claude branches:** `claude/<task-description>-<session-id>` (auto-generated).
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat: add SHA-512 hashing option`
  - `fix: handle broken symlinks during scan`
  - `test: add edge cases for empty directories`
  - `docs: update CLI usage in README`
- Keep commits atomic — one logical change per commit.
- Do not commit baseline files (`baselines/`) or `.venv/` directories.

---

## Security Considerations

- This tool reads arbitrary filesystem paths; always validate and sanitize user-provided paths.
- Avoid following symlinks by default (prevent directory traversal attacks); make it opt-in via a `--follow-symlinks` flag.
- Baseline files themselves may be tampered with; consider HMAC-signing baselines in future versions.
- Do not log file contents — only log paths and hash values.

---

## AI Assistant Notes

When working in this codebase:

1. **Read before editing** — always read a file fully before proposing or making changes.
2. **Minimal changes** — fix what was asked; do not refactor unrelated code.
3. **No silent dependencies** — if a new library is needed, add it to `requirements.txt` explicitly and note it in the PR/commit message.
4. **Preserve conventions** — match existing code style (naming, docstrings, type hints) in every new file or function.
5. **Tests are required** — every feature addition or bug fix must include or update tests.
6. **Never commit secrets** — do not commit API keys, passwords, or real filesystem paths from the developer's machine.
7. **Branch discipline** — develop on the designated `claude/...` branch; never push to `main` directly.
