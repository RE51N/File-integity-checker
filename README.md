# Image Hidden Data Scanner

A Windows-compatible command-line tool that hunts for hidden data inside image files.

It detects:

- **Appended files** — ZIP archives, executables, ISO images, PDFs, SQLite databases, crypto keys,
  and more hidden after the image's official end marker
- **Hidden text** — URLs, email addresses, IP addresses, base64 blobs, PEM keys, and sensitive
  keywords embedded in the binary data or metadata fields
- **Suspicious metadata** — EXIF comments, PNG text chunks, and other metadata fields that contain
  encoded or unusual content

---

## Quick Start (Windows CMD)

```cmd
:: 1. Install Python 3.10+ from https://python.org if you haven't already

:: 2. Open a Command Prompt and navigate to this folder
cd C:\path\to\File-integity-checker

:: 3. Install dependencies
pip install -r requirements.txt

:: 4. Run in interactive mode
python scan.py
```

That's it. The interactive menu will guide you through everything.

---

## Requirements

| Requirement   | Notes                                                     |
|---------------|-----------------------------------------------------------|
| Python 3.10+  | https://python.org/downloads/                            |
| Pillow        | Installed automatically via `pip install -r requirements.txt` |
| colorama      | Installed automatically — enables colours on Windows CMD |

### Optional (but recommended for Deep scans)

| Tool      | What it adds                                          | How to get it                                              |
|-----------|-------------------------------------------------------|------------------------------------------------------------|
| ExifTool  | Complete metadata read-out — the gold standard        | Download `exiftool.exe` from https://exiftool.org and put it anywhere on your PATH |
| binwalk   | Large signature database for embedded-file detection  | `pip install binwalk`                                      |

The scanner auto-detects these tools and uses them in **Deep** mode if present.
It works fine without them — you just get fewer results on Deep scans.

---

## Usage

### Interactive mode (recommended for beginners)

```cmd
python scan.py
```

You will see a menu:

```
  Main Menu
  ─────────────────────────────────────────────
  [1]  Scan a single image file
  [2]  Scan a folder of images
  [3]  View scan history log
  [4]  Strip appended data from a file
  [5]  Exit
```

### Command-line mode

```cmd
:: Scan a folder at standard depth (recommended)
python scan.py --path C:\Downloads\images\

:: Scan a single suspicious image at deep level
python scan.py --path C:\suspect\photo.jpg --level deep

:: Scan and offer to strip appended data from each affected image
python scan.py --path C:\images\ --strip

:: Re-scan files that were already logged (normally skipped)
python scan.py --path C:\images\ --rescan

:: Scan but don't record anything in the scan log
python scan.py --path photo.jpg --no-log

:: Don't descend into subfolders
python scan.py --path C:\images\ --no-recursive
```

---

## Scan Levels Explained

### Quick  `--level quick`
Reads all metadata (EXIF, comments) and tells you whether there is any data
after the image's end marker.  Very fast — good for a first pass over thousands
of images.

### Standard  `--level standard`  *(default)*
Everything in Quick, plus:
- Identifies **what** the appended data is (ZIP? EXE? plain text? crypto key?)
- Searches the appended bytes for URLs, email addresses, IP addresses, base64
  blobs, PEM markers, long hex strings, and sensitive keywords

### Deep  `--level deep`
Everything in Standard, plus:
- Searches the **entire** file binary (not just the appended part) for
  interesting patterns — catches data hidden inside the image body itself
- Runs **ExifTool** if installed for a complete metadata dump
- Runs **binwalk** if installed to detect embedded file signatures anywhere
  in the file

---

## Output

### Console
Each image gets a one-line result:

```
  [  CLEAN  ]
  [FINDINGS ]  Appended: 14,322 B → ZIP archive  |  2 suspicious metadata field(s)
  [HIGH RISK]  Appended: 8,192 B → Windows PE executable *** HIGH RISK ***
```

### Reports
When findings are detected a full `.txt` report is saved to the `reports/` folder:

```
reports\
  suspicious_photo_20240315_142300.txt
  holiday_snap_20240315_142301.txt
```

Each report includes:
- File path, size, SHA-256 hash
- Exact byte offset and size of appended data
- First 32 bytes of the appended data (hex)
- All metadata fields (suspicious ones flagged)
- All interesting strings found, with offsets
- ExifTool / binwalk output (Deep mode)

### Scan log
`scan_log.json` tracks every file you have scanned.  On future runs the scanner
skips files that are already in the log (use `--rescan` to override).

View the log from the interactive menu: **[3] View scan history log**

---

## Stripping Appended Data

If you want to clean an image:

1. Run a Standard or Deep scan first to confirm what is there.
2. Use **--strip** on the command line, or choose **[4]** from the menu.
3. The scanner will:
   - Save the extracted bytes to `reports/<filename>_appended_<timestamp>.bin`
   - Truncate the original image at its end marker
   - The original image will still open normally in any viewer

> The extracted `.bin` file is kept so you can examine it further (e.g. rename
> it to `.zip` or `.exe` and inspect it safely).

---

## Examples — What It Can Find

| Hidden content                          | Detected by                             |
|-----------------------------------------|-----------------------------------------|
| ZIP file appended to a JPEG             | Append detection + magic bytes (ZIP)   |
| Password stored in EXIF Comment         | Metadata scan + sensitive keyword      |
| C2 URL in PNG tEXt chunk               | Metadata scan + URL pattern            |
| Base64-encoded payload in UserComment   | Metadata scan + base64 heuristic       |
| Private key appended to an image        | Append detection + magic bytes (PEM)   |
| SQLite database hidden in a GIF         | Append detection + magic bytes (DB)    |
| Windows EXE embedded in a JPEG          | Append detection + magic bytes (PE) ⚠  |
| Plain text message after image end      | Append detection + text heuristic      |

---

## Supported Image Formats

JPEG · PNG · GIF · BMP · WebP · TIFF

---

## Running Tests

```cmd
pip install -r requirements-dev.txt
pytest
pytest --cov=src --cov-report=term-missing
```

---

## Project Structure

```
File-integity-checker/
├── scan.py              Main entry point
├── src/
│   ├── formats.py       Image end-marker detection
│   ├── magic.py         File-type identification from magic bytes
│   ├── metadata.py      EXIF / metadata extraction (Pillow)
│   ├── strings.py       String extraction and pattern detection
│   ├── external.py      ExifTool and binwalk wrappers
│   ├── scanner.py       Orchestrator — ties everything together
│   ├── scanlog.py       Persistent scan history (JSON)
│   └── reporter.py      Console output and text report files
├── tests/               Unit tests (pytest)
├── reports/             Auto-created — one report per image with findings
├── requirements.txt
└── requirements-dev.txt
```

---

## Notes on False Positives

- **Deep mode** searches the entire file binary, which includes compressed pixel
  data. This can produce false positives for base64 and hex patterns — review
  findings critically.
- Some cameras embed unusually long strings (GPS coordinates, lens serial
  numbers) in EXIF fields. These may be flagged — check the context.
- Always examine the extracted `.bin` file in a safe environment (e.g. a VM)
  before running or opening it.
