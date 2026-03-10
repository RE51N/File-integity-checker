"""Tests for src/strings.py — printable-string extraction and pattern detection."""

from __future__ import annotations

import pytest

from src.strings import extract_strings, find_interesting, StringFind


# ─── extract_strings ─────────────────────────────────────────────────────────


def test_extract_strings_finds_ascii_run() -> None:
    data = b"\x00\x00hello world\x00\x00"
    result = extract_strings(data, min_length=4)
    assert "hello world" in result


def test_extract_strings_ignores_short_runs() -> None:
    data = b"\x00hi\x00hello world\x00"
    result = extract_strings(data, min_length=5)
    assert "hi" not in result
    assert "hello world" in result


def test_extract_strings_multiple_runs() -> None:
    data = b"first\x00\x00second\x00\x00third"
    result = extract_strings(data, min_length=4)
    assert result == ["first", "second", "third"]


def test_extract_strings_empty_data() -> None:
    assert extract_strings(b"", min_length=4) == []


def test_extract_strings_all_binary() -> None:
    data = bytes(range(32))  # all control characters
    assert extract_strings(data, min_length=4) == []


def test_extract_strings_pure_ascii() -> None:
    data = b"ABCDEFGHIJ"
    result = extract_strings(data, min_length=4)
    assert result == ["ABCDEFGHIJ"]


# ─── find_interesting — URL detection ────────────────────────────────────────


def test_find_interesting_detects_http_url() -> None:
    data = b"visit https://evil.example.com/payload now"
    findings = find_interesting(data)
    reasons = [f.reason for f in findings]
    assert any("URL" in r for r in reasons)


def test_find_interesting_detects_ftp_url() -> None:
    data = b"ftp://files.example.com/secret.zip"
    findings = find_interesting(data)
    assert any("URL" in f.reason for f in findings)


# ─── find_interesting — email detection ──────────────────────────────────────


def test_find_interesting_detects_email() -> None:
    data = b"contact: attacker@badactor.net for info"
    findings = find_interesting(data)
    assert any("email" in f.reason for f in findings)


# ─── find_interesting — IP address detection ─────────────────────────────────


def test_find_interesting_detects_ip_address() -> None:
    data = b"C2 server at 192.168.100.200 ping me"
    findings = find_interesting(data)
    assert any("IP" in f.reason for f in findings)


# ─── find_interesting — base64 detection ─────────────────────────────────────


def test_find_interesting_detects_long_base64() -> None:
    # 60-char base64 string — well above the 40-char detection threshold
    # encodes "This is a secret hidden message for testing purposes"
    b64 = b"VGhpcyBpcyBhIHNlY3JldCBoaWRkZW4gbWVzc2FnZSBmb3IgdGVzdGluZyBwdXJwb3Nlcw=="
    data = b"payload=" + b64 + b" end"
    findings = find_interesting(data)
    assert any("base64" in f.reason for f in findings)


def test_find_interesting_ignores_short_base64() -> None:
    # 20 chars — below our 40-char threshold
    data = b"short=" + b"SGVsbG8gV29ybGQ=" + b" end"
    findings = find_interesting(data)
    assert not any("base64" in f.reason for f in findings)


# ─── find_interesting — PEM key detection ────────────────────────────────────


def test_find_interesting_detects_pem_marker() -> None:
    data = b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC"
    findings = find_interesting(data)
    assert any("PEM" in f.reason for f in findings)


# ─── find_interesting — hex key detection ────────────────────────────────────


def test_find_interesting_detects_long_hex() -> None:
    # 64 hex chars = 256-bit value (typical crypto key)
    hex_key = b"a" * 64
    data = b"key=" + hex_key + b";"
    findings = find_interesting(data)
    assert any("hex" in f.reason for f in findings)


def test_find_interesting_ignores_short_hex() -> None:
    data = b"id=deadbeef;"  # 8 hex chars — too short
    findings = find_interesting(data)
    assert not any("hex" in f.reason for f in findings)


# ─── find_interesting — sensitive keyword detection ──────────────────────────


def test_find_interesting_detects_password_keyword() -> None:
    data = b"password=hunter2 for the archive"
    findings = find_interesting(data)
    assert any("keyword" in f.reason for f in findings)


def test_find_interesting_detects_secret_keyword() -> None:
    data = b"this is my secret message hidden in the image"
    findings = find_interesting(data)
    assert any("keyword" in f.reason for f in findings)


# ─── find_interesting — deduplication ────────────────────────────────────────


def test_find_interesting_deduplicates_identical_patterns() -> None:
    # Same URL repeated twice
    url = b"https://example.com/payload"
    data = url + b" and also " + url
    findings = find_interesting(data)
    url_findings = [f for f in findings if "URL" in f.reason]
    assert len(url_findings) == 1  # deduplicated


# ─── find_interesting — clean data ───────────────────────────────────────────


def test_find_interesting_returns_empty_for_clean_data() -> None:
    data = b"Normal camera metadata: Canon EOS R5, ISO 100, f/2.8"
    findings = find_interesting(data)
    assert findings == []


# ─── StringFind dataclass ─────────────────────────────────────────────────────


def test_stringfind_has_expected_fields() -> None:
    sf = StringFind(offset=42, value="test_value", reason="test reason")
    assert sf.offset == 42
    assert sf.value == "test_value"
    assert sf.reason == "test reason"
