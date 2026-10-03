"""Tests for extraction + the smart head-and-tail truncation."""

import mailbox
import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phish_classifier import extract  # noqa: E402


# ------------------------------------------------------------- smart truncation
def test_short_text_untouched() -> None:
    text = "A" * extract.SMART_TRUNCATE_AT
    assert extract.smart_truncate(text) == text


def test_long_text_keeps_head_and_tail() -> None:
    head = "H" * 500
    tail = "T" * 500
    out = extract.smart_truncate(head + tail)
    assert out.startswith("H" * 350)
    assert out.endswith("T" * 350)
    assert extract.TRUNCATE_MARKER in out
    assert len(out) == 350 + len(extract.TRUNCATE_MARKER) + 350


def test_boundary_is_exclusive() -> None:
    assert extract.smart_truncate("x" * 701) != "x" * 701


def test_hard_truncate_cap() -> None:
    assert extract.hard_truncate("a" * 100) == "a" * 100
    assert extract.hard_truncate("a" * 2001) == "a" * 2000 + "..."
    assert extract.hard_truncate("a" * 2500, max_length=10) == "a" * 10 + "..."


# ------------------------------------------------------------------ robustness
def test_safe_decode_unknown_charset_falls_back() -> None:
    """The historic `unknown encoding: tr-ascii` crash (message #8093)."""
    out = extract.safe_decode(b"hello", "tr-ascii")
    assert out == "hello"


def test_safe_decode_real_charset() -> None:
    assert extract.safe_decode("مرحبا".encode("utf-8"), "utf-8") == "مرحبا"


def test_decode_mime_header_handles_broken_charset() -> None:
    # unknown charset inside an encoded-word must not raise
    out = extract.decode_mime_header("=?unknown-charset?B?aGVsbG8=?=")
    assert out  # decoded via fallback or returned as-is, but no crash


def test_decode_mime_header_empty() -> None:
    assert extract.decode_mime_header("") == ""


def test_clean_html_strips_script_and_tags() -> None:
    html = "<html><script>alert(1)</script><style>p{}</style><p>Hello <b>World</b></p></html>"
    out = extract.clean_html(html)
    assert "alert" not in out and "<p>" not in out
    assert "Hello World" in out


# ---------------------------------------------------------------- extraction
def _make_msg(from_="Sender <a@b.com>", subject="Hi", body="Body text",
              html: str = None, multipart_html_first: bool = False):
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = from_
    msg["Subject"] = subject
    if html is None:
        msg.set_content(body)
    else:
        msg.set_content(body)
        msg.add_alternative(html, subtype="html")
    return msg


def test_extract_plain_message() -> None:
    parts = extract.extract_email_parts(_make_msg())
    assert parts["sender"] == "Sender <a@b.com>"
    assert parts["subject"] == "Hi"
    assert "Body text" in parts["body"]


def test_extract_prefers_text_plain() -> None:
    msg = _make_msg(body="PLAIN-WINS", html="<p>HTML-LOSES</p>")
    parts = extract.extract_email_parts(msg)
    assert "PLAIN-WINS" in parts["body"]


def test_extract_html_only_message_is_cleaned() -> None:
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "a@b.com"
    msg["Subject"] = "S"
    msg.set_content("fallback")
    msg.replace_header("Content-Type", "text/html; charset=utf-8")
    parts = extract.extract_email_parts(msg)
    assert "<" not in parts["body"]


def test_extract_defaults_when_headers_missing() -> None:
    from email.message import EmailMessage

    msg = EmailMessage()
    msg.set_content("x")
    parts = extract.extract_email_parts(msg)
    assert parts["sender"] == "Unknown"
    assert parts["subject"] == "No Subject"


# ------------------------------------------------------------------- mbox load
@pytest.fixture()
def sample_mbox(tmp_path):
    path = tmp_path / "sample.mbox"
    box = mailbox.mbox(str(path))
    box.lock()
    for i in range(3):
        msg = mailbox.mboxMessage()
        msg.set_payload(f"Message number {i} body")
        msg["From"] = f"sender{i}@example.com"
        msg["Subject"] = f"Subject {i}"
        box.add(msg)
    box.flush()
    box.unlock()
    return str(path)


def test_load_emails_basic(sample_mbox) -> None:
    emails = extract.load_emails(sample_mbox, 5, from_end=False)
    assert len(emails) == 3
    assert emails[0]["index"] == 1
    assert emails[0]["sender"] == "sender0@example.com"
    assert "Subject: Subject 0" in emails[0]["text"]


def test_load_emails_from_end(sample_mbox) -> None:
    emails = extract.load_emails(sample_mbox, 2, from_end=True)
    assert len(emails) == 2
    assert emails[0]["index"] == 2  # last two messages


def test_load_emails_missing_file_returns_empty(tmp_path) -> None:
    assert extract.load_emails(str(tmp_path / "nope.mbox"), 5, False) == []
