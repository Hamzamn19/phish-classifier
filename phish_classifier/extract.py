"""MIME / mbox extraction, HTML cleaning and the smart head-and-tail cut.

Three responsibilities:
    * decode MIME headers and message bodies robustly (invalid charsets such
      as ``tr-ascii`` must never abort a load),
    * load a Google Takeout ``.mbox`` with a per-message guard,
    * smart-truncate text before it is sent to a model.
"""

from __future__ import annotations

import mailbox
import re
import sys
from email.header import decode_header
from typing import Dict, List

from bs4 import BeautifulSoup

# Smart truncation budget sent to the model:
#   len > 700 -> first 350 + marker + last 350 (keeps BOTH ends, so a
#   notification email never loses the verdict/subject sitting at the tail).
SMART_TRUNCATE_AT = 700
SMART_HEAD = 350
SMART_TAIL = 350
TRUNCATE_MARKER = "\n...[مقطوع]...\n"

# Hard cap applied when loading an email (full text kept <= this).
MAX_TEXT_LENGTH = 2000


def decode_mime_header(header: str) -> str:
    """Decode MIME-encoded header (RFC 2047)."""
    if not header:
        return ""
    parts = decode_header(header)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            for cs in [charset, "utf-8", "latin-1"]:
                if cs:
                    try:
                        decoded.append(part.decode(cs))
                        break
                    except (UnicodeDecodeError, LookupError):
                        continue
            else:
                decoded.append(part.decode("utf-8", errors="ignore"))
        else:
            decoded.append(part)
    return "".join(decoded)


def safe_decode(payload: bytes, charset: str) -> str:
    """Decode bytes; invalid declared charsets (e.g. ``tr-ascii``) fall
    back to utf-8 instead of raising ``LookupError``."""
    try:
        return payload.decode(charset, errors="ignore")
    except LookupError:
        return payload.decode("utf-8", errors="ignore")


def clean_html(html_content: str) -> str:
    """Remove HTML tags and return clean text."""
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = soup.get_text(separator=" ")
    return re.sub(r"\s+", " ", text).strip()


def extract_email_parts(message) -> Dict[str, str]:
    """Extract sender, subject, and body from an email message."""
    sender = decode_mime_header(message.get("From", "Unknown"))
    subject = decode_mime_header(message.get("Subject", "No Subject"))

    body = ""
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    body = safe_decode(payload, part.get_content_charset() or "utf-8")
                    break
            elif (content_type == "text/html"
                  and "attachment" not in content_disposition
                  and not body):
                payload = part.get_payload(decode=True)
                if payload:
                    html_body = safe_decode(payload, part.get_content_charset() or "utf-8")
                    body = clean_html(html_body)
    else:
        payload = message.get_payload(decode=True)
        if payload:
            content_type = message.get_content_type()
            charset = message.get_content_charset() or "utf-8"
            body = safe_decode(payload, charset)
            if content_type == "text/html":
                body = clean_html(body)

    return {
        "sender": sender,
        "subject": subject,
        "body": body.strip(),
    }


def smart_truncate(text: str) -> str:
    """Head & Tail cut: keeps the first and last 350 chars of long text."""
    if len(text) <= SMART_TRUNCATE_AT:
        return text
    return text[:SMART_HEAD] + TRUNCATE_MARKER + text[-SMART_TAIL:]


def hard_truncate(text: str, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Cap text length (applied when loading, before any model call)."""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def load_emails(mbox_path: str, limit: int, from_end: bool,
                max_text_length: int = MAX_TEXT_LENGTH) -> List[Dict]:
    """Read the mbox once and return prepared email dicts."""
    emails: List[Dict] = []
    try:
        mbox = mailbox.mbox(mbox_path)
        total = len(mbox)
        print(f"Found {total} emails in {mbox_path}", file=sys.stderr)

        if from_end:
            start_idx = max(0, total - limit)
            print(f"Scanning last {limit} emails (#{start_idx + 1} to #{total})...\n",
                  file=sys.stderr)
        else:
            start_idx = 0
            print(f"Scanning first {limit} emails...\n", file=sys.stderr)

        for i in range(start_idx, min(start_idx + limit, total)):
            # Per-message guard: ONE broken message must never abort the
            # whole load (root cause of a historic 8092/19108 stop).
            try:
                message = mbox[i]
                parts = extract_email_parts(message)
            except Exception as exc:  # noqa: BLE001 - keep loading, skip bad msg
                print(f"Warning: skipped unreadable email #{i + 1}: "
                      f"{type(exc).__name__}: {exc}", file=sys.stderr)
                continue
            full_text = f"Subject: {parts['subject']}\n\n{parts['body']}"
            emails.append({
                "index": i + 1,
                "sender": parts["sender"],
                "subject": parts["subject"],
                "text": hard_truncate(full_text, max_text_length),
            })
    except FileNotFoundError:
        print(f"Error: File not found: {mbox_path}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        print(f"Error reading mbox file: {exc}", file=sys.stderr)
    return emails
