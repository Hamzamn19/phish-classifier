"""phish_classifier - local phishing/ham classification for .mbox archives.

Two-stage cascade on a local Ollama server:
    fast model (screen) -> strong model (final decision),
with a spoof-safe exact/subdomain whitelist in front and smart head-and-tail
truncation of long bodies.  Everything runs offline on your own GPU.
"""

from .extract import (
    decode_mime_header,
    extract_email_parts,
    hard_truncate,
    load_emails,
    smart_truncate,
)
from .scanner import EmailScanner, export_csv, main, print_summary
from .whitelist import (
    BASE_WHITELIST_DOMAINS,
    build_whitelist,
    load_domain_file,
    match_domain,
    sender_domain,
)

__version__ = "0.1.0"

__all__ = [
    "EmailScanner",
    "BASE_WHITELIST_DOMAINS",
    "build_whitelist",
    "load_domain_file",
    "match_domain",
    "sender_domain",
    "decode_mime_header",
    "extract_email_parts",
    "hard_truncate",
    "load_emails",
    "smart_truncate",
    "export_csv",
    "print_summary",
    "main",
    "__version__",
]
