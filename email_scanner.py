#!/usr/bin/env python3
"""Backward-compatible entry point.

The implementation now lives in the ``phish_classifier`` package:
    phish_classifier/whitelist.py  - spoof-safe exact/subdomain whitelist
    phish_classifier/extract.py    - MIME/mbox extraction + smart truncation
    phish_classifier/scanner.py    - Ollama client + whitelist -> strong model

All existing commands keep working unchanged (--big-only is a deprecated no-op):
    python3 email_scanner.py <mbox> 1000 --last [--big-only] [--strong M] [--csv P]
"""

from phish_classifier import EmailScanner, decode_mime_header
from phish_classifier.scanner import main

__all__ = ["EmailScanner", "decode_mime_header", "main"]

if __name__ == "__main__":
    main()
