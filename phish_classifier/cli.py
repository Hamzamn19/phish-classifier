"""`phish-scan` - Typer command-line interface.

Mirrors the classic `python email_scanner.py` flags, with type-checked
options and `--help` generated automatically.

Flow: mbox -> exact/subdomain whitelist -> strong model (single pass).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer

from .scanner import (
    DEFAULT_OLLAMA_URL,
    DEFAULT_STRONG_MODEL,
    EmailScanner,
    export_csv,
    print_summary,
)

HELP = (
    "Scan a Google Takeout .mbox archive for phishing with a local Ollama "
    "model: an exact/subdomain whitelist skips trusted senders instantly, "
    "everything else is decided by the strong model. Fully offline."
)


def main(
    mbox: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to the .mbox file (e.g. from Google Takeout).",
    ),
    limit: int = typer.Argument(
        5, help="How many emails to scan (default 5)."
    ),
    last: bool = typer.Option(
        False, "--last", help="Scan the LAST <limit> emails instead of the first."
    ),
    strong: Optional[str] = typer.Option(
        None, "--strong", "-s",
        help=f"Model that decides non-whitelisted emails (default: {DEFAULT_STRONG_MODEL}).",
    ),
    csv: Path = typer.Option(
        Path("scan_results.csv"), "--csv",
        help="Output CSV path (utf-8-sig, Excel/Arabic safe).",
    ),
    url: str = typer.Option(
        DEFAULT_OLLAMA_URL, "--url", help="Ollama decision endpoint."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print per-email decision details."
    ),
) -> None:
    """Scan MBOX emails and write the classified results to CSV."""
    scanner = EmailScanner(ollama_url=url)
    if strong:
        scanner.strong_model = strong

    start = time.time()
    results = scanner.scan_mbox(
        str(mbox), limit, from_end=last, verbose=verbose
    )
    elapsed = time.time() - start

    export_csv(results, str(csv))
    print_summary(scanner, results, elapsed)

    if not results:
        typer.secho("No emails were scanned.", fg=typer.colors.RED)
        raise typer.Exit(code=1)


def run() -> None:
    typer.run(main)


if __name__ == "__main__":
    run()
