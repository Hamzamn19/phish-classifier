"""`phish-scan` - Typer command-line interface.

Mirrors the classic `python email_scanner.py` flags, with type-checked
options and `--help` generated automatically.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer

from .scanner import (
    DEFAULT_OLLAMA_URL,
    DEFAULT_SAFE_THRESHOLD,
    DEFAULT_STRONG_MODEL,
    EmailScanner,
    export_csv,
    print_summary,
)

HELP = (
    "Scan a Google Takeout .mbox archive for phishing with a two-stage "
    "Ollama cascade (fast model -> strong model), a spoof-safe whitelist "
    "and smart head-and-tail truncation. Everything runs locally/offline."
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
    big_only: bool = typer.Option(
        False, "--big-only",
        help="Skip the cascade: the strong model decides every email.",
    ),
    strong: Optional[str] = typer.Option(
        None, "--strong",
        help=f"Override the strong model (default: {DEFAULT_STRONG_MODEL}).",
    ),
    fast: Optional[str] = typer.Option(
        None, "--fast",
        help="Override the fast (stage-1) model.",
    ),
    csv: Path = typer.Option(
        Path("scan_results.csv"), "--csv",
        help="Output CSV path (utf-8-sig, Excel/Arabic safe).",
    ),
    url: str = typer.Option(
        DEFAULT_OLLAMA_URL, "--url", help="Ollama decision endpoint."
    ),
    threshold: float = typer.Option(
        DEFAULT_SAFE_THRESHOLD, "--threshold",
        help="Stage-1 accept threshold for 'Safe' results.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print per-email decision details."
    ),
) -> None:
    """Scan MBOX emails and write the classified results to CSV."""
    kwargs = {"ollama_url": url, "safe_threshold": threshold}
    if fast:
        kwargs["fast_model"] = fast
    scanner = EmailScanner(**kwargs)
    if strong:
        scanner.strong_model = strong

    start = time.time()
    results = scanner.scan_mbox(
        str(mbox), limit, from_end=last, verbose=verbose, big_only=big_only
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
