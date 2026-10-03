"""Ollama `/v1/systemone` client and scan orchestration.

Single-pass design (simple and GPU-friendly - only ONE model ever loads):

    mbox -> exact/subdomain whitelist -> (trusted? Safe instantly)
                                |
                          (suspicious)
                                v
                     strong model decides: Safe / Spam / Phishing

The whitelist answers in ~1ms with no GPU; the strong model (default
``clef-flash-4k``) is loaded lazily on the first non-whitelisted email
and unloaded when the scan finishes.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import time
from collections import Counter
from typing import Dict, List, Optional

import requests
from tqdm import tqdm

from . import extract
from . import whitelist as wl

DEFAULT_OLLAMA_URL = "http://localhost:11434/v1/systemone"
DEFAULT_STRONG_MODEL = "clef-flash-4k"
CLASSIFICATION_OPTIONS = ("Safe", "Spam", "Phishing")


class EmailScanner:
    def __init__(
        self,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        strong_model: str = DEFAULT_STRONG_MODEL,
        whitelist_domains: Optional[List[str]] = None,
    ):
        self.ollama_url = ollama_url
        self.strong_model = strong_model
        self.options = list(CLASSIFICATION_OPTIONS)
        self.max_text_length = extract.MAX_TEXT_LENGTH

        # Trusted senders - never sent to any model (saves time).
        # Matching is EXACT / subdomain only (see whitelist.match_domain).
        self.WHITELIST_DOMAINS = tuple(wl.BASE_WHITELIST_DOMAINS)
        self.whitelist_domains = (
            list(whitelist_domains) if whitelist_domains is not None
            else wl.build_whitelist()
        )

    # ------------------------------------------------------------------ util
    def clean_html(self, html_content: str) -> str:
        return extract.clean_html(html_content)

    @staticmethod
    def _safe_decode(payload: bytes, charset: str) -> str:
        return extract.safe_decode(payload, charset)

    def extract_email_parts(self, message) -> Dict[str, str]:
        return extract.extract_email_parts(message)

    def truncate_text(self, text: str) -> str:
        return extract.hard_truncate(text, self.max_text_length)

    def _whitelist_domain(self, sender: str) -> Optional[str]:
        """Return the matched whitelist domain if the sender is trusted."""
        return wl.match_domain(sender, self.whitelist_domains)

    @staticmethod
    def _whitelist_row(email: Dict, domain: str) -> Dict:
        """Immediate Safe row for a whitelisted sender (no model call)."""
        return {
            "email_index": email["index"],
            "sender": email["sender"],
            "subject": email["subject"],
            "classification": "Safe",
            "probabilities": {"Safe": 1.0},
            "model": f"whitelist({domain})",
            "score": 1.0,
            "confidence": 1.0,
        }

    # -------------------------------------------------------------- Ollama I/O
    def _send_decision(self, model: str, email_text: str) -> Optional[Dict]:
        """POST one decision request to /v1/systemone and parse the answer."""
        # Smart truncation (Head & Tail) - keeps BOTH ends so notification
        # emails don't lose their verdict/subject sitting at the tail.
        text = extract.smart_truncate(email_text)

        payload = {
            "model": model,
            "state": {"email": text},
            "questions": {
                "classification": {
                    "type": "choice",
                    "instructions": "Classify this email based on its content.",
                    "criteria": {
                        "Safe": "Normal communication or newsletter",
                        "Spam": "Unsolicited promotional content",
                        "Phishing": "Malicious attempt to steal data or credentials",
                    },
                }
            },
            "options": {"num_ctx": 2048},  # limit KV cache pre-allocation
        }

        try:
            response = requests.post(self.ollama_url, json=payload, timeout=30)
            if response.status_code != 200:
                print(f"Error calling Ollama API ({model}): "
                      f"{response.status_code} - {response.text[:200]}",
                      file=sys.stderr)
                return None
            data = response.json()

            answer = data["answers"]["classification"]
            choice = answer["choice"]
            probabilities = answer["probabilities"]
            # Probability of the chosen classification
            score = probabilities.get(choice, answer.get("confidence", 0.0))
            return {
                "classification": choice,
                "probabilities": probabilities,
                "confidence": answer.get("confidence", 0.0),
                "score": score,
                "model": model,
            }
        except (requests.exceptions.RequestException, json.JSONDecodeError,
                KeyError, IndexError) as exc:
            print(f"Error calling Ollama API ({model}): {exc}", file=sys.stderr)
            return None

    def _send_decision_with_retry(self, model: str, email_text: str,
                                  retries: int = 5) -> Optional[Dict]:
        """Retry on connection errors.

        Ollama runners may restart under memory pressure (model reload takes
        ~5-15s), so use exponential backoff: 1s, 2s, 4s, 8s, 8s (23s total).
        """
        for attempt in range(retries):
            result = self._send_decision(model, email_text)
            if result is not None:
                return result
            if attempt < retries - 1:
                wait = min(2 ** attempt, 8)  # 1, 2, 4, 8, 8
                print(f"  Retrying {model} in {wait}s "
                      f"(attempt {attempt + 2}/{retries})...", file=sys.stderr)
                time.sleep(wait)
        return None

    @staticmethod
    def _stop_model(model: str) -> None:
        """Unload a model to free VRAM before loading the next one."""
        try:
            subprocess.run(["ollama", "stop", model], timeout=20,
                           capture_output=True, check=False)
        except Exception:  # noqa: BLE001 - best effort only
            pass

    # ---------------------------------------------------------------- decides
    def classify_email(self, email_text: str, verbose: bool = False) -> Optional[Dict]:
        """Single decision from the strong model (whitelist is checked upstream)."""
        result = self._send_decision_with_retry(self.strong_model, email_text)
        if verbose and result:
            print(f"[Model: {result['model']}] - Confidence: "
                  f"{result.get('confidence', 0.0):.0%} - "
                  f"Result: {result['classification']}")
        return result

    @staticmethod
    def _make_row(email: Dict, result: Optional[Dict]) -> Dict:
        """Build a results-row dict from an email + (optional) model result."""
        if result:
            return {
                "email_index": email["index"],
                "sender": email["sender"],
                "subject": email["subject"],
                "classification": result.get("classification", "Unknown"),
                "probabilities": result.get("probabilities", {}),
                "model": result.get("model", "Unknown"),
                "score": result.get("score", 0.0),
                "confidence": result.get("confidence", 0.0),
            }
        return {
            "email_index": email["index"],
            "sender": email["sender"],
            "subject": email["subject"],
            "classification": "Error",
            "probabilities": {},
            "model": "N/A",
            "score": 0.0,
            "confidence": 0.0,
        }

    # ------------------------------------------------------------------ scan
    def _load_emails(self, mbox_path: str, limit: int, from_end: bool) -> List[Dict]:
        return extract.load_emails(mbox_path, limit, from_end,
                                   self.max_text_length)

    def scan_mbox(self, mbox_path: str, limit: int = 5, from_end: bool = False,
                  verbose: bool = False, big_only: bool = False) -> List[Dict]:
        """Single-pass scan: exact/subdomain whitelist, then the strong model.

        big_only: deprecated, ignored. The single-model flow IS the default
        now (kept so legacy ``--big-only`` commands keep working).
        """
        del big_only  # deprecated no-op
        emails = self._load_emails(mbox_path, limit, from_end)
        if not emails:
            return []

        results: List[Optional[Dict]] = [None] * len(emails)
        model_calls = 0

        print(f"\n{'=' * 60}\nSCAN - whitelist filter, then "
              f"{self.strong_model} decides {len(emails)} emails\n"
              f"{'=' * 60}", file=sys.stderr)

        for pos in tqdm(range(len(emails)),
                        desc=f"Scanning ({self.strong_model})",
                        unit="email", file=sys.stderr):
            e = emails[pos]
            if verbose:
                print(f"{'=' * 60}\nEmail #{e['index']}\n{'=' * 60}")
                print(f"From: {e['sender']}\nSubject: {e['subject']}")
                print(f"Body length: {len(e['text'])} characters")

            # Whitelist: trusted senders -> Safe immediately, no model call
            trusted = self._whitelist_domain(e["sender"])
            if trusted:
                if verbose:
                    print(f"  [WHITELIST] {trusted} -> Safe (model skipped)")
                results[pos] = self._whitelist_row(e, trusted)
                continue

            result = self._send_decision_with_retry(self.strong_model,
                                                    e["text"])
            model_calls += 1
            if verbose and result:
                print(f"[Model: {result['model']}] - Confidence: "
                      f"{result.get('confidence', 0.0):.0%} - "
                      f"Result: {result['classification']}")
            elif verbose and not result:
                print(f"  [ERROR] no decision for email #{e['index']}")
            results[pos] = self._make_row(e, result)

        # Free the GPU when the scan is over (only if we actually used it).
        if model_calls:
            self._stop_model(self.strong_model)

        return [r for r in results if r is not None]


def export_csv(results: List[Dict], csv_path: str) -> None:
    """Write results to CSV (utf-8-sig for Excel/Arabic compatibility)."""
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Sender", "Subject", "Final_Decision",
                         "Model_Used", "Probability_Score"])
        for row in results:
            writer.writerow([
                row.get("sender", ""),
                row.get("subject", ""),
                row.get("classification", ""),
                row.get("model", ""),
                f"{row.get('score', 0.0):.4f}",
            ])
    print(f"\nResults exported to: {csv_path}", file=sys.stderr)


def print_summary(scanner: EmailScanner, results: List[Dict],
                  elapsed: float) -> None:
    """Final summary block (counts + decision sources + flagged list)."""
    cls_counts = Counter(r["classification"] for r in results)
    model_counts = Counter(r.get("model", "N/A") for r in results)

    print(f"\n{'=' * 60}")
    print("FINAL SUMMARY")
    print(f"{'=' * 60}")
    print(f"Total scanned : {len(results)} emails")
    print(f"Safe          : {cls_counts['Safe']}")
    print(f"Spam          : {cls_counts['Spam']}")
    print(f"Phishing      : {cls_counts['Phishing']}")
    if cls_counts["Error"]:
        print(f"Errors        : {cls_counts['Error']}")
    print(f"Total time    : {elapsed:.1f}s "
          f"({elapsed / max(len(results), 1):.2f}s/email)")
    print()

    whitelist_count = sum(count for model, count in model_counts.items()
                          if model.startswith("whitelist("))
    model_count = sum(count for model, count in model_counts.items()
                      if not model.startswith("whitelist("))
    total = len(results) or 1
    print("Decision source:")
    print(f"  whitelist (instant, no GPU): "
          f"{whitelist_count} ({whitelist_count / total:.0%})")
    print(f"  {scanner.strong_model}:  "
          f"{model_count} ({model_count / total:.0%})")
    print()

    flagged = [r for r in results if r["classification"] in ("Spam", "Phishing")]
    if flagged:
        print(f"Flagged emails ({len(flagged)}):")
        for row in flagged:
            print(f"  [{row['classification']}] [{row.get('model', '?')}] "
                  f"{row['subject'][:60]}")


def main() -> None:
    """Legacy CLI entry point (plain argv parsing; `phish-scan` is the Typer front-end)."""
    if len(sys.argv) < 2:
        print("Usage: python -m phish_classifier.scanner <mbox> [limit] "
              "[--last] [--verbose] [--strong MODEL] [--csv PATH]")
        print("Examples:")
        print("  python email_scanner.py ~/Takeout/Mail/Inbox.mbox 5        # first 5")
        print("  python email_scanner.py ~/Takeout/Mail/Inbox.mbox 1000 --last  # last 1000")
        print("  python email_scanner.py ~/Takeout/Mail/Inbox.mbox 3000 --last --strong nimble-4k --csv out.csv")
        sys.exit(1)

    mbox_path = sys.argv[1]
    limit = 5
    from_end = False
    verbose = False
    strong_override = None
    csv_override = None

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--last":
            from_end = True
        elif args[i] == "--verbose":
            verbose = True
        elif args[i] == "--big-only":
            # Deprecated no-op: the single-model flow is now the default.
            print("Note: --big-only is deprecated and ignored "
                  "(single-model flow is the default).", file=sys.stderr)
        elif args[i] == "--strong" and i + 1 < len(args):
            strong_override = args[i + 1]
            i += 1
        elif args[i] == "--csv" and i + 1 < len(args):
            csv_override = args[i + 1]
            i += 1
        elif args[i].isdigit():
            limit = int(args[i])
        i += 1

    scanner = EmailScanner()
    if strong_override:
        scanner.strong_model = strong_override

    start_time = time.time()
    results = scanner.scan_mbox(mbox_path, limit, from_end=from_end,
                                verbose=verbose)
    elapsed = time.time() - start_time

    export_csv(results, csv_override or "scan_results_clef.csv")
    print_summary(scanner, results, elapsed)


if __name__ == "__main__":
    main()
