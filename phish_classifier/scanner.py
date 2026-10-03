"""Ollama `/v1/systemone` client, two-stage cascade and scan orchestration.

Cascade design (GPU-friendly: never two models resident at once):
    Stage 1  fast model screens every non-whitelisted email on its own.
             'Safe' >= threshold is final; everything else is queued.
             The fast model is then UNLOADED -> its memory is freed.
    Stage 2  strong model re-decides only the queued emails, then unloads.

``big_only=True`` -> SINGLE pass: the strong model decides every email
(no cascade, one model stays loaded for the whole run).
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
DEFAULT_FAST_MODEL = "tev1-4k"
DEFAULT_STRONG_MODEL = "clef-flash-4k"
DEFAULT_SAFE_THRESHOLD = 0.58
CLASSIFICATION_OPTIONS = ("Safe", "Spam", "Phishing")


class EmailScanner:
    def __init__(
        self,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        fast_model: str = DEFAULT_FAST_MODEL,
        strong_model: str = DEFAULT_STRONG_MODEL,
        safe_threshold: float = DEFAULT_SAFE_THRESHOLD,
        whitelist_domains: Optional[List[str]] = None,
    ):
        self.ollama_url = ollama_url
        self.fast_model = fast_model
        self.strong_model = strong_model
        # Asymmetric threshold: only "Safe" results >= this value are
        # accepted from the fast model.
        self.safe_threshold = safe_threshold
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

    # ---------------------------------------------------------------- cascade
    def classify_email(self, email_text: str, verbose: bool = False) -> Optional[Dict]:
        """Two-step model cascading with ASYMMETRIC threshold.

        Stage 1 - fast model:
          - If choice == "Safe" AND probability >= safe_threshold => accept.
          - Otherwise (Spam/Phishing at any score, or Safe < threshold) => escalate.
        Stage 2 - strong model: always the final decision.
        """
        # Stage 1: fast model
        result = self._send_decision_with_retry(self.fast_model, email_text)

        if result:
            choice = result["classification"]
            score = result["score"]
            confidence = result.get("confidence", 0.0)
            if choice == "Safe" and score >= self.safe_threshold:
                if verbose:
                    print(f"  [Stage 1 ACCEPTED] {self.fast_model}: {choice} "
                          f"prob={score:.4f} conf={confidence:.4f} "
                          f">= {self.safe_threshold}")
                return result
            if verbose:
                print(f"  [Stage 1 ESCALATE] {self.fast_model}: {choice} "
                      f"prob={score:.4f} conf={confidence:.4f} "
                      f"(threshold={self.safe_threshold}) -> escalating "
                      f"to {self.strong_model}")

        # Stage 2: strong model (final decision regardless of score)
        strong = self._send_decision_with_retry(self.strong_model, email_text)
        if strong:
            return strong

        # Both stages failed; return stage-1 result (if any) as-is.
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
        """Scan in TWO SEQUENTIAL phases - never two models loaded together.

        Phase 1  fast model screens EVERY email on its own.
                 'Safe' >= threshold is final; everything else is queued.
                 Fast model is then UNLOADED -> its leaked RAM is freed.
        Phase 2  strong model re-decides only the queued emails.
                 It is unloaded afterwards too.

        big_only=True  -> SINGLE pass: the strong model decides EVERY email
                          (no cascade, one model stays loaded all run).
        """
        emails = self._load_emails(mbox_path, limit, from_end)
        if not emails:
            return []

        results: List[Optional[Dict]] = [None] * len(emails)

        # ---------------- BIG MODEL ONLY: single pass ----------------
        if big_only:
            print(f"\n{'=' * 60}\nBIG MODEL ONLY - {self.strong_model} deciding "
                  f"all {len(emails)} emails\n{'=' * 60}", file=sys.stderr)
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
                        print(f"  [WHITELIST] {trusted} -> Safe (models skipped)")
                    results[pos] = self._whitelist_row(e, trusted)
                    continue

                result = self._send_decision_with_retry(self.strong_model,
                                                        e["text"])
                if verbose and result:
                    print(f"[Model: {result['model']}] - Confidence: "
                          f"{result.get('confidence', 0.0):.0%} - "
                          f"Result: {result['classification']}")
                results[pos] = self._make_row(e, result)

            return [r for r in results if r is not None]

        escalate: List[int] = []

        # ---------------- PHASE 1: fast model alone ----------------
        print(f"\n{'=' * 60}\nPHASE 1 - {self.fast_model} screening all "
              f"{len(emails)} emails\n{'=' * 60}", file=sys.stderr)

        for pos in tqdm(range(len(emails)), desc=f"Phase 1 ({self.fast_model})",
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
                    print(f"  [WHITELIST] {trusted} -> Safe (models skipped)")
                results[pos] = self._whitelist_row(e, trusted)
                continue

            result = self._send_decision_with_retry(self.fast_model, e["text"])

            if result:
                choice = result["classification"]
                score = result["score"]
                conf = result.get("confidence", 0.0)
                if verbose:
                    print(f"[Model: {result['model']}] - Confidence: {conf:.0%} "
                          f"- Result: {choice}")
                    print(f"Probabilities (prob={score:.4f}, conf={conf:.4f}, "
                          f"Safe threshold={self.safe_threshold}):")
                    for label, prob in result["probabilities"].items():
                        print(f"  {label}: {prob:.4f}")
                    print()

                if choice == "Safe" and score >= self.safe_threshold:
                    results[pos] = self._make_row(e, result)          # FINAL
                else:
                    if verbose:
                        print(f"  [ESCALATE] {choice} prob={score:.4f} "
                              f"(threshold={self.safe_threshold}) -> queued "
                              f"for {self.strong_model}")
                    escalate.append(pos)                               # provisional
                    results[pos] = self._make_row(e, result)
            else:
                escalate.append(pos)                                   # retry later
                results[pos] = self._make_row(e, None)

        # Free the fast model BEFORE loading the big one
        self._stop_model(self.fast_model)

        # ---------------- PHASE 2: strong model alone ----------------
        if escalate:
            print(f"\n{'=' * 60}\nPHASE 2 - {self.strong_model} re-deciding "
                  f"{len(escalate)} escalated emails\n{'=' * 60}", file=sys.stderr)
            for pos in tqdm(escalate, desc=f"Phase 2 ({self.strong_model})",
                            unit="email", file=sys.stderr):
                e = emails[pos]
                strong = self._send_decision_with_retry(self.strong_model, e["text"])
                if strong:
                    if verbose:
                        print(f"  [PHASE 2] #{e['index']} -> "
                              f"{strong['classification']} "
                              f"prob={strong['score']:.4f}")
                    results[pos] = self._make_row(e, strong)           # FINAL
                elif verbose:
                    print(f"  [PHASE 2] #{e['index']} failed - keeping "
                          f"phase-1 result")

            self._stop_model(self.strong_model)
        else:
            print(f"\nNo emails escalated - {self.strong_model} not needed.",
                  file=sys.stderr)

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
    """Final summary block (counts + cascade efficiency + flagged list)."""
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

    fast_count = model_counts.get(scanner.fast_model, 0)
    strong_count = model_counts.get(scanner.strong_model, 0)
    total = len(results) or 1
    print("Cascade efficiency:")
    print(f"  {scanner.fast_model} only (fast path): "
          f"{fast_count} ({fast_count / total:.0%})")
    print(f"  {scanner.strong_model} (escalated):    "
          f"{strong_count} ({strong_count / total:.0%})")
    print()

    flagged = [r for r in results if r["classification"] in ("Spam", "Phishing")]
    if flagged:
        print(f"Flagged emails ({len(flagged)}):")
        for row in flagged:
            print(f"  [{row['classification']}] [{row.get('model', '?')}] "
                  f"{row['subject'][:60]}")


def main() -> None:
    """CLI entry point (argparse-style parsing; typer planned for v0.1)."""
    if len(sys.argv) < 2:
        print("Usage: python -m phish_classifier.scanner <mbox> [limit] "
              "[--last] [--verbose] [--big-only] [--strong MODEL] [--csv PATH]")
        print("Examples:")
        print("  python email_scanner.py ~/Takeout/Mail/Inbox.mbox 5        # first 5")
        print("  python email_scanner.py ~/Takeout/Mail/Inbox.mbox 1000 --last  # last 1000")
        print("  python email_scanner.py ~/Takeout/Mail/Inbox.mbox 19108 --big-only  # strong model only")
        print("  python email_scanner.py ~/Takeout/Mail/Inbox.mbox 3000 --last --strong nimble-4k --csv out.csv")
        sys.exit(1)

    mbox_path = sys.argv[1]
    limit = 5
    from_end = False
    verbose = False
    big_only = False
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
            big_only = True
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
                                verbose=verbose, big_only=big_only)
    elapsed = time.time() - start_time

    export_csv(results, csv_override or "scan_results_clef.csv")
    print_summary(scanner, results, elapsed)


if __name__ == "__main__":
    main()
