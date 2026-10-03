"""Trusted-sender whitelist with spoof-safe exact / subdomain matching.

Why not ``domain in sender`` (substring matching)?
    It is a spoofing hole: ``mermaidcha[rt.com]`` passes an ``rt.com``
    entry, ``buy-cheap-apple.com`` passes ``apple.com``, and a hostile
    actor who knows your whitelist can buy a domain that merely *contains*
    a trusted string.  We therefore extract the real domain after ``@``
    and require either an exact match or a dot-boundary subdomain match
    (``mail.youtube.com`` -> ``youtube.com``, but ``evil-youtube.com`` -> no).
"""

from __future__ import annotations

import os
import re
from typing import List, Optional, Sequence

# Curated base entries (always active)
BASE_WHITELIST_DOMAINS: Sequence[str] = (
    "youtube.com",
    "linkedin.com",
    "accountprotection.microsoft.com",
    # approved false-positive fixes:
    "google.com",
    "twitter.com",
    "samsung-mail.com",
    "skype.com",
    "blackberry.com",
    "degoo.com",
)

_HERE = os.path.dirname(os.path.abspath(__file__))
# Shipped with the repo (offline-first); also accepted at repo root.
_RSPAMD_CANDIDATES = (
    os.path.join(_HERE, "whitelist_rspamd.txt"),
    os.path.join(os.path.dirname(_HERE), "whitelist_rspamd.txt"),
)


def load_domain_file(path: str) -> List[str]:
    """Read a one-domain-per-line file; ``#`` comments are ignored."""
    domains: List[str] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                domains.append(domain)
    return domains


def build_whitelist(extra_files: Sequence[str] = ()) -> List[str]:
    """Base curated list + shipped file(s) (Rspamd DMARC), deduplicated."""
    domains: List[str] = []

    def _add(items: Sequence[str]) -> None:
        for item in items:
            if item not in domains:
                domains.append(item)

    _add(BASE_WHITELIST_DOMAINS)
    for candidate in tuple(_RSPAMD_CANDIDATES) + tuple(extra_files):
        if os.path.exists(candidate):
            _add(load_domain_file(candidate))
    return domains


def sender_domain(sender: str) -> str:
    """Extract the mail domain after ``@`` from ``Name <a@b.c>`` or bare addresses."""
    match = re.search(r"<([^>]+)>", sender or "")
    address = match.group(1).lower() if match else (sender or "").lower()
    return address.split("@")[-1]


def match_domain(sender: str, domains: Sequence[str]) -> Optional[str]:
    """Return the whitelist entry the sender exactly/suffix-matches, else ``None``.

    Fixes the substring-matching spoofing hole: an attacker-owned
    ``buy-cheap-apple.com`` or ``mermaidcha-rt.com`` no longer passes the
    whitelist entries ``apple.com`` / ``rt.com``.
    """
    domain = sender_domain(sender)
    for entry in domains:
        if domain == entry or domain.endswith("." + entry):
            return entry
    return None
