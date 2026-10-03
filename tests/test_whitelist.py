"""Security-critical tests for the spoof-safe whitelist.

These lock down the exact/subdomain matching contract:
    * substring-spoofed domains MUST be refused (the historic vulnerability),
    * genuine senders (bare + subdomain) MUST still match,
    * shipped file loading must be deterministic and comment-safe.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phish_classifier import whitelist as wl  # noqa: E402


DOMAINS = ["youtube.com", "google.com", "rt.com", "apple.com", "jet.com"]


# --------------------------------------------------------------------- attacks
@pytest.mark.parametrize(
    "sender",
    [
        # classic "buy a domain containing the trusted string" spoofs
        "Evil <info@buy-cheap-apple.com>",
        "Phish <admin@apple.com.evil.net>",
        "Fake <x@notyoutube.com>",
        # the exact incidents found in production data:
        "Mermaid <hello@mermaidchart.com>",          # contains rt.com
        "AJET <ajet@mail.ajet.com>",                 # contains jet.com
        "Typing <support@typing.com>",               # contains ing.com
        "Wix <team@emails.wix.com>",                 # contains x.com
        # subdomain that is NOT under the trusted registrable domain
        "Amazon-TR <auto@amazon.com.tr>",
        "UPS-TR <auto@ups.com.tr>",
        # display-name tricks must not matter
        "YouTube <phish@evil-example.com>",
    ],
)
def test_spoofed_domains_are_refused(sender: str) -> None:
    assert wl.match_domain(sender, DOMAINS) is None


def test_plain_substring_is_not_enough() -> None:
    """`domain in sender` style matching must no longer be possible."""
    sender = "Mermaid <hello@mermaidcha-rt.com>"
    # the naive check would pass - ours must not:
    assert "rt.com" in sender.lower()
    assert wl.match_domain(sender, DOMAINS) is None


# --------------------------------------------------------------------- attacks
@pytest.mark.parametrize(
    ("sender", "expected"),
    [
        ("YouTube <noreply@youtube.com>", "youtube.com"),
        ("YouTube <noreply@mail.youtube.com>", "youtube.com"),   # subdomain
        ("Google <no-reply@accounts.google.com>", "google.com"),
        ("Google <a@plus.google.com>", "google.com"),
        ("bare noreply@youtube.com", "youtube.com"),              # no brackets
        ("Display Name <a@YouTube.COM>", "youtube.com"),          # case
        ('"Weird \\"Name\\"" <b@google.com>', "google.com"),
    ],
)
def test_legit_senders_match(sender: str, expected: str) -> None:
    assert wl.match_domain(sender, DOMAINS) == expected


def test_exact_match_wins_for_full_entry() -> None:
    """A full-host entry matches only that host, not sibling domains."""
    domains = ["accountprotection.microsoft.com"]
    assert wl.match_domain("MS <a@accountprotection.microsoft.com>", domains)
    assert wl.match_domain("MS <a@mail.accountprotection.microsoft.com>", domains)
    assert wl.match_domain("Fake <a@accountprotection.microsoft.com.evil.io>",
                           domains) is None


# --------------------------------------------------------------------- helpers
def test_sender_domain_extraction() -> None:
    assert wl.sender_domain('"Name" <a@B.Example.com>') == "b.example.com"
    assert wl.sender_domain("bare@host.org") == "host.org"
    assert wl.sender_domain("NoAddress") == "noaddress"  # degraded, no crash
    assert wl.sender_domain("") == ""


def test_build_whitelist_dedupes_and_ships_rspamd(tmp_path) -> None:
    base = wl.build_whitelist()
    # base curated entries always present
    assert "youtube.com" in base and "google.com" in base
    # shipped Rspamd file is loaded (repo ships it for offline use)
    assert len(base) > len(wl.BASE_WHITELIST_DOMAINS)
    assert len(base) == len(set(base)), "duplicates found"
    # facebookmail.com comes from the shipped Rspamd DMARC list
    assert "facebookmail.com" in base


def test_load_domain_file_ignores_comments_and_blanks(tmp_path) -> None:
    path = tmp_path / "list.txt"
    path.write_text("# comment\n\nExample.COM\n  spaced.net  \n", encoding="utf-8")
    assert wl.load_domain_file(str(path)) == ["example.com", "spaced.net"]


def test_extra_file_is_merged(tmp_path) -> None:
    path = tmp_path / "extra.txt"
    path.write_text("custom-brand.com\n", encoding="utf-8")
    merged = wl.build_whitelist(extra_files=[str(path)])
    assert "custom-brand.com" in merged
