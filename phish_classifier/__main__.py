"""Allow ``python -m phish_classifier`` as an alias for ``phish-scan``."""

from .cli import run

if __name__ == "__main__":
    run()
