"""`python -m diagnostic` entry point.

Thin shim over diagnostic.cli, which holds the single implementation shared with
`python -m main diagnostic ...`.
"""

from __future__ import annotations

from diagnostic.cli import main

if __name__ == "__main__":
    main()
