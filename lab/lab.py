"""Command-line entry point for the cybersecurity research lab."""

import sys
from pathlib import Path


if __package__ in (None, ""):
    # Support direct execution from the source tree.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from lab.cli import main
else:
    from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())