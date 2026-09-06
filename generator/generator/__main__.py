"""Container entrypoint: python -m generator"""

from __future__ import annotations

import sys

from generator.runner import run

if __name__ == "__main__":
    sys.exit(run())
