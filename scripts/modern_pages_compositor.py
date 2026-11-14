#!/usr/bin/env python3
"""Compose approved legacy/live feeds plus the fixed modern Directory subtree."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
if __package__:
    from .directory_feed_contract import MODERN_FEED
    from .pages_compositor import main
else:
    from directory_feed_contract import MODERN_FEED
    from pages_compositor import main

if __name__ == "__main__":
    raise SystemExit(main(feed=MODERN_FEED))
