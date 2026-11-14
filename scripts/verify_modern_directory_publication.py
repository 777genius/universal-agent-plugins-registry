#!/usr/bin/env python3
"""Verify the modern Directory using its fixed reviewed public trust."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
if __package__:
    from .directory_feed_contract import MODERN_FEED
    from .verify_directory_publication import main
else:
    from directory_feed_contract import MODERN_FEED
    from verify_directory_publication import main

if __name__ == "__main__":
    raise SystemExit(main(feed=MODERN_FEED))
