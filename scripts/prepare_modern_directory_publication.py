#!/usr/bin/env python3
"""Prepare modern schema-1 data only with separately provisioned reviewed trust.

This trusted entrypoint does not publish, promote, or deploy a production feed.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
if __package__:
    from .directory_feed_contract import MODERN_FEED
    from .prepare_directory_publication import main
else:
    from directory_feed_contract import MODERN_FEED
    from prepare_directory_publication import main

if __name__ == "__main__":
    raise SystemExit(main(feed=MODERN_FEED))
