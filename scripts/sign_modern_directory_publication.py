#!/usr/bin/env python3
"""Stage modern schema-1 bytes using only separately provisioned reviewed trust.

No promotion or Pages workflow is connected by this entrypoint.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
if __package__:
    from .directory_feed_contract import MODERN_FEED
    from .sign_directory_publication import main
else:
    from directory_feed_contract import MODERN_FEED
    from sign_directory_publication import main

if __name__ == "__main__":
    raise SystemExit(main(feed=MODERN_FEED))
