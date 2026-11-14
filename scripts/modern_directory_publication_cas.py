#!/usr/bin/env python3
"""Use the fixed modern CAS lineage only after public authority is provisioned."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
if __package__:
    from .directory_feed_contract import MODERN_FEED
    from .directory_publication_cas import main
else:
    from directory_feed_contract import MODERN_FEED
    from directory_publication_cas import main

if __name__ == "__main__":
    raise SystemExit(main(feed=MODERN_FEED))
