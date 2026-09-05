#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.directory_publication import PublicationError
from scripts.security_publication import load_latest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--feed", type=Path, required=True)
    parser.add_argument("--trusted-keys", type=Path, required=True)
    args = parser.parse_args()
    try:
        loaded = load_latest(args.feed, args.trusted_keys)
        if loaded is None:
            raise PublicationError("Security latest pointer is missing")
        snapshot, _latest = loaded
        print(f"verified Security sequence {snapshot['sequence']} with {snapshot['coverage']['checked']} checked subjects")
        return 0
    except (PublicationError, OSError, ValueError) as error:
        print(f"Security verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
