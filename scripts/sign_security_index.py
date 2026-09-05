#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.directory_publication import PublicationError, ed25519_private_key
from scripts.security_publication import publish


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--feed", type=Path, required=True)
    parser.add_argument("--trusted-keys", type=Path, required=True)
    parser.add_argument("--publication-id", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    try:
        if re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is None:
            raise PublicationError("source commit must be a full lowercase SHA")
        result = publish(args.candidate, args.feed, args.trusted_keys,
                         ed25519_private_key(os.environ.get("DISCOVERY_ED25519_PRIVATE_KEY", "")),
                         args.key_id, args.publication_id, args.source_commit)
        args.result.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        return 0
    except (PublicationError, OSError, ValueError) as error:
        print(f"Security signing failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
