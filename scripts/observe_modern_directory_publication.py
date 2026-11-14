#!/usr/bin/env python3
"""Observe modern production against an exact, still-current composition plan."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
if __package__:
    from . import directory_publication_cas as cas
    from . import observe_directory_publication as observer
    from .directory_deployment_contract import ROOT, load_modern_deployment_contract
    from .directory_feed_contract import MODERN_FEED
    from .directory_publication import MAX_SNAPSHOT_BYTES, PublicationError, canonical_json, parse_json_bytes, require, sha256_digest
    from .pages_compositor import CombinedCompositionPlan, read_combined_plan, require_current_combined_composition
else:
    import directory_publication_cas as cas
    import observe_directory_publication as observer
    from directory_deployment_contract import ROOT, load_modern_deployment_contract
    from directory_feed_contract import MODERN_FEED
    from directory_publication import MAX_SNAPSHOT_BYTES, PublicationError, canonical_json, parse_json_bytes, require, sha256_digest
    from pages_compositor import CombinedCompositionPlan, read_combined_plan, require_current_combined_composition


def observe_composition(repo: Path, remote: str, plan: CombinedCompositionPlan) -> dict:
    """The selected signed Git object supplies identity; arguments cannot invent it."""
    config = load_modern_deployment_contract()
    require_current_combined_composition(repo, remote, plan)
    selected = plan.modern
    path = f"{selected.signed_commit}:{MODERN_FEED.feed_path}/snapshots/{selected.sequence:020d}.json"
    size = int(cas._git(repo, ["cat-file", "-s", path]).stdout.strip())
    require(0 < size <= MAX_SNAPSHOT_BYTES, "selected modern snapshot exceeds its bound")
    body = cas._git(repo, ["show", path]).stdout.encode("utf-8")
    snapshot = parse_json_bytes(body, "selected modern snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
    require(isinstance(snapshot, dict) and canonical_json(snapshot) == body,
            "selected modern snapshot is not a canonical object")
    expected = {"sequence": selected.sequence, "publication_id": snapshot["publication_id"],
                "source_commit": snapshot["source_commit"], "snapshot_digest": sha256_digest(body)}
    observed = observer.observe_once(config["origin"], ROOT / MODERN_FEED.trusted_keys_path,
                                     selected.sequence, feed=MODERN_FEED)
    require(all(observed.get(key) == value for key, value in expected.items()),
            "modern production differs from the selected signed publication")
    require_current_combined_composition(repo, remote, plan)
    # Private publication receipt, not a new signed Directory wire format.
    return {**observed, "ledger_commit": selected.directory_commit,
            "legacy_ledger_commit": plan.legacy.ledger_head, "composition_tree": plan.tree}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        load_modern_deployment_contract()
        plan = read_combined_plan(args.plan)
        for attempt in range(3):
            try:
                receipt = observe_composition(args.repo, args.remote, plan)
                break
            except (PublicationError, OSError) as error:
                if attempt == 2:
                    raise error
                time.sleep(5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(receipt))
        return 0
    except (cas.CasError, PublicationError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print(f"observe-modern-directory: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
