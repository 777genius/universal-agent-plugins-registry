#!/usr/bin/env python3
"""Select the newest approved Directory and feeds for one serial Pages deploy."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

if __package__:
    from . import directory_publication_cas as cas
    from .directory_deployment_contract import ROOT, load_modern_deployment_contract
    from .directory_feed_contract import DirectoryFeedContract, LEGACY_FEED, MODERN_FEED, fixed_feed
    from .directory_publication import PublicationError, parse_timestamp
else:
    import directory_publication_cas as cas
    from directory_deployment_contract import ROOT, load_modern_deployment_contract
    from directory_feed_contract import DirectoryFeedContract, LEGACY_FEED, MODERN_FEED, fixed_feed
    from directory_publication import PublicationError, parse_timestamp

CasError, PROMOTION_INTENT_PREFIX = cas.CasError, cas.PROMOTION_INTENT_PREFIX
_git, _require_sha = cas._git, cas._require_sha
_validate_feed_or_recovery, parse_promotion_intent = cas._validate_feed_or_recovery, cas.parse_promotion_intent
promotion_intent_ref, read_ref_state = cas.promotion_intent_ref, cas.read_ref_state
validate_materialized_descendant = cas.validate_materialized_descendant
validate_signed_directory_append = cas.validate_signed_directory_append


LEDGER_REF = "refs/heads/directory-publication-ledger"
PRODUCTION_REF = "refs/tags/directory-publication-schema-1-production"
TERMINAL_DEPLOYMENT_STATES = {"success", "failure", "error", "inactive"}
COMPOSITOR_JOB_NAME = "Serialize, authenticate, and deploy the latest approved composition"
INTENT_CREATION_RULESET = "Directory promotion intent publisher creation"
INTENT_IMMUTABLE_RULESET = "Directory promotion intent immutable"
DIRECTORY_PUBLISHER_APP_ID = 4684827


@dataclass(frozen=True)
class CompositionPlan:
    ledger_head: str
    directory_commit: str
    signed_commit: str
    sequence: int
    intent_ref: str | None
    intent_oid: str | None
    production_marker: str | None


@dataclass(frozen=True)
class CombinedCompositionPlan:
    legacy: CompositionPlan
    modern: CompositionPlan
    tree: str
    references_digest: str


def _combined_references(repo: Path, remote: str) -> dict[str, str]:
    patterns = [ref for feed in (LEGACY_FEED, MODERN_FEED)
                for ref in (feed.ledger_ref, feed.production_ref, feed.intent_ref_prefix + "*")]
    result = _git(repo, ["ls-remote", "--refs", remote, *patterns])
    references: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            raise CasError("combined composition returned malformed refs")
        oid, ref = fields
        _require_sha(oid, ref)
        if ref in references or not any(
            ref in (feed.ledger_ref, feed.production_ref)
            or re.fullmatch(re.escape(feed.intent_ref_prefix) + r"[0-9]{20}", ref)
            for feed in (LEGACY_FEED, MODERN_FEED)
        ):
            raise CasError("combined composition returned duplicate or unexpected refs")
        references[ref] = oid
    return references


def _overlay_modern_tree(repo: Path, base: str, modern: str) -> str:
    """Replace exactly the modern feed subtree, preserving every sibling byte."""
    donor = _git(repo, ["rev-parse", f"{modern}:{MODERN_FEED.feed_path}"]).stdout.strip()
    if _git(repo, ["cat-file", "-t", donor]).stdout.strip() != "tree":
        raise CasError("modern feed must be a real Git tree")
    for entry in _git(repo, ["ls-tree", "-r", donor]).stdout.splitlines():
        fields = entry.split(None, 3)
        if (len(fields) != 4 or fields[0:2] != ["100644", "blob"]
                or re.fullmatch(r"(?:latest\.json|ledger-contract\.json|snapshots/[0-9]{20}(?:\.envelope)?\.json)", fields[3]) is None):
            raise CasError("modern feed contains a non-public or non-regular artifact")

    def replace(tree: str | None, parts: list[bytes]) -> str:
        entries = cas._root_entries(repo, tree) if tree is not None else {}
        name = parts[0]
        if len(parts) == 1:
            child = donor
        else:
            previous = entries.get(name)
            header = previous.partition(b"\t")[0].split() if previous is not None else []
            if previous is not None and (len(header) != 3 or header[:2] != [b"040000", b"tree"]):
                raise CasError("composition ancestor is not a regular Git tree")
            child = replace(header[2].decode("ascii") if header else None, parts[1:])
        entries[name] = b"040000 tree " + child.encode("ascii") + b"\t" + name
        return cas._write_tree_entries(repo, entries)

    return replace(base, [part.encode("ascii") for part in MODERN_FEED.feed_path.split("/")])


def combine_composition(repo: Path, remote: str) -> CombinedCompositionPlan:
    """Compose two fixed authorities; never deploy the modern ledger wholesale."""
    load_modern_deployment_contract()  # No silent legacy-only fallback.
    before = _combined_references(repo, remote)
    legacy = select_composition(repo, remote, ROOT / LEGACY_FEED.deployment_contract_path)
    modern = select_composition(repo, remote, feed=MODERN_FEED)
    base = cas._replace_root_entries(repo, legacy.directory_commit, legacy.ledger_head,
                                     {b"discovery", b"security"})
    tree = _overlay_modern_tree(repo, base, modern.directory_commit)
    after = _combined_references(repo, remote)
    if before != after:
        raise CasError("combined composition became stale during selection")
    digest = "sha256:" + hashlib.sha256(json.dumps(after, sort_keys=True).encode("utf-8")).hexdigest()
    return CombinedCompositionPlan(legacy, modern, tree, digest)


def read_combined_plan(path: Path) -> CombinedCompositionPlan:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or set(value) != {"legacy", "modern", "tree", "references_digest"}:
        raise CasError("combined composition plan has invalid fields")
    return CombinedCompositionPlan(CompositionPlan(**value["legacy"]), CompositionPlan(**value["modern"]),
                                   value["tree"], value["references_digest"])


def require_current_combined_composition(repo: Path, remote: str, previous: CombinedCompositionPlan) -> None:
    if combine_composition(repo, remote) != previous:
        raise CasError("combined composition became stale before external deploy")


def _remote_refs(repo: Path, remote: str, *, feed: DirectoryFeedContract = LEGACY_FEED) -> dict[str, str]:
    fixed_feed(feed)
    result = _git(repo, ["ls-remote", "--refs", remote, feed.ledger_ref, feed.production_ref,
                         f"{feed.intent_ref_prefix}*"])
    refs: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            raise CasError("remote returned a malformed Pages ref line")
        oid, ref = parts
        _require_sha(oid, ref)
        if ref in refs:
            raise CasError("remote returned a duplicate Pages ref")
        if ref not in (feed.ledger_ref, feed.production_ref) and not ref.startswith(feed.intent_ref_prefix):
            raise CasError("remote returned an unexpected Pages ref")
        refs[ref] = oid
    if feed.ledger_ref not in refs:
        raise CasError("production ledger branch is absent")
    return refs


def _fetch_commit(repo: Path, remote: str, oid: str) -> None:
    _require_sha(oid, "remote Pages commit")
    _git(repo, ["fetch", "--no-tags", remote, oid])
    if _git(repo, ["cat-file", "-t", oid]).stdout.strip() != "commit":
        raise CasError("remote Pages object is not a commit")


def _sequence(repo: Path, signed: str, *, feed: DirectoryFeedContract = LEGACY_FEED) -> int:
    fixed_feed(feed)
    latest = json.loads(_git(repo, ["show", f"{signed}:{feed.feed_path}/latest.json"]).stdout)
    sequence = latest.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or not 1 <= sequence <= 9_007_199_254_740_991:
        raise CasError("Directory sequence is invalid")
    return sequence


def _require_sequence_tag(
    repo: Path, remote: str, signed: str, sequence: int, *, feed: DirectoryFeedContract = LEGACY_FEED,
) -> None:
    fixed_feed(feed)
    tag = f"{feed.sequence_ref_prefix}{sequence:020d}"
    observed = read_ref_state(repo, remote, "refs/heads/__unused-main", "refs/heads/__unused-ledger", tag).sequence_tag
    if observed != signed:
        raise CasError("Directory sequence tag does not name the signed commit")


def _validate_later_ledger(
    repo: Path, remote: str, directory: str, head: str, *, feed: DirectoryFeedContract = LEGACY_FEED,
) -> None:
    fixed_feed(feed)
    if _git(repo, ["merge-base", "--is-ancestor", directory, head], check=False).returncode != 0:
        raise CasError("approved Directory is not in the current ledger lineage")
    previous = directory
    pending_signed = False
    for descendant in _git(repo, ["rev-list", "--reverse", "--ancestry-path", f"{directory}..{head}"]).stdout.splitlines():
        if _git(repo, ["show", "-s", "--format=%P", descendant]).stdout.strip().split() != [previous]:
            raise CasError("Pages ledger history is not linear")
        message = _git(repo, ["show", "-s", "--format=%B", descendant]).stdout
        if pending_signed:
            validate_materialized_descendant(repo, descendant, previous, feed=feed)
            pending_signed = False
        elif message == "chore(directory): publish signed snapshot\n\n":
            sequence = _sequence(repo, descendant, feed=feed)
            _require_sequence_tag(repo, remote, descendant, sequence, feed=feed)
            validate_signed_directory_append(
                repo, previous, descendant,
                f"{feed.sequence_ref_prefix}{sequence:020d}", feed=feed,
            )
            pending_signed = True
        else:
            if feed is MODERN_FEED:
                raise CasError("modern ledger contains a foreign feed append")
            match = re.fullmatch(r"chore\((discovery|security)\): publish sequence ([1-9][0-9]*)\n\n", message)
            if match is None:
                raise CasError("Pages ledger contains an unsupported append")
            _validate_feed_or_recovery(repo, remote, previous, descendant)
            index_feed, raw_sequence = match.groups()
            tag = f"refs/tags/{index_feed}-index-sequence-{int(raw_sequence):020d}"
            observed = read_ref_state(
                repo, remote, "refs/heads/__unused-main", "refs/heads/__unused-ledger", tag,
            ).sequence_tag
            if observed != descendant:
                raise CasError("feed sequence tag does not name its ledger append")
        previous = descendant
    if pending_signed:
        raise CasError("Pages ledger ends at an unmaterialized signed commit")


def select_composition(
    repo: Path, remote: str, contract: Path | None = None, *, feed: DirectoryFeedContract = LEGACY_FEED,
) -> CompositionPlan:
    """Re-read after the Pages lock; older queued callers never pin older bytes."""
    fixed_feed(feed)
    if feed is MODERN_FEED:
        if contract is not None:
            raise CasError("modern composition uses only its fixed reviewed deployment contract")
        config = load_modern_deployment_contract()
    else:
        config = json.loads(contract.read_text(encoding="utf-8"))
    if config.get("marker_ref") != feed.production_ref:
        raise CasError("production marker contract differs from Pages compositor")
    bootstrap = config.get("bootstrap_ledger_commit" if feed is MODERN_FEED else "bootstrap_materialized_commit")
    _require_sha(bootstrap, "bootstrap production commit")
    refs = _remote_refs(repo, remote, feed=feed)
    head = refs[feed.ledger_ref]
    marker = refs.get(feed.production_ref, None if feed is MODERN_FEED else bootstrap)
    _fetch_commit(repo, remote, head)
    if marker is not None:
        _fetch_commit(repo, remote, marker)
    _fetch_commit(repo, remote, bootstrap)
    if _git(repo, ["merge-base", "--is-ancestor", marker or bootstrap, head], check=False).returncode != 0:
        raise CasError("production marker is not in current ledger lineage")
    intents: list[tuple[int, str, str]] = []
    for ref, oid in refs.items():
        if ref.startswith(feed.intent_ref_prefix):
            match = re.fullmatch(re.escape(feed.intent_ref_prefix) + r"([0-9]{20})", ref)
            if match is None:
                raise CasError("malformed protected promotion intent ref")
            intents.append((int(match.group(1)), ref, oid))
    intents.sort()
    selected = marker
    signed = _git(repo, ["rev-parse", f"{marker}^"]).stdout.strip() if marker is not None else None
    chosen_ref: str | None = None
    chosen_oid: str | None = None
    previous_intent = bootstrap
    approved_targets: set[str] = set()
    for sequence, ref, oid in intents:
        _require_sha(oid, "remote promotion intent")
        _git(repo, ["fetch", "--no-tags", remote, oid])
        intent = parse_promotion_intent(repo, ref, oid, feed=feed)
        target = str(intent["materialized"])
        if intent["sequence"] != sequence:
            raise CasError("promotion intent sequence is inconsistent")
        if _git(repo, ["merge-base", "--is-ancestor", previous_intent, target], check=False).returncode != 0:
            raise CasError("promotion intents are not monotonic")
        _require_sequence_tag(repo, remote, str(intent["signed"]), sequence, feed=feed)
        approved_targets.add(target)
        previous_intent = target
        selected = target
        signed = str(intent["signed"])
        chosen_ref = ref
        chosen_oid = oid
    if feed is MODERN_FEED and (selected is None or not intents or (marker is not None and marker not in approved_targets)):
        raise CasError("modern publication requires an approved immutable intent; a seed is not production")
    if marker is not None and intents and _git(repo, ["merge-base", "--is-ancestor", selected, marker], check=False).returncode == 0:
        # Historical intents remain immutable after the production marker has
        # caught up. A late old tag cannot select an older site.
        selected = marker
        signed = _git(repo, ["rev-parse", f"{marker}^"]).stdout.strip()
        chosen_ref = None
        chosen_oid = None
    elif marker is not None and _git(repo, ["merge-base", "--is-ancestor", marker, selected], check=False).returncode != 0:
        raise CasError("latest intent and production marker diverge")
    if _git(repo, ["merge-base", "--is-ancestor", selected, head], check=False).returncode != 0:
        raise CasError("selected Directory intent is outside current ledger")
    sequence = _sequence(repo, signed, feed=feed)
    _require_sequence_tag(repo, remote, signed, sequence, feed=feed)
    validate_materialized_descendant(repo, selected, signed, feed=feed)
    lineage_start = bootstrap if feed is MODERN_FEED else selected
    _validate_later_ledger(repo, remote, lineage_start, head, feed=feed)
    return CompositionPlan(head, selected, signed, sequence, chosen_ref, chosen_oid, marker)


def require_current_composition(
    repo: Path, remote: str, contract: Path | None, previous: CompositionPlan,
    *, feed: DirectoryFeedContract = LEGACY_FEED,
) -> None:
    current = select_composition(repo, remote, contract, feed=feed)
    if current != previous:
        raise CasError("Pages composition became stale before external deploy")


def require_current_feed_freshness(
    ledger: Path, now: datetime | None = None, *, minimum_validity_seconds: int = 0,
) -> None:
    """The Security signature verifier does not itself enforce expiry."""
    if not 0 <= minimum_validity_seconds <= 900:
        raise CasError("feed minimum validity window is invalid")
    current = now or datetime.now(timezone.utc)
    for feed in ("discovery", "security"):
        pointer = ledger / feed / "latest.json"
        if not pointer.exists():
            if feed == "discovery":
                raise CasError("current Discovery feed is absent")
            continue
        latest = json.loads(pointer.read_bytes())
        relative = latest.get("snapshot_path")
        if not isinstance(relative, str) or re.fullmatch(r"snapshots/[0-9]{20}\.json", relative) is None:
            raise CasError(f"{feed} latest pointer has an unsafe snapshot path")
        snapshot = json.loads((ledger / feed / relative).read_bytes())
        generated = parse_timestamp(snapshot["generated_at"], f"{feed}.generated_at")
        expires = parse_timestamp(snapshot["expires_at"], f"{feed}.expires_at")
        if current < generated or current + timedelta(seconds=minimum_validity_seconds) >= expires:
            raise CasError(f"{feed} signed snapshot is not currently valid")


def _gh_json(path: str, token: str) -> object:
    result = subprocess.run(
        ["gh", "api", path], check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env={**os.environ, "GH_TOKEN": token},
    )
    return json.loads(result.stdout)


def _current_compositor_job_id(
    repository: str, token: str, run_id: int, run_attempt: int,
    fetch: Callable[[str, str], object],
) -> int:
    payload = fetch(
        f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}/jobs?per_page=100", token,
    )
    if not isinstance(payload, dict) or not isinstance(payload.get("jobs"), list):
        raise CasError("current Pages job receipt is invalid")
    jobs = payload["jobs"]
    if payload.get("total_count") != len(jobs) or len(jobs) > 100:
        raise CasError("current Pages job receipt is incomplete")
    ids = {
        job["id"] for job in jobs
        if isinstance(job, dict) and isinstance(job.get("id"), int)
        and job.get("run_attempt") == run_attempt
        and isinstance(job.get("name"), str)
        and (job["name"] == COMPOSITOR_JOB_NAME
             or job["name"].endswith(" / " + COMPOSITOR_JOB_NAME))
    }
    if len(ids) != 1:
        raise CasError("current Pages compositor job identity is ambiguous")
    return ids.pop()


def _status_job_id(repository: str, status: dict, run_id: int) -> int | None:
    identity = _status_run_job_ids(repository, status)
    return identity[1] if identity is not None and identity[0] == run_id else None


def _status_run_job_ids(repository: str, status: dict) -> tuple[int, int] | None:
    log_url = status.get("log_url")
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(repository)}/actions/runs/([1-9][0-9]*)/job/([1-9][0-9]*)",
        log_url or "",
    ) if isinstance(log_url, str) else None
    return (int(match.group(1)), int(match.group(2))) if match is not None else None


def _failed_environment_has_no_uncertain_backend(
    repository: str, token: str, status: dict, fetch: Callable[[str, str], object],
) -> bool:
    """A failed environment is safe only before dispatch or after action success."""
    identity = _status_run_job_ids(repository, status)
    if identity is None:
        return False
    run_id, job_id = identity
    job = fetch(f"repos/{repository}/actions/jobs/{job_id}", token)
    if not isinstance(job, dict) or job.get("id") != job_id or job.get("run_id") != run_id:
        return False
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False
    deploy_names = {"Deploy exact ledger tree", "Deploy only the freshly rechecked composition"}
    deployed = [step for step in steps if isinstance(step, dict) and step.get("name") in deploy_names]
    if len(deployed) != 1:
        return False
    step = deployed[0]
    if step.get("status") != "completed":
        return False
    if step.get("conclusion") == "success":
        return True
    # GitHub may stamp started_at even on skipped steps. The completed
    # conclusion, not that administrative timestamp, proves no action ran.
    return step.get("conclusion") == "skipped"


def _cancelled_before_runner(job: object, run_id: int, job_id: int, sha: str) -> bool:
    """Recognize a cancelled Pages job that GitHub never assigned to a runner."""
    return (isinstance(job, dict) and job.get("id") == job_id and job.get("run_id") == run_id
            and job.get("name") == COMPOSITOR_JOB_NAME and job.get("head_sha") == sha
            and job.get("status") == "completed" and job.get("conclusion") == "cancelled"
            and type(job.get("runner_id")) is int and job["runner_id"] == 0
            and job.get("runner_name") == "" and job.get("steps") == [])


def _cancelled_unstarted_pages_job(
    repository: str, token: str, deployment: dict, status: dict,
    fetch: Callable[[str, str], object],
) -> tuple[int, int] | None:
    """Require both a never-assigned job and a cancelled Pages backend."""
    sha = deployment.get("sha")
    identity = _status_run_job_ids(repository, status)
    if (status.get("state") != "error" or identity is None or not isinstance(sha, str)
            or re.fullmatch(r"[0-9a-f]{40}", sha) is None):
        return None
    run_id, job_id = identity
    job = fetch(f"repos/{repository}/actions/jobs/{job_id}", token)
    if not _cancelled_before_runner(job, run_id, job_id, sha):
        return None
    backend = fetch(f"repos/{repository}/pages/deployments/{sha}", token)
    return identity if isinstance(backend, dict) and backend.get("status") == "deployment_cancelled" else None


def _inactive_has_prior_success(
    repository: str, token: str, deployment_id: int, latest: dict,
    fetch: Callable[[str, str], object],
) -> bool:
    """GitHub may inactivate a completed Pages deployment after replacement."""
    latest_id = latest.get("id")
    if not isinstance(latest_id, int) or latest_id < 1:
        return False
    for page in range(1, 11):
        statuses = fetch(
            f"repos/{repository}/deployments/{deployment_id}/statuses?per_page=100&page={page}", token,
        )
        if not isinstance(statuses, list) or not statuses:
            return False
        if page == 1 and (not isinstance(statuses[0], dict) or statuses[0].get("id") != latest_id):
            return False
        for status in statuses:
            if not isinstance(status, dict) or not isinstance(status.get("id"), int):
                return False
            if status["id"] < latest_id and status.get("state") == "success":
                return True
        if len(statuses) < 100:
            return False
    return False


def _backend_cancelled_for_unique_sha(
    repository: str, token: str, deployment: dict,
    fetch: Callable[[str, str], object],
) -> bool:
    """Bind a Pages backend cancellation to one exact environment deployment."""
    deployment_id, sha = deployment.get("id"), deployment.get("sha")
    if not isinstance(deployment_id, int) or not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        return False
    matches = fetch(
        f"repos/{repository}/deployments?sha={sha}&environment=github-pages&per_page=100", token,
    )
    if (not isinstance(matches, list) or len(matches) != 1 or not isinstance(matches[0], dict)
            or matches[0].get("id") != deployment_id or matches[0].get("sha") != sha
            or matches[0].get("environment") != "github-pages"):
        return False
    backend = fetch(f"repos/{repository}/pages/deployments/{sha}", token)
    return isinstance(backend, dict) and backend.get("status") == "deployment_cancelled"


def _verified_deployment_frontier(
    repository: str, token: str, path: Path | None,
    fetch: Callable[[str, str], object], checkpoint_repo: Path | None = None,
    current_job: Callable[[], tuple[int, int]] | None = None,
    allowed_current_states: frozenset[str] = frozenset(),
) -> tuple[int | None, int | None]:
    if path is None:
        return None, None
    if checkpoint_repo is not None:
        from pages_deployment_checkpoint import read_checkpoint, require_archived_freshness
        head, frontier_id, archived = read_checkpoint(checkpoint_repo, "origin", path, repository,
                                                      token=token, fetch=fetch)
        if head is not None:
            current_deployment = require_archived_freshness(
                repository, token, archived, fetch, current_job=current_job,
                allowed_current_states=allowed_current_states,
            )
            return frontier_id, current_deployment
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(receipt, dict) or receipt.get("schema_version") != 1
            or receipt.get("repository") != repository or receipt.get("environment") != "github-pages"):
        raise CasError("Pages deployment frontier contract is invalid")
    deployment_id = receipt.get("deployment_id")
    sha = receipt.get("deployment_sha")
    status_id = receipt.get("success_status_id")
    log_url = receipt.get("success_log_url")
    if (not isinstance(deployment_id, int) or deployment_id < 1
            or not isinstance(status_id, int) or status_id < 1
            or not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None
            or not isinstance(log_url, str)
            or _status_run_job_ids(repository, {"log_url": log_url}) is None):
        raise CasError("Pages deployment frontier identity is invalid")
    deployment = fetch(f"repos/{repository}/deployments/{deployment_id}", token)
    status = fetch(f"repos/{repository}/deployments/{deployment_id}/statuses/{status_id}", token)
    if (not isinstance(deployment, dict) or deployment.get("id") != deployment_id
            or deployment.get("sha") != sha or deployment.get("environment") != "github-pages"
            or not isinstance(status, dict) or status.get("id") != status_id
            or status.get("state") != "success" or status.get("log_url") != log_url):
        raise CasError("Pages deployment frontier no longer has exact success evidence")
    return deployment_id, None


def require_terminal_previous_deployments(
    repository: str, token: str, *, run_id: int | None = None,
    run_attempt: int | None = None, frontier: Path | None = None,
    checkpoint_repo: Path | None = None,
    fetch: Callable[[str, str], object] = _gh_json,
) -> None:
    """A cancelled runner can leave an external Pages deployment in flight."""
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise CasError("GitHub repository identity is invalid")
    if not token:
        raise CasError("GitHub API token is missing")
    if (run_id is None) != (run_attempt is None) or (run_id is not None and (run_id < 1 or run_attempt < 1)):
        raise CasError("current Pages run identity is incomplete")
    self_deployment: int | None = None
    current_job_id: int | None = None

    def job_in_current_attempt() -> int:
        nonlocal current_job_id
        if current_job_id is None:
            current_job_id = _current_compositor_job_id(repository, token, run_id, run_attempt, fetch)
        return current_job_id

    frontier_id, archived_self = _verified_deployment_frontier(
        repository, token, frontier, fetch, checkpoint_repo,
        current_job=(lambda: (run_id, job_in_current_attempt())) if run_id is not None else None,
        allowed_current_states=frozenset({"queued", "waiting", "pending", "in_progress"}),
    )

    for page in range(1, 101):
        deployments = fetch(
            f"repos/{repository}/deployments?environment=github-pages&per_page=100&page={page}", token,
        )
        if not isinstance(deployments, list):
            raise CasError("GitHub deployments response is invalid")
        ids: list[int] = []
        for deployment in deployments:
            if not isinstance(deployment, dict) or deployment.get("environment") != "github-pages":
                raise CasError("GitHub returned an unexpected Pages deployment")
            deployment_id = deployment.get("id")
            if not isinstance(deployment_id, int) or deployment_id < 1:
                raise CasError("GitHub Pages deployment ID is invalid")
            if frontier_id is None or deployment_id > frontier_id or deployment_id == archived_self:
                ids.append(deployment_id)

        def latest_status(deployment_id: int) -> object:
            return fetch(f"repos/{repository}/deployments/{deployment_id}/statuses?per_page=1", token)

        with ThreadPoolExecutor(max_workers=8) as pool:
            status_results = list(pool.map(latest_status, ids))
        by_id = {item["id"]: item for item in deployments}
        for deployment_id, statuses in zip(ids, status_results, strict=True):
            if not isinstance(statuses, list) or len(statuses) != 1 or not isinstance(statuses[0], dict):
                raise CasError(f"Pages deployment {deployment_id} has no terminal receipt")
            state = statuses[0].get("state")
            if state == "inactive":
                if not _inactive_has_prior_success(repository, token, deployment_id, statuses[0], fetch):
                    raise CasError(f"Pages deployment {deployment_id} has uncertain external backend state")
            elif state in {"failure", "error"}:
                if (not _failed_environment_has_no_uncertain_backend(repository, token, statuses[0], fetch)
                        and not _backend_cancelled_for_unique_sha(repository, token, by_id[deployment_id], fetch)
                        and not _cancelled_unstarted_pages_job(repository, token, by_id[deployment_id], statuses[0], fetch)):
                    raise CasError(f"Pages deployment {deployment_id} has uncertain external backend state")
            elif state not in TERMINAL_DEPLOYMENT_STATES:
                if (run_id is None or _status_job_id(repository, statuses[0], run_id)
                        != job_in_current_attempt()):
                    raise CasError(f"Pages deployment {deployment_id} remains nonterminal: {state}")
                if self_deployment is not None and self_deployment != deployment_id:
                    raise CasError("multiple current-run Pages deployments remain nonterminal")
                self_deployment = deployment_id
        if len(deployments) < 100:
            return
    raise CasError("Pages deployment history exceeded the bounded receipt scan")


def require_successful_current_deployment(
    repository: str, token: str, *, run_id: int, run_attempt: int,
    frontier: Path | None = None, checkpoint_repo: Path | None = None,
    fetch: Callable[[str, str], object] = _gh_json,
) -> str:
    """Bind a protected marker update to this exact successful Pages job."""
    if (re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
            or not token or run_id < 1 or run_attempt < 1):
        raise CasError("current Pages deployment request is invalid")
    job_id = _current_compositor_job_id(repository, token, run_id, run_attempt, fetch)
    frontier_id, archived_self = _verified_deployment_frontier(
        repository, token, frontier, fetch, checkpoint_repo,
        current_job=lambda: (run_id, job_id),
        allowed_current_states=frozenset({"success"}),
    )
    matched: list[tuple[int, str]] = []
    receipts: list[tuple[int, str]] = []
    if checkpoint_repo is not None and _git(checkpoint_repo, [
        "rev-parse", "--verify", "refs/remotes/pages-checkpoint",
    ], check=False).returncode == 0:
        from pages_deployment_checkpoint import archived_receipts
        for archived in archived_receipts(checkpoint_repo):
            deployment_id, state = archived["deployment_id"], archived["status_state"]
            receipts.append((deployment_id, state))
            if _status_job_id(repository, {"log_url": archived["status_log_url"]}, run_id) == job_id:
                matched.append((deployment_id, state))
    for page in range(1, 101):
        deployments = fetch(
            f"repos/{repository}/deployments?environment=github-pages&per_page=100&page={page}", token,
        )
        if not isinstance(deployments, list):
            raise CasError("GitHub deployments response is invalid")
        for deployment in deployments:
            if not isinstance(deployment, dict) or deployment.get("environment") != "github-pages":
                raise CasError("GitHub returned an unexpected Pages deployment")
            deployment_id = deployment.get("id")
            if not isinstance(deployment_id, int) or deployment_id < 1:
                raise CasError("GitHub Pages deployment ID is invalid")
            if frontier_id is not None and deployment_id <= frontier_id and deployment_id != archived_self:
                continue
            statuses = fetch(f"repos/{repository}/deployments/{deployment_id}/statuses?per_page=1", token)
            if not isinstance(statuses, list) or len(statuses) != 1 or not isinstance(statuses[0], dict):
                raise CasError(f"Pages deployment {deployment_id} has no receipt")
            state = statuses[0].get("state")
            if not isinstance(state, str):
                raise CasError(f"Pages deployment {deployment_id} has an invalid state")
            if ((state == "inactive" and not _inactive_has_prior_success(
                repository, token, deployment_id, statuses[0], fetch,
            )) or (state in {"failure", "error"} and not _failed_environment_has_no_uncertain_backend(
                repository, token, statuses[0], fetch,
            ) and not _backend_cancelled_for_unique_sha(repository, token, deployment, fetch)
                    and not _cancelled_unstarted_pages_job(repository, token, deployment, statuses[0], fetch))):
                raise CasError(f"Pages deployment {deployment_id} has uncertain external backend state")
            receipts.append((deployment_id, state))
            if _status_job_id(repository, statuses[0], run_id) == job_id:
                matched.append((deployment_id, state))
        if len(deployments) < 100:
            break
    else:
        raise CasError("Pages deployment history exceeded the bounded receipt scan")
    if len(matched) != 1:
        raise CasError("exact current Pages deployment has no unambiguous success receipt")
    own_id, own_state = matched[0]
    if any(deployment_id != own_id and state not in TERMINAL_DEPLOYMENT_STATES
           for deployment_id, state in receipts):
        raise CasError("another Pages deployment remains nonterminal before marker update")
    newer_success = any(deployment_id > own_id and state == "success" for deployment_id, state in receipts)
    if own_state == "inactive" and newer_success:
        # GitHub deactivates the old successful environment deployment when
        # a newer one succeeds. The action-success job proof was checked above.
        return "superseded"
    if own_state != "success":
        raise CasError("exact current Pages deployment has no unambiguous success receipt")
    if newer_success:
        return "superseded"
    return "current"


def require_protected_intent_policy(
    repository: str, token: str, *, fetch: Callable[[str, str], object] = _gh_json,
    feed: DirectoryFeedContract = LEGACY_FEED,
) -> None:
    """Treat intent tags as approval only while exact owner rulesets are active."""
    fixed_feed(feed)
    app_id = DIRECTORY_PUBLISHER_APP_ID
    prefix = ""
    if feed is MODERN_FEED:
        app_id = load_modern_deployment_contract()["publisher_app_id"]
        prefix = "Modern "
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None or not token:
        raise CasError("GitHub intent policy request is invalid")
    summaries = fetch(f"repos/{repository}/rulesets?includes_parents=false", token)
    if not isinstance(summaries, list):
        raise CasError("GitHub intent ruleset listing is invalid")
    required = {
        prefix + INTENT_CREATION_RULESET: (
            {"creation"},
            [{"actor_id": app_id, "actor_type": "Integration", "bypass_mode": "always"}],
        ),
        prefix + INTENT_IMMUTABLE_RULESET: ({"update", "deletion"}, []),
    }
    for name, (expected_rules, expected_bypass) in required.items():
        matching = [item for item in summaries if isinstance(item, dict) and item.get("name") == name]
        if len(matching) != 1 or not isinstance(matching[0].get("id"), int):
            raise CasError(f"required intent ruleset is missing or ambiguous: {name}")
        detail = fetch(f"repos/{repository}/rulesets/{matching[0]['id']}", token)
        if not isinstance(detail, dict):
            raise CasError(f"intent ruleset detail is invalid: {name}")
        conditions = detail.get("conditions")
        ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
        rules = detail.get("rules")
        actual_rules = {rule.get("type") for rule in rules} if isinstance(rules, list) and all(isinstance(rule, dict) for rule in rules) else None
        if (detail.get("id") != matching[0]["id"] or detail.get("name") != name
                or detail.get("source_type") != "Repository" or detail.get("source") != repository
                or detail.get("target") != "tag" or detail.get("enforcement") != "active"
                or ref_name != {"include": [f"{feed.intent_ref_prefix}*"], "exclude": []}
                or actual_rules != expected_rules):
            raise CasError(f"intent ruleset does not enforce the approved contract: {name}")
        # GitHub omits bypass_actors for a read-only token. The owner verifies
        # the exact bypass lists at cutover with an administration-capable gh
        # session; an API response that does include them must still match.
        if "bypass_actors" in detail and detail["bypass_actors"] != expected_bypass:
            raise CasError(f"intent ruleset bypass policy differs from owner-approved contract: {name}")


def main(*, feed: DirectoryFeedContract = LEGACY_FEED) -> int:
    fixed_feed(feed)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--repo", type=Path, default=Path.cwd())
    plan.add_argument("--remote", default="origin")
    if feed is LEGACY_FEED:
        plan.add_argument("--contract", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    current = commands.add_parser("require-current")
    current.add_argument("--repo", type=Path, default=Path.cwd())
    current.add_argument("--remote", default="origin")
    if feed is LEGACY_FEED:
        current.add_argument("--contract", type=Path, required=True)
    current.add_argument("--plan", type=Path, required=True)
    receipt = commands.add_parser("require-terminal-deployments")
    receipt.add_argument("--repository", required=True)
    receipt.add_argument("--frontier", type=Path)
    receipt.add_argument("--checkpoint-repo", type=Path)
    successful = commands.add_parser("require-successful-deployment")
    successful.add_argument("--repository", required=True)
    successful.add_argument("--frontier", type=Path)
    successful.add_argument("--checkpoint-repo", type=Path)
    policy = commands.add_parser("require-intent-policy")
    policy.add_argument("--repository", required=True)
    freshness = commands.add_parser("require-feed-freshness")
    freshness.add_argument("--ledger-path", type=Path, required=True)
    freshness.add_argument("--minimum-validity-seconds", type=int, default=0)
    args = parser.parse_args()
    try:
        if feed is MODERN_FEED:
            load_modern_deployment_contract()
        if args.command == "plan":
            selected = (combine_composition(args.repo, args.remote) if feed is MODERN_FEED
                        else select_composition(args.repo, args.remote, args.contract))
            args.output.write_text(json.dumps(asdict(selected), sort_keys=True) + "\n", encoding="utf-8")
        elif args.command == "require-current":
            if feed is MODERN_FEED:
                require_current_combined_composition(args.repo, args.remote, read_combined_plan(args.plan))
            else:
                previous = CompositionPlan(**json.loads(args.plan.read_text(encoding="utf-8")))
                require_current_composition(args.repo, args.remote, args.contract, previous)
        elif args.command == "require-terminal-deployments":
            raw_run = os.environ.get("GITHUB_RUN_ID")
            raw_attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
            require_terminal_previous_deployments(
                args.repository, os.environ.get("GH_TOKEN", ""),
                run_id=int(raw_run) if raw_run else None,
                run_attempt=int(raw_attempt) if raw_attempt else None,
                frontier=args.frontier,
                checkpoint_repo=args.checkpoint_repo,
            )
        elif args.command == "require-feed-freshness":
            require_current_feed_freshness(
                args.ledger_path, minimum_validity_seconds=args.minimum_validity_seconds,
            )
        elif args.command == "require-successful-deployment":
            print(require_successful_current_deployment(
                args.repository, os.environ.get("GH_TOKEN", ""),
                run_id=int(os.environ["GITHUB_RUN_ID"]),
                run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
                frontier=args.frontier,
                checkpoint_repo=args.checkpoint_repo,
            ))
        else:
            require_protected_intent_policy(args.repository, os.environ.get("GH_TOKEN", ""))
            if feed is MODERN_FEED:
                require_protected_intent_policy(args.repository, os.environ.get("GH_TOKEN", ""), feed=feed)
    except (CasError, KeyError, OSError, ValueError, PublicationError, subprocess.SubprocessError) as error:
        print(f"pages-compositor: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
