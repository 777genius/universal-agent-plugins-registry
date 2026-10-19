#!/usr/bin/env python3
"""Persist exact terminal Pages receipts in a protected, append-only Git branch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from directory_publication_cas import CasError, _git, _require_sha


CHECKPOINT_REF = "refs/heads/pages-publication-checkpoints"
CHECKPOINT_PATH = "checkpoint.json"
UPDATE_RULESET = "Pages checkpoint publisher updates"
IMMUTABLE_RULESET = "Pages checkpoint immutable history"
PUBLISHER_APP_ID = 4684827
MAX_PAGES = 100
MAX_RETRIES = 4
RECENT_STATUS_WINDOW = timedelta(days=1)
STATUS_SECOND_SETTLE = timedelta(seconds=3)
SHA = re.compile(r"[0-9a-f]{40}")


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _gh_json(path: str, token: str) -> object:
    result = subprocess.run(["gh", "api", path], env={**os.environ, "GH_TOKEN": token},
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def _baseline(path: Path, repository: str) -> tuple[dict, str]:
    raw = path.read_bytes()
    data = json.loads(raw)
    if (not isinstance(data, dict) or data.get("schema_version") != 1
            or data.get("repository") != repository or data.get("environment") != "github-pages"
            or type(data.get("deployment_id")) is not int or data["deployment_id"] < 1
            or not isinstance(data.get("deployment_sha"), str) or not SHA.fullmatch(data["deployment_sha"])
            or type(data.get("success_status_id")) is not int or data["success_status_id"] < 1
            or not isinstance(data.get("success_log_url"), str)):
        raise CasError("Pages checkpoint bootstrap manifest is invalid")
    return data, "sha256:" + hashlib.sha256(raw).hexdigest()


def require_policy(repository: str, token: str, fetch: Callable[[str, str], object] = _gh_json) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not token:
        raise CasError("Pages checkpoint policy request is invalid")
    summaries = fetch(f"repos/{repository}/rulesets?includes_parents=false", token)
    if not isinstance(summaries, list):
        raise CasError("Pages checkpoint ruleset listing is invalid")
    required = {
        UPDATE_RULESET: ({"creation", "update"}, [{"actor_id": PUBLISHER_APP_ID,
                       "actor_type": "Integration", "bypass_mode": "always"}]),
        IMMUTABLE_RULESET: ({"deletion", "non_fast_forward", "required_linear_history"}, []),
    }
    for name, (rules, bypass) in required.items():
        matches = [s for s in summaries if isinstance(s, dict) and s.get("name") == name]
        if len(matches) != 1 or type(matches[0].get("id")) is not int:
            raise CasError(f"Pages checkpoint ruleset missing or ambiguous: {name}")
        detail = fetch(f"repos/{repository}/rulesets/{matches[0]['id']}", token)
        if not isinstance(detail, dict):
            raise CasError(f"Pages checkpoint ruleset detail invalid: {name}")
        actual = detail.get("rules")
        conditions = detail.get("conditions")
        ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
        actual_types = {r.get("type") for r in actual} if isinstance(actual, list) and all(
            isinstance(r, dict) for r in actual) else None
        if (detail.get("id") != matches[0]["id"] or detail.get("name") != name
                or detail.get("source_type") != "Repository" or detail.get("source") != repository
                or detail.get("target") != "branch" or detail.get("enforcement") != "active"
                or ref_name != {"include": [CHECKPOINT_REF], "exclude": []}
                or actual_types != rules):
            raise CasError(f"Pages checkpoint ruleset contract invalid: {name}")
        # Read-only GitHub API responses can omit bypass_actors. The owner must
        # verify the actual lists with an administration-capable gh session.
        if "bypass_actors" in detail and detail["bypass_actors"] != bypass:
            raise CasError(f"Pages checkpoint ruleset bypass invalid: {name}")


def _remote_head(repo: Path, remote: str) -> str | None:
    lines = _git(repo, ["ls-remote", "--refs", remote, CHECKPOINT_REF]).stdout.splitlines()
    if not lines:
        return None
    if len(lines) != 1:
        raise CasError("Pages checkpoint ref is ambiguous")
    fields = lines[0].split("\t")
    if len(fields) != 2 or fields[1] != CHECKPOINT_REF:
        raise CasError("Pages checkpoint ref response is malformed")
    _require_sha(fields[0], "Pages checkpoint ref")
    return fields[0]


def _checkpoint_payload(repo: Path, oid: str) -> dict:
    parents = _git(repo, ["show", "-s", "--format=%P", oid]).stdout.strip().split()
    if len(parents) > 1:
        raise CasError("Pages checkpoint history is not linear")
    files = _git(repo, ["ls-tree", "-r", "--name-only", oid]).stdout.splitlines()
    if files != [CHECKPOINT_PATH]:
        raise CasError("Pages checkpoint commit has unexpected paths")
    raw = _git(repo, ["show", f"{oid}:{CHECKPOINT_PATH}"]).stdout.encode()
    value = json.loads(raw)
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise CasError("Pages checkpoint JSON is not canonical")
    return value


def _utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _needs_latest_status(receipt: dict) -> bool:
    return _now() - _timestamp(receipt["deployment_updated_at"]) <= RECENT_STATUS_WINDOW


def _latest_matches(repository: str, token: str, receipt: dict,
                    fetch: Callable[[str, str], object]) -> bool:
    deployment_id = receipt["deployment_id"]
    statuses = fetch(f"repos/{repository}/deployments/{deployment_id}/statuses?per_page=1", token)
    return (isinstance(statuses, list) and len(statuses) == 1 and isinstance(statuses[0], dict)
            and type(statuses[0].get("id")) is int and statuses[0]["id"] == receipt["status_id"]
            and statuses[0].get("state") == receipt["status_state"]
            and statuses[0].get("log_url") == receipt["status_log_url"])


def _valid_receipt(receipt: object, repository: str) -> bool:
    if not isinstance(receipt, dict) or set(receipt) != {"deployment_id", "deployment_sha", "status_id",
                                                "status_state", "status_log_url", "deployment_updated_at",
                                                "terminal_evidence"}:
        return False
    evidence = receipt["terminal_evidence"]
    if (type(receipt["deployment_id"]) is not int or receipt["deployment_id"] < 1
            or not isinstance(receipt["deployment_sha"], str) or not SHA.fullmatch(receipt["deployment_sha"])
            or type(receipt["status_id"]) is not int or receipt["status_id"] < 1
            or not isinstance(receipt["status_state"], str)
            or receipt["status_state"] not in {"success", "inactive", "failure", "error"}
            or not isinstance(receipt["status_log_url"], str)
            or not _utc_timestamp(receipt["deployment_updated_at"])
            or not isinstance(evidence, dict)):
        return False
    kind = evidence.get("kind")
    if receipt["status_state"] == "success":
        return evidence == {"kind": "success_status"}
    if receipt["status_state"] == "inactive":
        return (kind == "prior_success" and set(evidence) == {"kind", "status_id", "log_url"}
                and type(evidence["status_id"]) is int and evidence["status_id"] > 0
                and evidence["status_id"] < receipt["status_id"]
                and isinstance(evidence["log_url"], str))
    if kind == "backend_cancelled":
        return evidence == {"kind": "backend_cancelled", "deployment_sha": receipt["deployment_sha"],
                            "backend_status": "deployment_cancelled",
                            "unique_deployment_id": receipt["deployment_id"]}
    return (kind == "action_step" and set(evidence) == {"kind", "run_id", "job_id", "step_name", "status", "conclusion"}
            and type(evidence["run_id"]) is int and evidence["run_id"] > 0
            and type(evidence["job_id"]) is int and evidence["job_id"] > 0
            and evidence["status"] == "completed" and evidence["conclusion"] in {"success", "skipped"}
            and evidence["step_name"] in {"Deploy exact ledger tree", "Deploy only the freshly rechecked composition"}
            and receipt["status_log_url"] == f"https://github.com/{repository}/actions/runs/{evidence['run_id']}/job/{evidence['job_id']}")


def read_checkpoint(repo: Path, remote: str, baseline_path: Path, repository: str, *,
                    token: str, fetch: Callable[[str, str], object] = _gh_json,
                    local_head: str | None = None,
                    ) -> tuple[str | None, int, dict[int, dict]]:
    """Authenticate all historical checkpoint commits before trusting the head."""
    baseline, digest = _baseline(baseline_path, repository)
    require_policy(repository, token, fetch)
    head: str | None = local_head
    if local_head is not None:
        _require_sha(local_head, "local Pages checkpoint candidate")
    else:
        for _ in range(3):
            head = _remote_head(repo, remote)
            if head is None:
                return None, baseline["deployment_id"], {}
            _git(repo, ["fetch", "--no-tags", remote, f"+{CHECKPOINT_REF}:refs/remotes/pages-checkpoint"])
            if _git(repo, ["rev-parse", "refs/remotes/pages-checkpoint"]).stdout.strip() == head:
                break
        else:
            raise CasError("Pages checkpoint changed repeatedly during authentication")
    commits = _git(repo, ["rev-list", "--reverse", head]).stdout.splitlines()
    if not commits or len(commits) > 10000:
        raise CasError("Pages checkpoint history is absent or exceeds bound")
    previous: str | None = None
    frontier_id = baseline["deployment_id"] - 1
    frontier_sha = baseline["deployment_sha"]
    archived: dict[int, dict] = {}
    for oid in commits:
        payload = _checkpoint_payload(repo, oid)
        parent = _git(repo, ["show", "-s", "--format=%P", oid]).stdout.strip() or None
        if parent != previous or payload.get("previous_commit") != previous:
            raise CasError("Pages checkpoint ancestry does not match its previous commit")
        if (set(payload) != {"schema_version", "repository", "environment", "bootstrap_manifest_sha256",
                             "previous_commit", "frontier", "observation", "closed_delta", "reclosed_delta"}
                or payload["schema_version"] != 1 or payload["repository"] != repository
                or payload["environment"] != "github-pages" or payload["bootstrap_manifest_sha256"] != digest):
            raise CasError("Pages checkpoint contract or bootstrap digest is invalid")
        delta = payload["closed_delta"]
        reclosed = payload["reclosed_delta"]
        frontier = payload["frontier"]
        observation = payload["observation"]
        if (not isinstance(delta, list) or not isinstance(reclosed, list)
                or (previous is None and (not delta or reclosed))
                or (previous is not None and not delta and not reclosed)
                or not isinstance(observation, dict)
                or set(observation) != {"observed_at", "newest_deployment_id", "deployment_count"}
                or not _utc_timestamp(observation["observed_at"])
                or type(observation["newest_deployment_id"]) is not int
                or type(observation["deployment_count"]) is not int or observation["deployment_count"] < 0):
            raise CasError("Pages checkpoint observation is invalid")
        if observation["newest_deployment_id"] < frontier_id:
            raise CasError("Pages checkpoint observation is inconsistent")
        for receipt in delta:
            if not _valid_receipt(receipt, repository) or receipt["deployment_id"] <= frontier_id:
                raise CasError("Pages checkpoint closed delta is invalid or out of order")
            if previous is None and not archived:
                matches_success = (receipt["status_state"] == "success"
                                   and receipt["status_id"] == baseline["success_status_id"]
                                   and receipt["status_log_url"] == baseline["success_log_url"])
                matches_inactive = (receipt["status_state"] == "inactive"
                                    and receipt["terminal_evidence"] == {
                                        "kind": "prior_success", "status_id": baseline["success_status_id"],
                                        "log_url": baseline["success_log_url"]})
                if (receipt["deployment_id"] != baseline["deployment_id"]
                        or receipt["deployment_sha"] != baseline["deployment_sha"]
                        or not (matches_success or matches_inactive)):
                    raise CasError("Pages checkpoint bootstrap receipt differs from the audited manifest")
            frontier_id, frontier_sha = receipt["deployment_id"], receipt["deployment_sha"]
            archived[frontier_id] = receipt
        for receipt in reclosed:
            if not _valid_receipt(receipt, repository):
                raise CasError("Pages checkpoint reclosed receipt is invalid")
            old = archived.get(receipt["deployment_id"])
            if (old is None or receipt["deployment_sha"] != old["deployment_sha"]
                    or _timestamp(receipt["deployment_updated_at"]) < _timestamp(old["deployment_updated_at"])
                    or receipt["status_id"] < old["status_id"]
                    or (_timestamp(receipt["deployment_updated_at"]) == _timestamp(old["deployment_updated_at"])
                        and receipt["status_id"] == old["status_id"])):
                raise CasError("Pages checkpoint reclosure is not monotonic")
            archived[receipt["deployment_id"]] = receipt
        if (not isinstance(frontier, dict) or frontier != {"deployment_id": frontier_id,
                                                         "deployment_sha": frontier_sha}
                or observation["newest_deployment_id"] < frontier_id):
            raise CasError("Pages checkpoint frontier is inconsistent")
        previous = oid
    return head, frontier_id, archived


def archived_receipts(repo: Path) -> list[dict]:
    """Read receipts only after read_checkpoint authenticated this exact fetched head."""
    head = _git(repo, ["rev-parse", "refs/remotes/pages-checkpoint"]).stdout.strip()
    receipts: dict[int, dict] = {}
    for oid in _git(repo, ["rev-list", "--reverse", head]).stdout.splitlines():
        payload = _checkpoint_payload(repo, oid)
        for receipt in payload["closed_delta"] + payload["reclosed_delta"]:
            receipts[receipt["deployment_id"]] = receipt
    return [receipts[identity] for identity in sorted(receipts)]


def require_archived_freshness(repository: str, token: str, archived: dict[int, dict],
                               fetch: Callable[[str, str], object], *,
                               current_job: Callable[[], tuple[int, int]] | None = None,
                               allowed_current_states: frozenset[str] = frozenset(),
                               ) -> int | None:
    """A late status on an old deployment must be reclosed before any deploy."""
    remaining = set(archived)
    last_id: int | None = None
    baseline_id = min(remaining)
    frontier_id = max(remaining)
    current_deployment: int | None = None
    for page in range(1, MAX_PAGES + 1):
        items = fetch(f"repos/{repository}/deployments?environment=github-pages&per_page=100&page={page}", token)
        if not isinstance(items, list):
            raise CasError("Pages archived deployment listing is invalid")
        for item in items:
            if (not isinstance(item, dict) or type(item.get("id")) is not int
                    or item.get("environment") != "github-pages"
                    or (last_id is not None and item["id"] >= last_id)):
                raise CasError("Pages archived deployment listing is unordered")
            last_id = item["id"]
            if item["id"] < baseline_id:
                raise CasError("Pages archived deployment listing skipped the baseline")
            if item["id"] in archived:
                prior = archived[item["id"]]
                changed = (item.get("sha") != prior["deployment_sha"]
                           or not _utc_timestamp(item.get("updated_at"))
                           or _timestamp(item["updated_at"]) != _timestamp(prior["deployment_updated_at"])
                           or (_needs_latest_status(prior) and not _latest_matches(
                               repository, token, prior, fetch)))
                if changed:
                    exact_current = False
                    if current_job is not None and item.get("sha") == prior["deployment_sha"]:
                        statuses = fetch(f"repos/{repository}/deployments/{item['id']}/statuses?per_page=1", token)
                        if isinstance(statuses, list) and len(statuses) == 1 and isinstance(statuses[0], dict):
                            run_id, job_id = current_job()
                            status = statuses[0]
                            exact_current = (type(status.get("id")) is int and status["id"] > prior["status_id"]
                                             and status.get("state") in allowed_current_states
                                             and status.get("log_url") ==
                                             f"https://github.com/{repository}/actions/runs/{run_id}/job/{job_id}")
                    if not exact_current or current_deployment is not None:
                        raise CasError(f"Pages deployment {item['id']} has a late uncheckpointed update")
                    current_deployment = item["id"]
                remaining.remove(item["id"])
            elif item["id"] <= frontier_id:
                raise CasError("Pages archived deployment listing contains an unknown identity")
            if item["id"] == baseline_id:
                if remaining:
                    raise CasError("Pages archived deployment listing omitted an identity")
                return current_deployment
        if len(items) < 100:
            break
    raise CasError("Pages archived deployment listing exceeded bound or omitted baseline")


def _terminal_receipt(repository: str, token: str, deployment: dict,
                      fetch: Callable[[str, str], object], *,
                      prior_receipt: dict | None = None) -> dict | None:
    """Return exact closure evidence or None for any uncertain backend state."""
    import pages_compositor as pages

    deployment_id, sha = deployment["id"], deployment.get("sha")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise CasError("Pages deployment SHA is invalid")
    statuses = fetch(f"repos/{repository}/deployments/{deployment_id}/statuses?per_page=1", token)
    if not isinstance(statuses, list) or len(statuses) != 1 or not isinstance(statuses[0], dict):
        return None
    latest = statuses[0]
    sid, state, log_url = latest.get("id"), latest.get("state"), latest.get("log_url")
    if type(sid) is not int or sid < 1 or not isinstance(log_url, str):
        return None
    evidence: dict | None = None
    if state == "success":
        evidence = {"kind": "success_status"}
    elif state == "inactive":
        for page in range(1, 11):
            try:
                history = fetch(f"repos/{repository}/deployments/{deployment_id}/statuses?per_page=100&page={page}", token)
            except subprocess.CalledProcessError:
                if prior_receipt is None:
                    raise
                break
            if not isinstance(history, list) or not history:
                break
            if page == 1 and (not isinstance(history[0], dict) or history[0].get("id") != sid):
                return None
            prior = next((s for s in history if isinstance(s, dict) and type(s.get("id")) is int
                          and s["id"] < sid and s.get("state") == "success" and isinstance(s.get("log_url"), str)), None)
            if prior:
                evidence = {"kind": "prior_success", "status_id": prior["id"], "log_url": prior["log_url"]}
                break
            if len(history) < 100:
                break
        if evidence is None and prior_receipt is not None:
            prior_proof: dict | None = None
            if prior_receipt["status_state"] == "success":
                prior_proof = {"kind": "prior_success", "status_id": prior_receipt["status_id"],
                               "log_url": prior_receipt["status_log_url"]}
            elif prior_receipt["status_state"] == "inactive":
                prior_proof = prior_receipt["terminal_evidence"]
            if (prior_proof is not None and prior_proof.get("kind") == "prior_success"
                    and prior_receipt["deployment_id"] == deployment_id
                    and prior_receipt["deployment_sha"] == sha
                    and prior_proof["status_id"] < sid):
                evidence = dict(prior_proof)
    elif state in {"failure", "error"}:
        identity = pages._status_run_job_ids(repository, latest)
        if identity:
            run_id, job_id = identity
            job = fetch(f"repos/{repository}/actions/jobs/{job_id}", token)
            if isinstance(job, dict) and job.get("id") == job_id and job.get("run_id") == run_id:
                job_steps = job.get("steps")
                steps = ([s for s in job_steps if isinstance(s, dict) and s.get("name") in {
                    "Deploy exact ledger tree", "Deploy only the freshly rechecked composition"}]
                    if isinstance(job_steps, list) else [])
                if len(steps) == 1 and steps[0].get("status") == "completed" and steps[0].get("conclusion") in {"success", "skipped"}:
                    evidence = {"kind": "action_step", "run_id": run_id, "job_id": job_id,
                                "step_name": steps[0]["name"], "status": "completed",
                                "conclusion": steps[0]["conclusion"]}
        if evidence is None and pages._backend_cancelled_for_unique_sha(repository, token, deployment, fetch):
            evidence = {"kind": "backend_cancelled", "deployment_sha": sha,
                        "backend_status": "deployment_cancelled", "unique_deployment_id": deployment_id}
    if evidence is None:
        return None
    receipt = {"deployment_id": deployment_id, "deployment_sha": sha, "status_id": sid,
               "status_state": state, "status_log_url": log_url, "terminal_evidence": evidence}
    receipt["deployment_updated_at"] = deployment.get("updated_at")
    if not _valid_receipt(receipt, repository):
        raise CasError("Pages terminal receipt is malformed")
    return receipt


def _candidate(repository: str, token: str, frontier_id: int, archived: dict[int, dict],
               fetch: Callable[[str, str], object]) -> tuple[list[dict], list[dict], dict]:
    seen: list[dict] = []
    changed: list[dict] = []
    observed_archived: set[int] = set()
    baseline_id = min(archived)
    crossed = False
    last_id: int | None = None
    newest_id: int | None = None
    for page in range(1, MAX_PAGES + 1):
        items = fetch(f"repos/{repository}/deployments?environment=github-pages&per_page=100&page={page}", token)
        if not isinstance(items, list):
            raise CasError("Pages deployments response is invalid")
        for item in items:
            if (not isinstance(item, dict) or item.get("environment") != "github-pages"
                    or type(item.get("id")) is not int or item["id"] < 1
                    or not isinstance(item.get("sha"), str) or not SHA.fullmatch(item["sha"])
                    or not _utc_timestamp(item.get("updated_at"))
                    or (last_id is not None and item["id"] >= last_id)):
                raise CasError("Pages deployment listing is unordered or invalid")
            if newest_id is None:
                newest_id = item["id"]
            last_id = item["id"]
            if item["id"] < baseline_id:
                raise CasError("Pages deployment listing skipped the authenticated baseline")
            if item["id"] > frontier_id:
                seen.append(item)
                continue
            prior = archived.get(item["id"])
            if prior is None or prior["deployment_sha"] != item["sha"]:
                raise CasError("Pages deployment listing contains an unknown closed identity")
            observed_archived.add(item["id"])
            if _timestamp(item["updated_at"]) < _timestamp(prior["deployment_updated_at"]):
                raise CasError("Pages deployment update timestamp moved backwards")
            if (_timestamp(item["updated_at"]) > _timestamp(prior["deployment_updated_at"])
                    or (_needs_latest_status(prior) and not _latest_matches(
                        repository, token, prior, fetch))):
                changed.append(item)
            if item["id"] == baseline_id:
                crossed = True
                break
        if crossed or len(items) < 100:
            break
    else:
        raise CasError("Pages deployment history exceeded bounded checkpoint scan")
    if not crossed:
        raise CasError("Pages checkpoint cannot bound the old frontier")
    if observed_archived != set(archived):
        raise CasError("Pages deployment listing omitted an archived identity")
    reclosed: list[dict] = []
    for deployment in sorted(changed, key=lambda item: item["id"]):
        receipt = _terminal_receipt(repository, token, deployment, fetch,
                                    prior_receipt=archived[deployment["id"]])
        if receipt is None:
            raise CasError(f"Pages deployment {deployment['id']} has a late uncertain status")
        reclosed.append(receipt)
    delta: list[dict] = []
    for deployment in reversed(seen):
        receipt = _terminal_receipt(repository, token, deployment, fetch)
        if receipt is None:
            break
        delta.append(receipt)
    observed = {"observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "newest_deployment_id": newest_id or frontier_id,
                "deployment_count": len(seen) + len(observed_archived)}
    return delta, reclosed, observed


def _commit(repo: Path, parent: str | None, payload: dict) -> str:
    blob = _git(repo, ["hash-object", "-w", "--stdin"], input_text=_canonical(payload).decode()).stdout.strip()
    tree = _git(repo, ["mktree"], input_text=f"100644 blob {blob}\t{CHECKPOINT_PATH}\n").stdout.strip()
    cmd = ["commit-tree", tree]
    if parent:
        cmd.extend(["-p", parent])
    identity = {**os.environ, "GIT_AUTHOR_NAME": "iliya", "GIT_AUTHOR_EMAIL": "iliyazelenkog@gmail.com",
                "GIT_COMMITTER_NAME": "iliya", "GIT_COMMITTER_EMAIL": "iliyazelenkog@gmail.com"}
    for variable in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
        observed = _git(repo, ["var", variable], env=identity).stdout.strip()
        if not observed.startswith("iliya <iliyazelenkog@gmail.com> "):
            raise CasError(f"Pages checkpoint {variable} differs from owner identity")
    return _git(repo, cmd, input_text="chore(pages): advance deployment checkpoint\n\nRefs #328\n", env=identity).stdout.strip()


def _settle_candidate(repository: str, token: str, receipts: list[dict],
                      fetch: Callable[[str, str], object]) -> None:
    """Close the status timestamp second, then reread exact live identities."""
    if not receipts:
        return
    latest_second = max(_timestamp(receipt["deployment_updated_at"]) for receipt in receipts)
    remaining = (latest_second + STATUS_SECOND_SETTLE - _now()).total_seconds()
    if remaining > 5:
        raise CasError("Pages deployment timestamp is too far ahead of the checkpoint clock")
    if remaining > 0:
        time.sleep(remaining)
    if _now() < latest_second + STATUS_SECOND_SETTLE:
        raise CasError("Pages checkpoint clock did not pass the deployment status second")
    for receipt in receipts:
        identity = receipt["deployment_id"]
        deployment = fetch(f"repos/{repository}/deployments/{identity}", token)
        if (not isinstance(deployment, dict) or deployment.get("id") != identity
                or deployment.get("sha") != receipt["deployment_sha"]
                or deployment.get("environment") != "github-pages"
                or deployment.get("updated_at") != receipt["deployment_updated_at"]
                or not _latest_matches(repository, token, receipt, fetch)):
            raise CasError(f"Pages deployment {identity} changed before checkpoint push")


def advance(repo: Path, remote: str, baseline_path: Path, repository: str, token: str, *,
            fetch: Callable[[str, str], object] = _gh_json,
            push: Callable[[Path, list[str]], subprocess.CompletedProcess[str]] | None = None) -> str:
    """CAS append the largest already terminal prefix, tolerating a lost push reply."""
    baseline, digest = _baseline(baseline_path, repository)
    if push is None:
        push = lambda root, args: _git(root, args, check=False)
    for attempt in range(MAX_RETRIES):
        head, frontier_id, archived = read_checkpoint(repo, remote, baseline_path, repository,
                                                      token=token, fetch=fetch)
        bootstrap_receipt: dict | None = None
        if head is None:
            # Bootstrap must have exact live success evidence while it still exists.
            deployment = fetch(f"repos/{repository}/deployments/{baseline['deployment_id']}", token)
            status = fetch(f"repos/{repository}/deployments/{baseline['deployment_id']}/statuses/{baseline['success_status_id']}", token)
            if (not isinstance(deployment, dict) or deployment.get("id") != baseline["deployment_id"]
                    or deployment.get("sha") != baseline["deployment_sha"]
                    or deployment.get("environment") != "github-pages"
                    or not isinstance(status, dict) or status.get("id") != baseline["success_status_id"]
                    or status.get("state") != "success" or status.get("log_url") != baseline["success_log_url"]):
                raise CasError("Pages checkpoint bootstrap success evidence is unavailable")
            bootstrap_receipt = _terminal_receipt(repository, token, deployment, fetch)
            if bootstrap_receipt is None:
                raise CasError("Pages checkpoint bootstrap has a late uncertain status")
            archived = {baseline["deployment_id"]: bootstrap_receipt}
        delta, reclosed, observation = _candidate(repository, token, frontier_id, archived, fetch)
        if head is not None and not delta and not reclosed:
            return "unchanged"
        new_id = delta[-1]["deployment_id"] if delta else frontier_id
        new_sha = delta[-1]["deployment_sha"] if delta else archived[frontier_id]["deployment_sha"]
        payload = {"schema_version": 1, "repository": repository, "environment": "github-pages",
                   "bootstrap_manifest_sha256": digest, "previous_commit": head,
                   "frontier": {"deployment_id": new_id, "deployment_sha": new_sha},
                   "observation": observation,
                   "closed_delta": ([bootstrap_receipt] if bootstrap_receipt is not None else []) + delta,
                   "reclosed_delta": reclosed}
        _settle_candidate(repository, token, payload["closed_delta"] + reclosed, fetch)
        candidate = _commit(repo, head, payload)
        # The same full lineage validator used by readers must accept the
        # candidate before an immutable branch can ever point at it.
        _validated_head, validated_frontier, _validated_archived = read_checkpoint(
            repo, remote, baseline_path, repository, token=token, fetch=fetch,
            local_head=candidate,
        )
        if validated_frontier != new_id:
            raise CasError("Pages checkpoint candidate frontier differs after validation")
        lease = head or "0" * 40
        result = push(repo, ["push", f"--force-with-lease={CHECKPOINT_REF}:{lease}", remote,
                             f"{candidate}:{CHECKPOINT_REF}"])
        observed = _remote_head(repo, remote)
        if observed == candidate:
            return "published"
        if observed == head:
            if result.returncode == 0:
                raise CasError("Pages checkpoint push claimed success without a ref advance")
            if attempt + 1 < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 4))
            continue
        if observed is None and head is not None:
            raise CasError("Pages checkpoint ref disappeared after push")
        # Another writer won. Reauthenticate its full lineage before retrying.
        if attempt + 1 < MAX_RETRIES:
            time.sleep(min(2 ** attempt, 4))
    raise CasError("Pages checkpoint CAS retries exhausted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["advance", "require-policy"])
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        if args.command == "require-policy":
            require_policy(args.repository, os.environ.get("GH_TOKEN", ""))
        else:
            if args.repo is None or args.baseline is None:
                raise CasError("Pages checkpoint repo and baseline are required")
            print(advance(args.repo, args.remote, args.baseline, args.repository, os.environ.get("GH_TOKEN", "")))
    except (CasError, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"pages-checkpoint: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
