"""Content-bound display annotations for reproduced upstream false positives.

Nothing is removed from the report or excluded from scanner execution. These
two E4 matches are headings/table labels in the static asset upload protocol,
not instructions to send an agent conversation. Every source and match selector
must agree; a new source, scanner, snippet or profile requires validation again.
"""
from __future__ import annotations

import hashlib
import json

SOURCE = {
    "repository": "777genius/universal-agent-plugins-registry",
    "revision": "4d7d8e075e1b0d899965496bacf2811be5d94091",
    "path": "plugins/cloudflare/skills/cloudflare",
    "content_digest": "sha256:3fc80ceeefbdc9ac0184a6188d6bb8fc1cba8133f92c854e3ad2d52c7f610d6d",
}
SCANNER_REVISION = "f3b25697d76256998ca9d42c198d256258d4c035"
REASON = ("This exact match names a Cloudflare static asset upload session. The surrounding "
          "heading or validity table describes uploading Worker assets, not agent conversation "
          "history. SkillSpector 2.13.1 E4 matches the words 'Upload Session' without requiring "
          "conversation context. This registry annotation retains the original finding.")
EXCEPTIONS = (
    {"id": "cloudflare-upload-session-heading-v1",
     "path": "references/workers-for-platforms/api.md", "line": 93,
     "match_fingerprint": "d4f64bba95c41458d45421eebf46825971fb8098c1cd89a407143ab54d19206a",
     "snippet_digest": "sha256:c188fd7050d743b445fc087519d6fcd33a0a8b25ebba4ef93910e47c5d65b754"},
    {"id": "cloudflare-upload-session-validity-v1",
     "path": "references/workers-for-platforms/gotchas.md", "line": 110,
     "match_fingerprint": "fdcf74bb61343ce2f2d1b6553c77e65339da98c0a7cd0d551f800df6468ba150",
     "snippet_digest": "sha256:cf0cc64aa91db29ea06a9d9acdaea8b3ad912f1b444cffb65b2945b8eccbeca7"},
)
EXCEPTION_SET = {"version": 1, "source": SOURCE, "scanner_revision": SCANNER_REVISION,
                 "rule": "E4", "reason": REASON, "exceptions": list(EXCEPTIONS)}
EXCEPTION_SET_DIGEST = "sha256:" + hashlib.sha256(
    (json.dumps(EXCEPTION_SET, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
).hexdigest()


def matching_exception(source: dict, scanner: dict, profile: dict, finding: dict) -> dict | None:
    """Return the annotation only after every content identity check succeeds.

    The caller must additionally verify that profile.digest is the current
    digest of its allowlisted profile document. The returned annotation binds
    that exact digest; the exception-set digest is part of those documents.
    """
    if any(source.get(key) != value for key, value in SOURCE.items()):
        return None
    if scanner != {"id": "skillspector", "version": "2.13.1", "revision": SCANNER_REVISION}:
        return None
    if profile.get("id") not in {"static-standard-v3", "static-extended-v3"}:
        return None
    digest = profile.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        return None
    if finding.get("rule", finding.get("id")) != "E4" or finding.get("severity") != "HIGH":
        return None
    snippet = finding.get("code_snippet")
    if not isinstance(snippet, str):
        return None
    snippet_digest = "sha256:" + hashlib.sha256(snippet.encode("utf-8")).hexdigest()
    path = finding.get("path") or finding.get("location", {}).get("file")
    line = finding.get("line") or finding.get("location", {}).get("start_line")
    for exception in EXCEPTIONS:
        if (path != exception["path"] or line != exception["line"]
            or finding.get("match_fingerprint") != exception["match_fingerprint"]
            or snippet_digest != exception["snippet_digest"]):
            continue
        occurrences = finding.get("occurrences") or []
        if not isinstance(occurrences, list):
            return None
        if any(not isinstance(occurrence, dict)
               or occurrence.get("path", occurrence.get("file")) != exception["path"]
               or occurrence.get("line", occurrence.get("start_line")) != exception["line"]
               for occurrence in occurrences):
            return None
        return {"id": exception["id"], "reason": REASON,
                "source_content_digest": SOURCE["content_digest"],
                "scanner_revision": SCANNER_REVISION,
                "match_fingerprint": exception["match_fingerprint"],
                "snippet_digest": snippet_digest, "profile_digest": digest}
    return None
