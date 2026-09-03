"""Repository identity used by generated active metadata.

Historical signed fixtures intentionally retain their original repository name.
For live builds the workflow supplies UAP_ACTIVE_REPOSITORY from the exact
checked-out repository. Local fixture builds keep the legacy default so unit
tests remain reproducible even though GitHub also sets GITHUB_REPOSITORY.
"""

from __future__ import annotations

import os
import re


LEGACY_REGISTRY_REPOSITORY = "777genius/universal-agent-plugins"
CURRENT_REGISTRY_REPOSITORY = "777genius/universal-agent-plugins-registry"
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def active_registry_repository() -> str:
    """Return the live registry identity, with a fixture-safe local fallback."""
    value = os.environ.get("UAP_ACTIVE_REPOSITORY", "").strip()
    if REPOSITORY_RE.fullmatch(value):
        return value
    return LEGACY_REGISTRY_REPOSITORY


def active_registry_pages_origin() -> str:
    return "https://777genius.github.io/" + active_registry_repository().split("/", 1)[1]
