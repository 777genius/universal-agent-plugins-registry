"""Fixed Directory schema-1 publication lineages selected by trusted code.

The modern namespace is reserved implementation structure. This module contains
no production origin, signing key, bootstrap, approval or deployment authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class DirectoryFeedContract:
    name: str
    feed_path: str
    ledger_ref: str
    sequence_tag_prefix: str
    trust_config_path: str
    trusted_keys_path: str
    snapshot_schema_path: str
    private_key_environment: str
    wire_evidence_cutover_sequence: int

    @property
    def sequence_ref_prefix(self) -> str:
        return "refs/tags/" + self.sequence_tag_prefix


LEGACY_FEED = DirectoryFeedContract(
    name="legacy",
    feed_path="registry/schemas/1",
    ledger_ref="refs/heads/directory-publication-ledger",
    sequence_tag_prefix="directory-publication-schema-1-sequence-",
    trust_config_path="registry/publication/config.json",
    trusted_keys_path="registry/publication/trusted-keys.json",
    snapshot_schema_path="schemas/directory-snapshot.schema.json",
    private_key_environment="DIRECTORY_ED25519_PRIVATE_KEY",
    wire_evidence_cutover_sequence=15,
)

MODERN_FEED = DirectoryFeedContract(
    name="modern",
    feed_path="registry/modern/schemas/1",
    ledger_ref="refs/heads/directory-modern-publication-ledger",
    sequence_tag_prefix="directory-modern-publication-schema-1-sequence-",
    trust_config_path="registry/publication/modern/config.json",
    trusted_keys_path="registry/publication/modern/trusted-keys.json",
    snapshot_schema_path="schemas/directory-modern-snapshot.schema.json",
    private_key_environment="DIRECTORY_MODERN_ED25519_PRIVATE_KEY",
    wire_evidence_cutover_sequence=1,
)


def fixed_feed(feed: DirectoryFeedContract) -> DirectoryFeedContract:
    """Do not admit profiles constructed from candidate fields or environment."""
    if feed is not LEGACY_FEED and feed is not MODERN_FEED:
        raise ValueError("Directory feed must be selected by a fixed trusted entrypoint")
    return feed


def reviewed_source_path(root: Path, relative: str) -> Path:
    """A fixed modern trust path must not redirect outside its reviewed tree."""
    path = root / relative
    if path.resolve() != path:
        raise ValueError("modern Directory trust path must be a regular reviewed-source path")
    return path
