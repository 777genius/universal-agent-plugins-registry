import os
import unittest
from unittest import mock

from scripts.repository_identity import (
    CURRENT_REGISTRY_REPOSITORY,
    LEGACY_REGISTRY_REPOSITORY,
    active_registry_pages_origin,
    active_registry_repository,
)


class RepositoryIdentityTests(unittest.TestCase):
    def test_local_fixture_builds_keep_legacy_identity(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(active_registry_repository(), LEGACY_REGISTRY_REPOSITORY)

    def test_live_github_build_uses_renamed_registry_identity(self):
        with mock.patch.dict(os.environ, {"UAP_ACTIVE_REPOSITORY": CURRENT_REGISTRY_REPOSITORY}, clear=True):
            self.assertEqual(active_registry_repository(), CURRENT_REGISTRY_REPOSITORY)
            self.assertEqual(
                active_registry_pages_origin(),
                "https://777genius.github.io/universal-agent-plugins-registry",
            )

    def test_invalid_environment_does_not_control_identity(self):
        with mock.patch.dict(os.environ, {"UAP_ACTIVE_REPOSITORY": "evil/../repo"}, clear=True):
            self.assertEqual(active_registry_repository(), LEGACY_REGISTRY_REPOSITORY)


if __name__ == "__main__":
    unittest.main()
