# Universal Agent Plugins npm release

UAP owns publication of the `universal-agent-plugins` npm facade. The exact
native `agentplugins` binaries remain built, released, and attested only by
`777genius/plugin-kit-ai`; the npm package pins those public assets and never
vendors a binary or a second Go engine.

Start **Publish universal-agent-plugins to npm** manually at the exact UAP tag
(the workflow run's ref must be that tag) with all four release coordinates:

- UAP tag `vX.Y.Z`;
- npm version `X.Y.Z`;
- plugin-kit-ai tag `agentplugins-vX.Y.Z`;
- the tag's lowercase 40-character plugin-kit-ai commit.

Leave `verify_only` enabled first. The workflow fails unless all three versions
match, both tags resolve exactly, and the plugin-kit-ai release is immutable.
It authenticates the six binaries, `checksums.txt`, and
`release-manifest.json`, including API names and sizes, checksums, manifest
metadata, and GitHub attestations from
`777genius/plugin-kit-ai/.github/workflows/agentplugins-release.yml`. It then
stages and inspects one exact npm tarball and runs it with the matching native
binary on macOS x64/arm64, Linux x64/arm64, and Windows x64/arm64.

Only the publish job receives `id-token: write`. It has no npm token and uses
npm trusted publishing with provenance. Before that job, all npm operations are
read-only. A version that already exists, or a version that would move `latest`
backward, is rejected. Concurrency serializes duplicate version attempts.

After publication, the same six native runners reacquire the public npm package
anonymously. Each proof creates an isolated HOME, XDG, npm cache, temporary
directory, and synthetic project, then proves `version`, read-only `doctor`,
public `search`, and an add/info/update/remove lifecycle. Nothing runs in a real
user project.

Publication is irreversible: npm versions are immutable. If a post-publication
proof exposes a defect, do not overwrite a version or dist-tag it away. Correct
the issue and publish a higher fix-forward version through the complete workflow.

The native runner matrix is intentionally a GitHub check. Local static and Node
tests validate its contract, but the six OS/architecture executions, trusted
publisher exchange, npm provenance, and anonymous public reacquisition can only
be recorded by the GitHub workflow.
