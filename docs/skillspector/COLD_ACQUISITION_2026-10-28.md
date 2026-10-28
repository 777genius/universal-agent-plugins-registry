# Cold acquisition verification — 2026-10-28

The cold Git acquisition bottleneck is reproduced and removed without increasing the preparation deadline, scanner budgets, or content limits. The final v3 caller acquired the complete pinned Cloudflare root in **6.710 seconds**, then executed the real standard SkillSpector profile. Its report correctly remains **partial** for analysis limitations.

## Why the hosted run needed a correction

[Controlled run 40673797731](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/40673797731) passed workflow/contract validation and skipped publication, but its main Cloudflare record failed before analysis: `preparation_timeout`, 120.002574 s acquisition, no content digest, and no analysis duration. The older [local CLI experiment](CLI_E2E_2026-10-28.md) used cached mirrors and explicitly did not measure this network path.

`PinnedRepository` creates a blobless repository. The old package reader then requests each object's size separately. The new cold trace directly confirms that each missing size query launches a separate promisor fetch. This makes preparation time depend on one network round trip per file.

## Measured comparison

Every experiment used a fresh `PinnedRepository` against the real public repository, without offline mirrors or GitHub credentials. The source pin and package bytes were identical.

| Experiment | Acquisition time | Fetch invocations | Outcome |
| --- | ---: | ---: | --- |
| Old reader | 120.003842 s | 227 | Deadline after 226 individual size queries; no materialization |
| Initial batched helper | 10.406656 s | 11 | Complete root; intermediate helper before two guard refinements |
| Final helper through actual v3 caller | 6.710318 s | 11 | Complete root, then actual standard scan |

Fetch counts include the initial pinned fetch. The completed root contains **320 files, 320 distinct blob IDs, and 1,411,657 bytes**. Ten explicit batches of at most 32 objects replace per-file lazy fetches. The complete root is materialized and analyzed together; transfer batching does not split the analysis scope.

- Repository: `777genius/universal-agent-plugins-registry`.
- Source revision: `4d7d8e075e1b0d899965496bacf2811be5d94091`.
- Root: `plugins/cloudflare/skills/cloudflare`.
- Exact content digest: `sha256:3fc80ceeefbdc9ac0184a6188d6bb8fc1cba8133f92c854e3ad2d52c7f610d6d`.
- Code base commit during measurement: `c7325e0798d0b638371403008da227e46eea66cc`. The acquisition change was pending commit, so the JSON also records exact hashes of all eight working-tree source files; all stayed unchanged during the final run.
- Final helper SHA-256: `sha256:157c97e237ae51e05e57722b3987d27db3f402ab295715873dcafe14d78a2148`.

The helper validates the complete tree's paths, modes, object IDs and file count before hydration. It disables implicit lazy fetching, bounds each Git child's file output and cumulative new pack bytes, checks file and aggregate sizes including repeated blob occurrences, verifies returned blob identities, and keeps the existing process-group deadline. Fetches do not update refs, write commit graphs, recurse into submodules or run automatic maintenance. The final refinements respect an inherited lower file-size hard limit and let discovery reject an invalid LFS `SKILL.md` individually while whole-root analysis continues to reject LFS payloads.

## Final scan result

The actual `skillspector_coverage_v3.scan_selected` caller was verified to reference the new helper. It used the standard profile unchanged: 60 s outer process, 45 s internal workflow, 30 s per artifact, 512 files and 4 MiB tree limit. Preparation remains bounded at 120 s.

- Cold acquisition including the initial fetch: **6.710318 s**; the helper itself took 5.746942 s.
- Scanner analysis: **53.480321 s**, execution `completed`, scanner exit code 1.
- Report: `partial`; 478 emitted upstream signals, 473 content signals, 253 displayed groups.
- Both exact Upload Session annotations remain present with their evidence: 2 `false_positive` groups and 251 `unreviewed` groups.
- Queue decision: `extended_profile_required` → `static-extended-v3`. The retry now addresses the scanner's analysis budget rather than repeatedly timing out during source acquisition.
- `skillspector_contract.validate_record` passed. Record SHA-256: `sha256:a995b801b5aa857528d0a7a0ce4f623a90c4680a397cc7a1e73e11d403abf2f3`.

Root separately reported **164 focused SkillSpector tests passing in 18.141 s**. This test-suite result is distinct from the one real scanner execution measured here. No reports were published by these experiments.

## Hosted controlled gate

[Run 40680891575](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/40680891575), at code commit `f10b72bca0a7519881d8fa7f0c918a80375b193b`, completed preparation, the single 15-source worker and assembly successfully. Publication was correctly skipped. Independent publisher validation of the downloaded artifact passed with that exact source commit.

All 15 records are current and have completed execution: **3 complete, 12 partial, 0 errors**. Cloudflare contributes 13 records: **3 complete and 10 partial**. The main Cloudflare root was acquired in **4.300903 s**, retained the same whole-root digest, and ran analysis for 47.456786 s. Its 486 upstream signals contain 481 content occurrences grouped into 261 groups; both exact Upload Session annotations are retained.

The resulting queue has 11 blocked permanent limitations, 3 complete results requiring no attempt, and one scheduled extended attempt for the main Cloudflare root. React Native now has only its five parser limitations and is blocked instead of repeated without a useful change. The complete set contains 634 upstream occurrences, 615 content occurrences and 365 displayed groups; these are signal groups, not independently confirmed vulnerabilities.

The [hosted evidence JSON](hosted-controlled-2026-10-28.json) binds every source, status, timing and queue decision to the artifact hashes. This gate predates the additive reference and ledger evidence projection. That later projection does not change the source acquisition, scanner or analysis profile; its validation against retained full raw reports is recorded separately.

## Transport and reproducibility

This workspace cannot resolve GitHub from the production helper's sanitized environment without its approved proxy. The measurement harness added only the environment's proxy keys and Git Trace2 instrumentation to the Git transport. It did not change deadlines, file limits, source identities, package bytes, or scanner arguments. No proxy values, GitHub credentials, or HTTP headers were recorded. The scanner kept its production environment allowlist.

The old and initial-new standalone experiments used one 120 s budget including the initial fetch. The final caller kept production's separate initial-fetch and package-preparation budgets, each 120 s. Its observed complete acquisition was under seven seconds including both stages. These timings are observations on this network route, not a latency guarantee for hosted runners; the corrected hosted controlled run remains a separate gate.

The committed [measurement JSON](cold-acquisition-2026-10-28.json) records commands, source/code/scanner/profile identities, phase timings, fetch counts, coverage reasons, retry decision, and raw trace/record digests. The isolated harnesses and full traces were retained under `cold-acquisition-verification/` outside the repository. To reproduce the transport behavior in a normal network environment, construct a fresh `PinnedRepository` at the source revision above with `mirror_root=None`, invoke the checked-in `skillspector_acquisition.bounded_package_files` with the unchanged standard limits and `WorkBudget(120)`, and verify the complete digest above. `tests.test_skillspector_acquisition` additionally reproduces cold promisor behavior using a local Git server with filtering enabled and verifies batched fetch counts, byte limits, whole-root identity, and deadline handling.
