# SkillSpector execution profiles and controlled measurements

The checked-in corpus pins 15 immutable skill roots: all 13 skills in the
Cloudflare plugin, one previously runtime-limited React Native skill, and one
reproducible parser-limited App Store Connect skill. The measurements cover 18
executions: every Cloudflare root with the standard profile, its largest root
also with the extended profile, and both profiles for the other two sources.

`controlled-profiles-2026-10-28.json` records source revisions and content digests,
scanner revision, exact profile documents, acquisition and analysis time,
completion state, distinct limitation counts, raw occurrence counts, content
occurrence counts, group counts, and raw/normalized report digests. Original
scanner JSON and complete normalized records are produced by the reproduction
command below. They are not replaced by the first 32 findings.

## Observed results

| Source | Size | Standard profile | Extended profile |
| --- | --- | --- | --- |
| Cloudflare plugin, all roots | 13 skills | 3 complete; 10 partial | Only the largest root was repeated |
| Cloudflare main skill | 320 files; 1,411,657 bytes | 45-second internal budget reached | 150-second internal budget still reached; more work completed |
| React Native best practices | 58 files; 466,131 bytes | Runtime limit present | Runtime limits cleared; parser limits remain |
| App Store Connect workflow | 1 file; 6,900 bytes | Parser limit and missing references | Same permanent limitations |

The React Native extended scan took about 88 seconds and eliminated its runtime
limitations. The Cloudflare main skill still remained partial after about 154
seconds including startup and report generation. An extended retry therefore
has a bounded opportunity to make progress; it is not a promise of complete
coverage. The parser example returned the same limitation in approximately four
seconds under either profile. Repeating it indefinitely with unchanged scanner,
content and profile would waste capacity.

The measured run shared one host between up to six independent scanners.
Acquisition used local immutable Git mirrors obtained through `gh`; those
acquisition times are not network download benchmarks. The JSON contains exact
observed values. Timing varies with host load. Group counts describe the signals
actually emitted in each bounded run, not all possible problems in the source
and not a reconstruction of the old truncated 603-finding sample.

## Bounded budgets

| Budget | Standard | Extended |
| --- | --- | --- |
| Outer process deadline | 60 seconds | 180 seconds |
| Scanner workflow deadline | 45 seconds | 150 seconds |
| Per-artifact static analysis ceiling | 30 seconds | 90 seconds |
| Acquired file ceiling | 512 | 2,048 |
| Acquired tree ceiling | 4 MiB | 16 MiB |
| OSV request timeout | 3 seconds | 3 seconds |

The ordinary budget remains close to the original production limit. The
extended profile allows the observed 88-second source to clear its runtime
limit without giving every source the same larger allowance. The outer deadline
leaves time to emit a structured incomplete result after the internal deadline.
When the caller has less remaining time, both internal limits are reduced to
fit the actual process deadline. A hard timeout terminates the scanner's process
group, including parser helpers.

These profiles do not raise fixed upstream parser or unsupported-format limits.
Source trees are analyzed as complete selected skill packages. No file-by-file
splitting is used. No skill script is executed. The scanner receives a clean
environment, no credentials, no tracing configuration, and no author-supplied
suppression baseline.

## Reproduce

Check out NVIDIA/SkillSpector at
`f3b25697d76256998ca9d42c198d256258d4c035` and install its frozen `uv.lock` with
Python 3.12. Place bare Git mirrors under `MIRRORS/owner/repository.git`. For
example, `gh repo clone software-mansion-labs/skills MIRRORS/software-mansion-labs/skills.git -- --bare`
creates such a mirror. The actual corpus uses these repositories:

- `777genius/universal-agent-plugins-registry`
- `software-mansion-labs/skills`
- `rorkai/app-store-connect-cli-skills`

From this registry checkout, run:

```bash
python3 -m scripts.measure_skillspector_profiles \
  --selection docs/skillspector/controlled-sources-2026-10-28.json \
  --scanner /path/to/SkillSpector/.venv/bin/skillspector \
  --mirror-root /path/to/MIRRORS \
  --profiles static-standard-v3 static-extended-v3 \
  --workers 1 \
  --output-dir /path/to/profile-measurements
```

This command intentionally runs both profiles for every corpus source, so it
produces 30 measurements instead of the original targeted 18. Each measurement
directory retains `raw.json`, `record.json`, `invocation.json`, and `summary.json`.
The top-level summary contains the precise scanner and profile configuration.
Partial results remain partial; acquisition or normalization failures make the
command exit unsuccessfully after retaining the other measurements.

## Two narrowly bound Upload Session annotations

The pinned scanner's E4 context-leakage regex matches `Upload Session` even when
the optional conversation-history suffix is absent. Two reproduced Cloudflare
matches are a `Create Upload Session` heading and a table row giving upload
session JWT validity. Their surrounding source describes a static asset upload
protocol. `scripts/skillspector_exceptions.py` documents and binds those two
annotations to the exact source repository, revision, skill root, content
digest, scanner revision, rule, severity, file, line, full-match fingerprint,
snippet digest, and current profile digest.

The findings and raw counts are retained. Only their review classification is
`false_positive`, with a visible registry rationale. Another file, source
revision, content digest, snippet, scanner or profile does not inherit the
annotation. The exception-set digest is included in both profile identities.
No network or credential rule is suppressed. A concealed executable SC9 remains
a content finding even if its behavior is also outside analysis coverage; only
SC9 records explicitly describing a pure inspection limit move to coverage.
