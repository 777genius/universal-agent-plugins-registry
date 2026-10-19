#!/usr/bin/env bash
# Run one bounded inert scan slice. Artifact upload belongs to the workflow.
set -euo pipefail

phase="${1:?acquire or validate required}"
case "$phase" in acquire|validate) ;; *) exit 2 ;; esac
case "${PHASE_BUDGET_MINUTES:?phase budget required}" in 120|300) ;; *) exit 2 ;; esac
test "${DISCOVERY_PHASE_FINISHED:-false}" != true
# Retain the phase clock with the checkpoint, not in the ephemeral workspace.
# A failed-job retry downloads this file before starting another slice.
start_file="../checkpoint/phase-${phase}-started"
now="$(date +%s)"
test ! -L ../checkpoint
mkdir -p ../checkpoint
test ! -L "$start_file"
if ! test -f "$start_file"; then
  temporary_clock="$(mktemp ../checkpoint/.phase-clock.XXXXXX)"
  printf '%s\n' "$now" > "$temporary_clock"
  mv "$temporary_clock" "$start_file"
fi
started="$(< "$start_file")"
[[ "$started" =~ ^[1-9][0-9]{0,9}$ ]]
elapsed=$((now - started))
test "$elapsed" -ge 0
remaining=$((PHASE_BUDGET_MINUTES * 60 - elapsed))
if test "$remaining" -le 0; then
  echo "::error::Discovery phase wall budget exhausted. Resume only its confirmed checkpoint."
  exit 1
fi
work_budget=1800
if test "$remaining" -lt "$work_budget"; then work_budget="$remaining"; fi
args=(--mode "${MODE:?mode required}" --phase "$phase" --checkpoint-dir ../checkpoint
      --work-budget-seconds "$work_budget")
if test "$phase" = acquire; then
  output=../acquisition.json
  diagnostics=../acquisition-diagnostics.json
else
  output=../candidate.json
  diagnostics=../diagnostics.json
  args+=(--repository-workers 8)
fi
args+=(--output "$output" --diagnostics-output "$diagnostics")
if test -n "${PREVIOUS_SNAPSHOT:-}"; then args+=(--previous-snapshot "$PREVIOUS_SNAPSHOT"); fi

# Cooperative deadlines stop new work. This process guard also bounds a stuck
# in-flight Git operation and leaves the workflow time to upload atomic progress.
set +e
timeout --signal=TERM --kill-after=60s "$((work_budget + 180))s" \
  python3 scripts/build_discovery_index.py "${args[@]}"
status=$?
set -e
if test "$status" -eq 4; then
  test ! -f "$output"
  echo "::notice::Discovery slice yielded. Upload progress before continuing."
  exit 0
fi
if test "$status" -ne 0 && ! { test "$phase" = validate && test "$status" -eq 3; }; then
  exit "$status"
fi
test -f "$output"
test -f "$diagnostics"
test "$(wc -c < "$output")" -le 16777216
echo "DISCOVERY_PHASE_FINISHED=true" >> "$GITHUB_ENV"
if test "$phase" = validate; then
  complete=true
  if test "$status" -eq 3; then
    complete=false
    echo "::warning::Discovery scan was incomplete. The published last-known-good index remains active."
  fi
  echo "DISCOVERY_CANDIDATE_COMPLETE=$complete" >> "$GITHUB_ENV"
  echo "DISCOVERY_CANDIDATE_DIGEST=sha256:$(sha256sum "$output" | cut -d' ' -f1)" >> "$GITHUB_ENV"
fi
