#!/usr/bin/env bash
#
# Quill Change Control - GitHub Action wrapper.
#
# Runs `quill verify`, turns the Change Passport into a PR-visible summary +
# commit Status Check, exposes the verdict as a step output, and exits 0 for
# PASS / NEEDS_REVIEW or 1 for BLOCK so the job gates the merge.
#
# Inputs (environment):
#   QUILL_HEAD          ref to verify against the contract base (default HEAD)
#   QUILL_PASSPORT_DIR  where passport.{json,md} are written (default .quill)
#   QUILL_FAIL_ON_BLOCK "true" to exit 1 on BLOCK (default true)
#   QUILL_HEAD_SHA      commit SHA to attach the Status Check to (default: git HEAD)
#   GITHUB_TOKEN        token for the Status Check + PR comment (optional)
#   GITHUB_REPOSITORY   owner/repo (provided by Actions)
#   GITHUB_OUTPUT       step-output file (provided by Actions)
#   GITHUB_STEP_SUMMARY job-summary file (provided by Actions)
#
set -uo pipefail

HEAD_REF="${QUILL_HEAD:-HEAD}"
PASSPORT_DIR="${QUILL_PASSPORT_DIR:-.quill}"
FAIL_ON_BLOCK="${QUILL_FAIL_ON_BLOCK:-true}"
STATUS_CONTEXT="quill/change-control"

# --strict (default on) requires a signed perimeter from a trusted approver, so
# an unsigned / tampered / absent boundary BLOCKs rather than silently passing.
STRICT_FLAG=""
if [[ "${QUILL_STRICT:-true}" == "true" ]]; then
  STRICT_FLAG="--strict"
fi

# 1. Run the verifier. It exits 1 on BLOCK; we capture that without aborting so
#    we can still publish the passport and a Status Check before deciding. The
#    passport is gate-signed automatically when QUILL_GATE_KEY is in the env
#    (an off-box CI secret), so reviewers can verify the verdict independently.
quill verify $STRICT_FLAG --head "$HEAD_REF" --passport-dir "$PASSPORT_DIR" \
  >/dev/null 2>"$PASSPORT_DIR.err" || true

PASSPORT_JSON="$PASSPORT_DIR/passport.json"
PASSPORT_MD="$PASSPORT_DIR/passport.md"

if [[ ! -f "$PASSPORT_JSON" ]]; then
  echo "::error::quill verify did not produce a passport. stderr:"
  cat "$PASSPORT_DIR.err" 2>/dev/null || true
  exit 2
fi

# 2. Read the verdict + reasons from the passport (python is always present).
VERDICT="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$PASSPORT_JSON")"
EXIT_CODE="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["exit_code"])' "$PASSPORT_JSON")"
REASONS="$(python -c 'import json,sys; print("; ".join(json.load(open(sys.argv[1]))["reasons"]))' "$PASSPORT_JSON")"

echo "Quill verdict: $VERDICT ($REASONS)"

# 3. Step output (so later steps / the job can branch on the verdict).
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "verdict=$VERDICT"
    echo "exit_code=$EXIT_CODE"
  } >>"$GITHUB_OUTPUT"
fi

# 4. Job summary: the full markdown passport, visible on the PR's Checks tab.
if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -f "$PASSPORT_MD" ]]; then
  cat "$PASSPORT_MD" >>"$GITHUB_STEP_SUMMARY"
fi

# 5. Commit Status Check. PASS / NEEDS_REVIEW -> success (NEEDS_REVIEW is a soft
#    signal); BLOCK -> failure. Best-effort: a missing token just skips it.
case "$VERDICT" in
  BLOCK) STATE="failure" ;;
  *)     STATE="success" ;;
esac
SHA="${QUILL_HEAD_SHA:-$(git rev-parse HEAD 2>/dev/null)}"
if [[ -n "${GITHUB_TOKEN:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "$SHA" ]]; then
  DESC="$VERDICT: ${REASONS:0:130}"
  python - "$STATE" "$DESC" "$SHA" <<'PY' || echo "::warning::could not publish Status Check"
import json, os, sys, urllib.request
state, desc, sha = sys.argv[1], sys.argv[2], sys.argv[3]
repo = os.environ["GITHUB_REPOSITORY"]
token = os.environ["GITHUB_TOKEN"]
body = json.dumps({
    "state": state,
    "description": desc,
    "context": "quill/change-control",
}).encode()
req = urllib.request.Request(
    f"https://api.github.com/repos/{repo}/statuses/{sha}",
    data=body,
    method="POST",
    headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    },
)
urllib.request.urlopen(req, timeout=15).read()
print("published Status Check:", state)
PY
fi

# 6. Exit code: fail the job only on BLOCK (when fail-on-block is on).
if [[ "$VERDICT" == "BLOCK" && "$FAIL_ON_BLOCK" == "true" ]]; then
  exit 1
fi
exit 0
