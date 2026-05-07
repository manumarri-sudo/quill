#!/usr/bin/env bash
# One-shot driver for the Quill experiment.
#
#   ANTHROPIC_API_KEY=sk-... ./run_experiment.sh [extra harness flags]
#
# All extra args are forwarded to agentdojo_harness.py.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"

export PYTHONPATH="${REPO}/src:${HERE}:${PYTHONPATH:-}"

cd "${REPO}"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ANTHROPIC_API_KEY is not set."
  echo "  export ANTHROPIC_API_KEY=sk-ant-..."
  echo "  bash experiments/run_experiment.sh"
  exit 0
fi

echo ">> running harness"
python3 experiments/agentdojo_harness.py "$@"

echo ">> rendering artifacts"
python3 experiments/render_artifacts.py

echo ""
echo "results in: ${HERE}/results"
ls -1 "${HERE}/results"
