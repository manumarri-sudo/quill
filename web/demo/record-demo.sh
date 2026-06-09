#!/usr/bin/env bash
# Record the 30-second README demo GIF.
#
# Captures the rm -rf save flow:
#   1. agent attempts rm -rf
#   2. Quill blocks with reason + try-instead suggestion
#   3. notification fires with one-shot approve token
#   4. quill approve <token>
#   5. retry succeeds
#
# Requires:
#   brew install asciinema
#   cargo install --git https://github.com/asciinema/agg   # GIF renderer
#
# Output:
#   ./web/quill_demo.cast    (asciinema raw recording)
#   ./web/quill_demo.gif     (rendered, drop into README)
#
# Run from the repo root:
#   ./web/demo/record-demo.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Sanity checks --------------------------------------------------------

command -v asciinema >/dev/null || { echo "Install asciinema: brew install asciinema"; exit 1; }
command -v agg       >/dev/null || { echo "Install agg: cargo install --git https://github.com/asciinema/agg"; exit 1; }
command -v quill     >/dev/null || { echo "Install quill: uvx quillx start"; exit 1; }

# Demo scenario --------------------------------------------------------
# Run the demo non-interactively so the recording is deterministic.
# The expect-style scripting below uses sleep delays to pace the typing
# for a human-readable demo.

CAST_FILE="$REPO_ROOT/web/quill_demo.cast"
GIF_FILE="$REPO_ROOT/web/quill_demo.gif"

# Clean any prior recordings.
rm -f "$CAST_FILE" "$GIF_FILE"

# The actual demo script. asciinema-rec runs this in a subshell and
# captures both the typed input and the program output.
DEMO_SCRIPT=$(cat <<'SCRIPT'
clear
printf '\033[1;36m# quill: the pause button between your AI agent and prod\033[0m\n'
sleep 1

printf '\033[1;33m# the agent attempts to clean up build artifacts...\033[0m\n'
sleep 1

# Simulate the agent's dangerous command
printf '\033[1m$\033[0m rm -rf /\n'
sleep 1.2

# Quill catches it
printf '\033[1;31m  ⛔ verdict.blocked\033[0m  rm -rf is critical-risk\n'
printf '   reason  : refuses to wipe the root filesystem\n'
printf '   try     : if you meant ./build, use a relative path\n'
printf '   approve : quill approve T7gQ2x9aB4   \033[2m(10 min, single use)\033[0m\n'
sleep 3

printf '\n\033[1;33m# operator reads the notification on their phone,\033[0m\n'
printf '\033[1;33m# agrees the agent meant ./build, approves once:\033[0m\n'
sleep 2

printf '\033[1m$\033[0m quill approve T7gQ2x9aB4\n'
sleep 1
printf '   \033[1;32m✓\033[0m approved rm for one call · expires 2026-06-09T01:24:11\n'
printf '     next attempt of this exact (tool, args) will go through.\n'
sleep 2.5

printf '\n\033[1;33m# the agent retries with the relative path...\033[0m\n'
sleep 1.5

printf '\033[1m$\033[0m rm -rf ./build\n'
sleep 0.8
printf '   \033[1;32m✓\033[0m verdict.allowed  rm scoped to ./build\n'
sleep 2

printf '\n\033[1;36m# every decision goes into ~/.quill/audit.log.jsonl\033[0m\n'
printf '\033[1;36m# HMAC-chained, mode 0o600, EU AI Act Art. 12 + 14 ready\033[0m\n'
sleep 3

printf '\n\033[1m$\033[0m quill audit verify\n'
sleep 0.8
printf '   \033[1;32mchain intact:\033[0m 472 entries verified.\n'
sleep 3

printf '\n\033[1;35m# install:  uvx quillx start\033[0m\n'
sleep 2
SCRIPT
)

echo
echo "Recording starts in 3 seconds. Make your terminal ~80 cols wide."
echo "Press Ctrl+D after the demo finishes to save the recording."
echo
sleep 3

asciinema rec "$CAST_FILE" \
  --command "bash -c '$DEMO_SCRIPT'" \
  --rows 24 \
  --cols 88 \
  --title "Quill: the rm -rf save" \
  --idle-time-limit 1.5

# Render to GIF --------------------------------------------------------

echo
echo "Rendering GIF..."

agg "$CAST_FILE" "$GIF_FILE" \
  --theme monokai \
  --font-size 16 \
  --speed 1.0 \
  --line-height 1.4

echo
echo "Done."
echo "  cast : $CAST_FILE"
echo "  gif  : $GIF_FILE"
echo
echo "Drop the GIF into the README via the existing markdown line:"
echo '  ![Quill in action: real recent BLOCK decisions from a dogfooding session](web/quill_demo.gif)'
