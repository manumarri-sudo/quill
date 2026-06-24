"""The GitHub Action wrapper must fail closed (security re-review P0-3).

These tests drive ``scripts/quill-passport.sh`` as a black box through a real
git repo, proving the two properties that matter:

  1. a passport committed into the PR (or left over from a prior step) can never
     be mistaken for this run's verdict - the wrapper reads the verdict only from
     a passport it wrote into a private temp dir;
  2. the published passport reflects the *real* verdict, overwriting any stale one.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parent.parent / "scripts" / "quill-passport.sh"


def _run(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True, capture_output=True, text=True)


def _git_env(home: Path) -> dict[str, str]:
    """A git/quill env with the venv's bin on PATH so the `quill` console script
    and `git` resolve, and a throwaway HOME so we never touch the real one."""
    venv_bin = str(Path(sys.executable).parent)
    env = dict(os.environ)
    env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
    env["HOME"] = str(home)
    env.update(
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@e",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@e",
    )
    return env


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    root = tmp_path / "repo"
    root.mkdir()
    env = _git_env(tmp_path / "home")
    _run(["git", "init", "-q", "-b", "main"], root, env)
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('hi')\n")
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "base"], root, env)
    return root, env


def test_committed_passport_cannot_fake_a_pass(repo: tuple[Path, dict[str, str]]) -> None:
    """An attacker commits a PASS passport into the PR, then makes an out-of-scope
    change whose real verdict is BLOCK. The wrapper must fail the job (exit 1) and
    publish the REAL BLOCK passport, not the planted one."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo

    # Contract: only src/** is in scope (cooperative mode keeps this test focused
    # on the wrapper's fail-closed logic, not on signing).
    _run(["quill", "begin", "task: tidy src", "--scope", "src/**"], root, env)
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "contract"], root, env)

    # The PR makes an out-of-scope change -> real verify() yields BLOCK...
    (root / "PAYLOAD.txt").write_text("exfiltrate\n")
    # ...and plants a forged PASS passport in the repo-visible passport dir.
    quill_dir = root / ".quill"
    quill_dir.mkdir(exist_ok=True)
    (quill_dir / "passport.json").write_text(
        json.dumps({"verdict": "PASS", "exit_code": 0, "reasons": ["forged"]})
    )
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "pr"], root, env)

    proc = subprocess.run(
        ["bash", str(WRAPPER)],
        cwd=root,
        env={**env, "QUILL_STRICT": "false", "QUILL_PASSPORT_DIR": ".quill"},
        capture_output=True,
        text=True,
    )

    # The job fails on the real BLOCK, and the published passport is the real one.
    assert proc.returncode == 1, f"expected BLOCK exit 1, got {proc.returncode}: {proc.stderr}"
    published = json.loads((quill_dir / "passport.json").read_text())
    assert published["verdict"] == "BLOCK"
    assert "PAYLOAD.txt" in published["evidence"]["out_of_scope"]
