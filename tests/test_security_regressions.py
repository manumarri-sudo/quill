"""Regression tests for security review findings (rounds 1-5).

Each test covers a specific vulnerability that was found and fixed, ensuring
it cannot silently regress. Tests are named after the finding ID they cover.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from quill import contract as contract_mod
from quill import perimeter as perimeter_mod
from quill import verify as verify_mod
from quill.policy import _glob_segments, classify_sensitive_surface
from quill.verify import Verdict


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True,
    )
    return r.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@e")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "app.py").write_text("x = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


# ── H-1: base_commit option injection ─────────────────────────────────────────

class TestH1BaseCommitOptionInjection:
    """A crafted contract.base_commit like '--output=/tmp/x' must not be
    passed raw to git, where it would be interpreted as an option."""

    def test_option_injection_blocked_strict(self, repo: Path) -> None:
        contract = contract_mod.Contract(
            version=1,
            task="test",
            task_source="text",
            allowed_paths=("**",),
            base_commit="--output=/tmp/exfil",
            created_at="2026-01-01T00:00:00Z",
            contract_id="test-h1",
        )
        result = verify_mod.verify(contract=contract, root=repo, strict=True)
        assert result.verdict is Verdict.BLOCK
        assert any("not a valid commit SHA" in r for r in result.reasons)

    def test_option_injection_tolerated_cooperative(self, repo: Path) -> None:
        contract = contract_mod.Contract(
            version=1,
            task="test",
            task_source="text",
            allowed_paths=("**",),
            base_commit="--output=/tmp/exfil",
            created_at="2026-01-01T00:00:00Z",
            contract_id="test-h1",
        )
        result = verify_mod.verify(contract=contract, root=repo, strict=False)
        assert result.verdict is not None  # doesn't crash

    def test_valid_sha_accepted(self, repo: Path) -> None:
        sha = _git(repo, "rev-parse", "HEAD")
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        assert contract.base_commit is not None
        result = verify_mod.verify(contract=contract, root=repo)
        assert result.verdict is Verdict.PASS


# ── H-2: strict mode requires contract.repo ──────────────────────────────────

class TestH2StrictRequiresRepo:
    """In strict mode, when the environment identifies a repo (GITHUB_REPOSITORY),
    a contract without a repo binding must BLOCK — prevents cross-repo replay."""

    def test_missing_repo_blocks_strict(self, repo: Path) -> None:
        contract, _ = contract_mod.begin(
            "test task", allowed_paths=["**"], root=repo,
        )
        assert contract.repo is None
        env = {"GITHUB_REPOSITORY": "owner/name"}
        result = verify_mod.verify(
            contract=contract, root=repo, strict=True, env=env,
        )
        assert result.verdict is Verdict.BLOCK
        assert any("no repository binding" in r for r in result.reasons)

    def test_matching_repo_passes_strict(self, repo: Path) -> None:
        contract, _ = contract_mod.begin(
            "test task", allowed_paths=["**"], root=repo, repo="owner/name",
        )
        env = {"GITHUB_REPOSITORY": "owner/name"}
        result = verify_mod.verify(
            contract=contract, root=repo, strict=True, env=env,
        )
        assert result.verdict is not Verdict.BLOCK or not any(
            "repository" in r for r in result.reasons
        )

    def test_mismatched_repo_blocks_strict(self, repo: Path) -> None:
        contract, _ = contract_mod.begin(
            "test task", allowed_paths=["**"], root=repo, repo="owner/other",
        )
        env = {"GITHUB_REPOSITORY": "owner/name"}
        result = verify_mod.verify(
            contract=contract, root=repo, strict=True, env=env,
        )
        assert result.verdict is Verdict.BLOCK
        assert any("repo" in r.lower() for r in result.reasons)


# ── H-4: renamed file secret detection ───────────────────────────────────────

def _fake_openai_key() -> str:
    """Build a string that matches the OpenAI Project API Key pattern without
    embedding a literal secret in the source file."""
    return "sk-" + "proj-" + "a" * 60


class TestH4RenameSecretDetection:
    """A 100% rename produces no added lines in the diff, so secrets in the
    renamed file must be caught via blob-level scanning."""

    def test_renamed_file_with_secret_detected(self, repo: Path) -> None:
        (repo / "src" / "config.py").write_text(
            f"API_KEY = '{_fake_openai_key()}'\n"
        )
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add config with secret")
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "settings.py").write_text(
            (repo / "src" / "config.py").read_text()
        )
        (repo / "src" / "config.py").unlink()
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "rename config to settings")
        result = verify_mod.verify(contract=contract, root=repo)
        has_secret = bool(result.secret_findings)
        assert has_secret, "renamed file's secret should be detected via blob scan"

    def test_renamed_file_without_secret_clean(self, repo: Path) -> None:
        (repo / "src" / "utils.py").write_text("def helper(): pass\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add utils")
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "helpers.py").write_text(
            (repo / "src" / "utils.py").read_text()
        )
        (repo / "src" / "utils.py").unlink()
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "rename utils to helpers")
        result = verify_mod.verify(contract=contract, root=repo)
        assert not result.secret_findings


# ── M-2: deep path glob recursion ────────────────────────────────────────────

class TestM2DeepPathGlob:
    """A very deep path (1600+ segments) with ** patterns must not blow the
    stack; the DP-memoized matcher handles it in O(n*m)."""

    def test_deep_path_does_not_recurse(self) -> None:
        deep = ["a"] * 1600
        pat = ["**", "a"]
        assert _glob_segments(deep, pat) is True

    def test_deep_path_no_match(self) -> None:
        deep = ["a"] * 1600
        pat = ["**", "b"]
        assert _glob_segments(deep, pat) is False

    def test_deep_path_multiple_stars(self) -> None:
        deep = ["a", "b"] * 800
        pat = ["**", "a", "**", "b"]
        assert _glob_segments(deep, pat) is True

    def test_shallow_path_still_works(self) -> None:
        assert _glob_segments(["src", "app.py"], ["src", "**"]) is True
        assert _glob_segments(["src", "app.py"], ["**", "*.py"]) is True
        assert _glob_segments(["src", "app.py"], ["lib", "**"]) is False


# ── H-3: wrapper strict requires head_commit ─────────────────────────────────
# (Covered in test_action_wrapper.py via the fake quill; this is a unit-level
# regression for the verify() function itself.)

class TestH3CandidateBinding:
    """The passport must contain a head_commit that matches the evaluated ref,
    so evidence can't describe a different candidate."""

    def test_head_commit_populated(self, repo: Path) -> None:
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "new.py").write_text("y = 2\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "change")
        result = verify_mod.verify(contract=contract, root=repo)
        assert result.head_commit is not None
        assert len(result.head_commit) >= 7
