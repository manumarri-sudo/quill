"""End-to-end tests for the Change Control trust spine.

The properties under test are the ones that make "I don't watch the agent, I
trust the boundary" actually true:

  * A human signs the perimeter once; many diffs verify against it (approve-once,
    scale-to-many).
  * A diff that touches a forbidden path, a gate-tamper surface, or a secret is
    BLOCKed without any human in the loop.
  * In strict mode an unsigned / tampered / unestablished perimeter is BLOCKed,
    so a missing guarantee never silently passes.
  * An agent cannot bootstrap its own trust: committing its own approver key (to
    self-sign the perimeter) is itself a gate-tamper BLOCK.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from quill import attest
from quill import contract as contract_mod
from quill import perimeter as perimeter_mod
from quill import provenance as provenance_mod
from quill import verify as verify_mod
from quill.verify import Verdict


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "base")
    return tmp_path


def _approver(repo: Path) -> str:
    """Create an approver keypair, commit the pubkey, return the private PEM."""
    priv_pem, pub_pem = attest.generate_keypair()
    d = perimeter_mod.signature_path(repo).parent / "approvers"
    d.mkdir(parents=True, exist_ok=True)
    (d / "human.pub").write_text(pub_pem)
    return priv_pem


def _sign_perimeter(repo: Path, priv_pem: str, *, forbidden: tuple[str, ...] = ()) -> None:
    p = perimeter_mod.default_perimeter(forbidden_paths=forbidden, approved_by="human")
    p.write(repo)
    provenance_mod.sign_artifact(p.to_dict(), priv_pem, perimeter_mod.signature_path(repo))


def _begin(repo: Path) -> contract_mod.Contract:
    """Commit the perimeter/approver setup into `base`, then capture a contract.

    In a real repo the signed perimeter and approver keys live on the base
    branch (committed once, out of band), so a feature PR's diff never contains
    them. Mirroring that here keeps the setup out of the gated diff; only changes
    committed *after* this call land in base..HEAD.
    """
    _git(repo, "add", "-A")
    if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=repo).returncode != 0:
        _git(repo, "commit", "-m", "perimeter setup")
    c, _ = contract_mod.begin("standing perimeter task", allowed_paths=(), root=repo)
    return c


def _commit_change(repo: Path, path: str, content: str) -> None:
    f = repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", f"change {path}")


def _verify(
    repo: Path, contract: contract_mod.Contract, *, strict: bool = True
) -> verify_mod.VerifyResult:
    return verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=strict,
    )


# --------------------------------------------------------------------------- #


def test_signed_perimeter_in_bounds_passes(repo: Path) -> None:
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = _verify(repo, contract)
    assert result.verdict is Verdict.PASS
    assert result.provenance is not None
    assert result.provenance.status is provenance_mod.ProvenanceStatus.OK


def test_approve_once_scale_to_many(repo: Path) -> None:
    """One signature validates many independent diffs - no re-signing per change."""
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    for i in range(5):
        contract = _begin(repo)
        _commit_change(repo, f"src/f{i}.py", f"v = {i}\n")
        assert _verify(repo, contract).verdict is Verdict.PASS


def test_forbidden_path_blocks(repo: Path) -> None:
    priv = _approver(repo)
    _sign_perimeter(repo, priv, forbidden=("src/auth/**",))
    contract = _begin(repo)
    _commit_change(repo, "src/auth/login.py", "secret_logic = 1\n")
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert any("forbidden" in r for r in result.reasons)
    assert "src/auth/login.py" in result.forbidden_hits


def test_gate_tamper_workflow_edit_blocks(repo: Path) -> None:
    """Editing the workflow that runs the gate is always a BLOCK."""
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo)
    _commit_change(repo, ".github/workflows/ci.yml", "name: ci\non: push\n")
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert result.gate_tamper_hits


def test_agent_cannot_bootstrap_trust_by_committing_its_own_key(repo: Path) -> None:
    """The key adversarial property: an agent that adds its own approver key to
    self-sign the perimeter trips the gate-tamper rule on `.quill/approvers/**`,
    so it can never authorize itself."""
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo)
    _, rogue_pub = attest.generate_keypair()
    _commit_change(repo, ".quill/approvers/rogue.pub", rogue_pub)
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert any(".quill/approvers/rogue.pub" in h for h in result.gate_tamper_hits)


def test_strict_unsigned_perimeter_blocks(repo: Path) -> None:
    """A perimeter with no approver keys configured cannot establish trust -> BLOCK."""
    p = perimeter_mod.default_perimeter()
    p.write(repo)  # no signature, no approvers
    contract = _begin(repo)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = _verify(repo, contract, strict=True)
    assert result.verdict is Verdict.BLOCK
    assert result.provenance is not None
    assert result.provenance.status is provenance_mod.ProvenanceStatus.NO_APPROVERS


def test_strict_tampered_perimeter_blocks(repo: Path) -> None:
    """Agent widens the perimeter after the human signed it -> signature invalid."""
    priv = _approver(repo)
    _sign_perimeter(repo, priv, forbidden=("src/auth/**",))
    # Tamper: rewrite the perimeter to drop the forbidden path, keep the old sig.
    perimeter_mod.default_perimeter(forbidden_paths=()).write(repo)
    contract = _begin(repo)
    _commit_change(repo, "src/auth/login.py", "x = 1\n")
    result = _verify(repo, contract, strict=True)
    assert result.verdict is Verdict.BLOCK
    assert result.provenance is not None
    assert result.provenance.status is provenance_mod.ProvenanceStatus.BAD_SIGNATURE


def test_strict_no_perimeter_blocks(repo: Path) -> None:
    contract = _begin(repo)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = verify_mod.verify(contract=contract, root=repo, perimeter=None, strict=True)
    assert result.verdict is Verdict.BLOCK


def test_env_pinned_approver_without_committed_dir(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adversarial-safe path: approver pubkey comes from a CI secret (env),
    not the repo, and validates the signature."""
    priv_pem, pub_pem = attest.generate_keypair()
    p = perimeter_mod.default_perimeter()
    p.write(repo)
    provenance_mod.sign_artifact(p.to_dict(), priv_pem, perimeter_mod.signature_path(repo))
    monkeypatch.setenv(provenance_mod.APPROVER_ENV, pub_pem)
    contract = _begin(repo)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    import os

    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=True,
        env=dict(os.environ),
    )
    assert result.verdict is Verdict.PASS
    assert result.provenance is not None
    assert result.provenance.status is provenance_mod.ProvenanceStatus.OK


def test_secret_on_added_line_blocks(repo: Path) -> None:
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo)
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    _commit_change(repo, "src/config.py", f'KEY = "{key}"\n')
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert result.secret_findings
