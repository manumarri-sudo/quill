"""Tests for the ESF ruleset compiler (quill.esf).

Covers ruleset shape, that the protected surface matches the Seatbelt
floor's single source of truth, and PARITY between the Python reference
verdict (is_path_protected) and the path logic the Swift PolicyEngine
implements. If these drift, the always-on ESF layer would protect a
different set of paths than the per-session Seatbelt floor.
"""
from __future__ import annotations

import json
import os

import pytest

from quill import esf, sandbox


def test_ruleset_shape() -> None:
    rs = esf.compile_ruleset()
    assert rs["version"] == esf.RULESET_VERSION
    assert rs["fail_closed"] is True
    assert isinstance(rs["protected_files"], list)
    assert isinstance(rs["protected_prefixes"], list)
    assert "AUTH_UNLINK" in rs["watched_events"]


def test_ruleset_is_json_serializable() -> None:
    rs = esf.compile_ruleset()
    blob = json.dumps(rs)
    assert json.loads(blob) == rs


def test_protected_surface_matches_seatbelt_source_of_truth() -> None:
    """ESF protected paths must be exactly the canonicalized Seatbelt set."""
    rs = esf.compile_ruleset()
    files, trees = sandbox.default_protected()
    want_files = sorted({c for p in files if (c := sandbox._canonical(p))})
    want_prefixes = sorted({c for p in trees if (c := sandbox._canonical(p))})
    assert rs["protected_files"] == want_files
    assert rs["protected_prefixes"] == want_prefixes


def test_covers_gate_disable_surface() -> None:
    rs = esf.compile_ruleset()
    joined = " ".join(rs["protected_files"] + rs["protected_prefixes"])
    assert ".claude/settings.json" in joined
    assert ".claude/hooks" in joined        # the A2 hole, always-on
    assert ".quill/config.toml" in joined
    assert ".quill/key" in joined


def test_is_path_protected_exact_file(tmp_path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text("x")
    rs = {"protected_files": [os.path.realpath(str(cfg))], "protected_prefixes": []}
    assert esf.is_path_protected(str(cfg), rs) is True


def test_is_path_protected_under_prefix(tmp_path) -> None:
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    target = hooks / "pre-bash.sh"
    target.write_text("x")
    rs = {"protected_files": [], "protected_prefixes": [os.path.realpath(str(hooks))]}
    assert esf.is_path_protected(str(target), rs) is True


def test_is_path_protected_prefix_boundary_no_false_match(tmp_path) -> None:
    """A sibling sharing a name prefix must NOT be treated as protected."""
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    sibling = tmp_path / "hooks-backup"
    sibling.mkdir()
    decoy = sibling / "x"
    decoy.write_text("x")
    rs = {"protected_files": [], "protected_prefixes": [os.path.realpath(str(hooks))]}
    assert esf.is_path_protected(str(decoy), rs) is False


def test_is_path_protected_allows_unrelated(tmp_path) -> None:
    other = tmp_path / "main.py"
    other.write_text("x")
    rs = {"protected_files": ["/nope/config.toml"], "protected_prefixes": ["/nope/hooks"]}
    assert esf.is_path_protected(str(other), rs) is False


def test_write_ruleset_roundtrip(tmp_path, monkeypatch) -> None:
    dest = tmp_path / "esf-rules.json"
    monkeypatch.setenv("QUILL_ESF_RULES", str(dest))
    p = esf.write_ruleset()
    assert p == dest
    loaded = json.loads(dest.read_text())
    assert loaded == esf.compile_ruleset()


def test_parity_python_reference_vs_compiled_ruleset(tmp_path) -> None:
    """The Python reference verdict agrees with the compiled ruleset on the
    real protected surface (this is what the Swift engine must mirror)."""
    rs = esf.compile_ruleset()
    # every protected file is judged protected
    for f in rs["protected_files"]:
        assert esf.is_path_protected(f, rs) is True
    # a path under each prefix is judged protected
    for pre in rs["protected_prefixes"]:
        assert esf.is_path_protected(os.path.join(pre, "child"), rs) is True
