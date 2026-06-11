"""Tests for the Seatbelt sandbox floor (quill.sandbox).

These assert the SBPL structure invariants that make the profile correct:
last-match-wins ordering, canonical paths, the allow-default floor vs the
seal allowlist, and the loopback-only egress block. The numeric-IP network
filter is a regression guard - `sandbox-exec` rejects `(remote ip "127.0.0.1:*")`
with "host must be * or localhost", which a live run caught.
"""

from __future__ import annotations

import os

from quill import sandbox as sb


def _seal_spec() -> sb.SandboxSpec:
    files, trees = sb.default_protected()
    return sb.SandboxSpec(
        writable=["/Users/x/proj", "/private/tmp"],
        protected_files=files,
        protected_trees=trees,
        confine_writes=True,
        network="localhost",
    )


def test_floor_is_allow_default_with_no_blanket_write_deny() -> None:
    spec = sb.SandboxSpec(
        protected_files=["~/.quill/config.toml"],
        protected_trees=["~/.claude/hooks"],
        confine_writes=False,
        network="all",
    )
    prof = sb.build_profile(spec)
    assert prof.startswith("(version 1)")
    assert "(allow default)" in prof
    # floor must NOT blanket-deny writes (would break dev tooling)
    assert "(deny file-write*)" not in prof
    # floor has no network block
    assert "(deny network*)" not in prof
    # the gate-disable surface is denied
    assert "(deny file-write*" in prof


def test_seal_confines_writes_and_seals_egress() -> None:
    prof = sb.build_profile(_seal_spec())
    assert "(deny file-write*)" in prof  # blanket write deny
    assert "(allow file-write*" in prof  # then the allowlist
    assert "(deny network*)" in prof  # egress sealed
    assert '(remote ip "localhost:*")' in prof


def test_protected_deny_comes_after_allow_block_last_match_wins() -> None:
    """The protected deny must render AFTER the allow block so it wins."""
    prof = sb.build_profile(_seal_spec())
    allow_idx = prof.index("(allow file-write*")
    # the protected deny block is the one carrying the gate config literal
    deny_idx = prof.index("config.toml")
    assert deny_idx > allow_idx, "protected deny must come after the allowlist"


def test_no_numeric_ip_in_network_filter_regression() -> None:
    """sandbox-exec rejects numeric IPs in network filters; only * / localhost."""
    prof = sb.build_profile(_seal_spec())
    assert "127.0.0.1" not in prof
    assert "(remote ip" in prof  # the localhost form is still present


def test_paths_are_canonicalized() -> None:
    """`/tmp` is a symlink to `/private/tmp`; an uncanonical path silently
    matches nothing, so the renderer must resolve it."""
    spec = sb.SandboxSpec(writable=["/tmp"], confine_writes=True, network="all")
    prof = sb.build_profile(spec)
    if os.path.realpath("/tmp") == "/private/tmp":
        assert '"/private/tmp"' in prof
        # the raw symlink form should not appear as a write rule
        assert '(subpath "/tmp")' not in prof


def test_sbpl_string_escapes_quotes_and_backslashes() -> None:
    assert sb._sbpl_str('a"b') == 'a\\"b'
    assert sb._sbpl_str("a\\b") == "a\\\\b"


def test_dedupe_preserves_order() -> None:
    assert sb._dedupe(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


def test_canonical_returns_none_on_bad_input() -> None:
    assert sb._canonical("") is None
    assert sb._canonical(None) is None  # type: ignore[arg-type]


def test_default_protected_covers_gate_disable_surface() -> None:
    files, trees = sb.default_protected()
    joined = " ".join(files + trees)
    assert ".claude/settings.json" in joined
    assert ".claude/hooks" in joined  # the A2 hole
    assert ".quill/config.toml" in joined
    assert ".quill/key" in joined
    assert ".zshrc" in joined  # shell rc persistence vector


def test_launch_argv_shape() -> None:
    from pathlib import Path

    argv = sb.launch_argv(Path("/tmp/p.sb"), ["python3", "x.py"])
    assert argv == ["sandbox-exec", "-f", "/tmp/p.sb", "--", "python3", "x.py"]


def test_build_spec_floor_has_empty_writable() -> None:
    spec = sb.build_spec(cwd="/Users/x/proj", confine_writes=False, seal_network=False)
    assert spec.writable == []  # floor needs no allowlist
    assert spec.network == "all"
    assert spec.protected_files  # but always protects the gate surface


def test_build_spec_seal_includes_cwd_and_gate_state() -> None:
    spec = sb.build_spec(cwd="/Users/x/proj", confine_writes=True, seal_network=True)
    assert "/Users/x/proj" in spec.writable
    assert spec.network == "localhost"
    # gate + harness state must stay writable so logging/session survive
    assert any(".quill" in p for p in spec.writable)
    assert any(".claude" in p for p in spec.writable)
