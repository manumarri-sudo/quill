"""Policy primitive tests: Risk, Scope, SessionIntent.

The classifier is the most security-load-bearing piece: if a dangerous
action escapes classification, the gate doesn't fire. These tests pin the
defaults.
"""
from __future__ import annotations

import pytest

from quill.policy import Risk, Scope, SessionIntent, classify


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        # destructive filesystem
        ("fs.delete", Risk.CRITICAL),
        ("fs.delete_file", Risk.CRITICAL),
        ("filesystem.delete_directory", Risk.CRITICAL),
        # dangerous git
        ("git.push --force", Risk.CRITICAL),
        ("github.delete_repository", Risk.CRITICAL),
        ("github.create_pull_request", Risk.CRITICAL),
        # database destructive
        ("postgres.drop_table", Risk.CRITICAL),
        ("postgres.truncate", Risk.CRITICAL),
        # production deploy
        ("deploy.production", Risk.CRITICAL),
        # money
        ("stripe.refunds.create", Risk.CRITICAL),
        ("stripe.charges.create", Risk.CRITICAL),
        # outbound communication
        ("email.send_email", Risk.CRITICAL),
        ("slack.send_message", Risk.CRITICAL),
    ],
)
def test_dangerous_actions_default_to_critical(tool: str, expected: Risk) -> None:
    assert classify(tool) == expected


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("fs.read_file", Risk.LOW),
        ("filesystem.read_directory", Risk.LOW),
        ("github.list_issues", Risk.LOW),
        ("github.get_pull_request", Risk.LOW),
    ],
)
def test_safe_reads_default_to_low(tool: str, expected: Risk) -> None:
    assert classify(tool) == expected


def test_unknown_action_defaults_to_medium() -> None:
    assert classify("custom.unrecognized_action") == Risk.MEDIUM


# ---- Scope ---------------------------------------------------------------


def test_scope_parse_simple() -> None:
    s = Scope.parse("payments:refund")
    assert s.namespace == "payments"
    assert s.action == "refund"
    assert s.resource is None


def test_scope_parse_with_resource() -> None:
    s = Scope.parse("payments:refund:customer:c_8e4f")
    assert s.namespace == "payments"
    assert s.action == "refund"
    assert s.resource == "customer:c_8e4f"


def test_scope_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="invalid scope"):
        Scope.parse("just_one_segment")


def test_scope_matches_namespace() -> None:
    s = Scope.parse("payments:refund")
    assert s.matches_tool("payments.refund", args={"amount": 20})
    assert not s.matches_tool("filesystem.delete", args={"path": "/etc"})


def test_scope_matches_resource_segment() -> None:
    s = Scope.parse("payments:refund:customer:c_8e4f")
    assert s.matches_tool("payments.refund", args={"customer_id": "c_8e4f"})
    assert not s.matches_tool("payments.refund", args={"customer_id": "c_X"})


def test_scope_no_resource_means_namespace_only() -> None:
    s = Scope.parse("filesystem:read")
    assert s.matches_tool("filesystem.read_file", args={})
    assert s.matches_tool("filesystem.read_file", args={"path": "/anywhere"})


# ---- SessionIntent --------------------------------------------------------


def test_session_intent_blocks_unscoped() -> None:
    intent = SessionIntent(
        session_id="ses_alpha",
        intent="help c_8e4f",
        scope=(Scope.parse("payments:refund:customer:c_8e4f"),),
    )
    assert intent.covers("payments.refund", {"customer_id": "c_8e4f"})
    assert not intent.covers("payments.refund", {"customer_id": "c_X"})
    assert not intent.covers("fs.delete", {"path": "/etc/passwd"})


def test_session_intent_explains_why() -> None:
    intent = SessionIntent(
        session_id="ses_alpha",
        intent="help c_8e4f",
        scope=(Scope.parse("payments:refund:customer:c_8e4f"),),
    )
    reason = intent.in_scope_reason("fs.delete", {"path": "/etc/passwd"})
    assert reason is not None
    assert "fs.delete" in reason
    assert "allow-list" in reason or "scope" in reason.lower()
    assert "/etc/passwd" in reason


def test_empty_scope_blocks_everything() -> None:
    """A SessionIntent with no scope grants nothing — operator must be explicit."""
    intent = SessionIntent(
        session_id="ses_alpha",
        intent="help c_8e4f",
        scope=(),
    )
    assert not intent.covers("anything.at_all", {})
