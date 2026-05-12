"""Notification handler tests - observation + audit + downstream forward.

Covers: every known kind dispatches to the right audit event_type, exceptions
never escape, the forwarder receives correct calls, the pin-cache invalidator
fires only on tools/list_changed, missing/unknown notifications still get
audit-logged.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from quill.audit import AuditLog
from quill.notifications import (
    DownstreamForwarder,
    _classify,
    make_message_handler,
)


class _RecordingForwarder(DownstreamForwarder):
    """Forwarder that records what was forwarded for assertions."""

    def __init__(self) -> None:
        super().__init__()
        # Bypass the "no session" early-return.
        self.set_session(SimpleNamespace())  # truthy stand-in
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def forward_tools_changed(self) -> None:
        self.calls.append(("tools_changed", {}))

    async def forward_resources_changed(self) -> None:
        self.calls.append(("resources_changed", {}))

    async def forward_prompts_changed(self) -> None:
        self.calls.append(("prompts_changed", {}))

    async def forward_resource_updated(self, uri: Any) -> None:
        self.calls.append(("resource_updated", {"uri": uri}))

    async def forward_log(self, *, level: str, data: Any, logger: str | None) -> None:
        self.calls.append(("log", {"level": level, "data": data, "logger": logger}))

    async def forward_progress(
        self, *, progress_token: Any, progress: float, total: float | None,
    ) -> None:
        self.calls.append(
            ("progress", {"token": progress_token, "progress": progress, "total": total}),
        )


class _RecordingInvalidator:
    def __init__(self) -> None:
        self.invalidations: list[str] = []

    def invalidate(self, upstream: str) -> None:
        self.invalidations.append(upstream)


def _audit_lines(p: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in p.read_text().splitlines() if line]


def _fake_notif(class_name: str, **params: Any) -> Any:
    """Build a stand-in for ServerNotification without depending on mcp internals.

    The handler reads `.root` (the inner notification) and `type(root).__name__`
    for kind detection. We construct a SimpleNamespace whose `.root` has the
    right class name via a dynamically-created class.
    """
    NotifClass = type(class_name, (), {})

    class _ParamsObj:
        def __init__(self, **kw: Any) -> None:
            for k, v in kw.items():
                setattr(self, k, v)

        def model_dump(self) -> dict[str, Any]:
            return {k: getattr(self, k) for k in dir(self) if not k.startswith("_") and k != "model_dump"}

    root = NotifClass()
    if params:
        root.params = _ParamsObj(**params)
    return SimpleNamespace(root=root)


# -----------------------------------------------------------------------------
# classify


def test_classify_handles_each_known_kind() -> None:
    cases = {
        "ToolListChangedNotification":     "upstream.tools.list_changed",
        "ToolsListChangedNotification":    "upstream.tools.list_changed",
        "ResourceListChangedNotification": "upstream.resources.list_changed",
        "PromptListChangedNotification":   "upstream.prompts.list_changed",
        "ResourceUpdatedNotification":     "upstream.resource.updated",
        "LoggingMessageNotification":      "upstream.log",
        "ProgressNotification":            "upstream.progress",
        "CancelledNotification":           "upstream.cancelled",
    }
    for name, expected in cases.items():
        cls = type(name, (), {})
        assert _classify(cls()) == expected, name


def test_classify_unknown_kind_does_not_drop_it() -> None:
    cls = type("WeirdNewNotification", (), {})
    assert _classify(cls()) == "upstream.notification.unknown"


# -----------------------------------------------------------------------------
# handler


@pytest.mark.asyncio
async def test_handler_audit_logs_tools_list_changed_and_invalidates_and_forwards(
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "a.jsonl"
    invalidator = _RecordingInvalidator()
    forwarder = _RecordingForwarder()
    with AuditLog(path=audit_path, hmac_key=b"k" * 32) as audit:
        h = make_message_handler(
            upstream_name="filesystem",
            audit=audit,
            session_id="ses-1",
            forwarder=forwarder,
            invalidator=invalidator,
        )
        await h(_fake_notif("ToolListChangedNotification"))

    lines = _audit_lines(audit_path)
    types = [l["type"] for l in lines]
    assert "upstream.tools.list_changed" in types
    assert invalidator.invalidations == ["filesystem"]
    assert forwarder.calls == [("tools_changed", {})]


@pytest.mark.asyncio
async def test_handler_logs_progress_and_forwards(tmp_path: Path) -> None:
    forwarder = _RecordingForwarder()
    with AuditLog(path=tmp_path / "a.jsonl", hmac_key=b"k" * 32) as audit:
        h = make_message_handler(
            upstream_name="github", audit=audit,
            session_id="ses-1", forwarder=forwarder,
        )
        await h(_fake_notif(
            "ProgressNotification",
            progressToken="t-1", progress=0.5, total=1.0,
        ))

    assert forwarder.calls == [
        ("progress", {"token": "t-1", "progress": 0.5, "total": 1.0}),
    ]


@pytest.mark.asyncio
async def test_handler_logs_log_message_and_forwards(tmp_path: Path) -> None:
    forwarder = _RecordingForwarder()
    with AuditLog(path=tmp_path / "a.jsonl", hmac_key=b"k" * 32) as audit:
        h = make_message_handler(
            upstream_name="postgres", audit=audit,
            session_id="ses-1", forwarder=forwarder,
        )
        await h(_fake_notif(
            "LoggingMessageNotification",
            level="warning", data="slow query", logger="postgres",
        ))

    kinds = [c[0] for c in forwarder.calls]
    assert "log" in kinds


@pytest.mark.asyncio
async def test_handler_resource_changes_forward_separately(tmp_path: Path) -> None:
    forwarder = _RecordingForwarder()
    with AuditLog(path=tmp_path / "a.jsonl", hmac_key=b"k" * 32) as audit:
        h = make_message_handler(
            upstream_name="fs", audit=audit, session_id="s",
            forwarder=forwarder,
        )
        await h(_fake_notif("ResourceListChangedNotification"))
        await h(_fake_notif("PromptListChangedNotification"))
        await h(_fake_notif("ResourceUpdatedNotification", uri="file:///x"))

    kinds = [c[0] for c in forwarder.calls]
    assert kinds == ["resources_changed", "prompts_changed", "resource_updated"]


@pytest.mark.asyncio
async def test_handler_logs_transport_exception_force_fsync(tmp_path: Path) -> None:
    audit_path = tmp_path / "a.jsonl"
    with AuditLog(path=audit_path, hmac_key=b"k" * 32) as audit:
        h = make_message_handler(
            upstream_name="x", audit=audit, session_id="s",
            forwarder=DownstreamForwarder(),
        )
        await h(ConnectionResetError("upstream pipe broken"))
    line = _audit_lines(audit_path)[0]
    assert line["type"] == "upstream.error"
    assert line["risk"] == "high"
    assert "ConnectionResetError" in line["payload"]["error_type"]


@pytest.mark.asyncio
async def test_handler_never_raises_on_garbage(tmp_path: Path) -> None:
    """The mcp SDK's session loop dies if the message_handler raises.
    Random bad input must NOT propagate out."""
    with AuditLog(path=tmp_path / "a.jsonl", hmac_key=b"k" * 32) as audit:
        h = make_message_handler(
            upstream_name="x", audit=audit, session_id="s",
            forwarder=DownstreamForwarder(),
        )
        # None, empty, raw dict, object without .root - all must be no-op.
        await h(None)
        await h({})
        await h(SimpleNamespace())
        await h(SimpleNamespace(root=None))


@pytest.mark.asyncio
async def test_handler_only_invalidates_on_tools_list_changed(tmp_path: Path) -> None:
    """Pin-cache invalidate is specific: resources/list_changed must NOT
    invalidate the tool pin cache (different concern).
    """
    invalidator = _RecordingInvalidator()
    with AuditLog(path=tmp_path / "a.jsonl", hmac_key=b"k" * 32) as audit:
        h = make_message_handler(
            upstream_name="x", audit=audit, session_id="s",
            forwarder=_RecordingForwarder(),
            invalidator=invalidator,
        )
        await h(_fake_notif("ResourceListChangedNotification"))
        await h(_fake_notif("PromptListChangedNotification"))
        await h(_fake_notif("LoggingMessageNotification", level="info", data="x", logger="l"))
        assert invalidator.invalidations == []
        await h(_fake_notif("ToolListChangedNotification"))
        assert invalidator.invalidations == ["x"]


@pytest.mark.asyncio
async def test_forwarder_no_session_is_silent_noop(tmp_path: Path) -> None:
    """Before the downstream client connects, forwarder methods must early-return.
    Notifications still get audit-logged."""
    audit_path = tmp_path / "a.jsonl"
    forwarder = DownstreamForwarder()  # no session set
    assert forwarder.has_session is False
    with AuditLog(path=audit_path, hmac_key=b"k" * 32) as audit:
        h = make_message_handler(
            upstream_name="x", audit=audit, session_id="s",
            forwarder=forwarder,
        )
        await h(_fake_notif("ToolListChangedNotification"))
    types = [l["type"] for l in _audit_lines(audit_path)]
    assert "upstream.tools.list_changed" in types
