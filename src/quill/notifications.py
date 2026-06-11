"""Bidirectional notification forwarding + sampling refusal for the MCP proxy.

Wires a `message_handler` callback to each upstream's `ClientSession`. The
callback fires on every server-initiated message: notifications, sampling
requests, transport errors. The handler:

  1. Audit-logs every notification with a stable `event_type`.
  2. Invalidates the proxy's tool-pin cache on `tools/list_changed`, so the
     next `list_tools` re-runs verification - catches both legitimate
     upstream upgrades AND rug-pull attacks.
  3. Forwards the notification downstream to the connected MCP client
     (Claude Code, Cursor, ...) so the client sees a live picture of the
     upstream state. Forwarding is gated by `DownstreamForwarder.set_session`
     - until the downstream session is established, notifications are
     audit-logged but not forwarded (no client to forward to yet).

Dispatch pattern adapted from IBM/mcp-context-forge `notification_service.py`
(Apache-2.0): we borrowed the class-name-substring matching idiom that
absorbs mcp-SDK type renames across versions. Their full NotificationService
has persistence, subscription tracking, and refresh queues - Quill doesn't
need any of that, so we kept the dispatch and dropped the rest.

Source: https://github.com/IBM/mcp-context-forge - credited in NOTICE.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from mcp.client.session import MessageHandlerFnT
from mcp.shared.session import RequestResponder

from quill.audit import AuditLog


class _PinCacheInvalidator(Protocol):
    """The proxy supplies this so the pump can drop tool-pin cache state on
    upstream tools/list_changed."""

    def invalidate(self, upstream: str) -> None: ...


# Class-name substring → audit event_type mapping.
# Substring match because the mcp SDK has used both
# ToolListChangedNotification and ToolsListChangedNotification at various
# versions; we match either.
_NOTIFICATION_KIND_MAP: dict[tuple[str, ...], str] = {
    ("ToolListChangedNotification", "ToolsListChangedNotification"): "upstream.tools.list_changed",
    (
        "ResourceListChangedNotification",
        "ResourcesListChangedNotification",
    ): "upstream.resources.list_changed",
    (
        "PromptListChangedNotification",
        "PromptsListChangedNotification",
    ): "upstream.prompts.list_changed",
    ("ResourceUpdatedNotification",): "upstream.resource.updated",
    ("LoggingMessageNotification",): "upstream.log",
    ("ProgressNotification",): "upstream.progress",
    ("CancelledNotification",): "upstream.cancelled",
}


def _classify(root: Any) -> str:
    """Map a notification's `.root` to a stable audit event_type.

    Returns "upstream.notification.unknown" for un-mapped types so we never
    silently drop upstream traffic from the chain.
    """
    name = type(root).__name__
    for fragments, event_type in _NOTIFICATION_KIND_MAP.items():
        if any(f in name for f in fragments):
            return event_type
    return "upstream.notification.unknown"


@dataclass(slots=True)
class DownstreamForwarder:
    """Holds a reference to the live downstream `ServerSession`.

    The proxy creates one of these and calls `set_session` once the downstream
    `Server.run()` has its session up. The notification handler closes over
    this object so it can forward to the client whenever the upstream emits
    a server-push event.

    All forward methods early-return if `_session is None`. That's the
    correct behavior on startup before the client has connected - there's
    nobody downstream to forward to yet, but the upstream may already be
    chattering.
    """

    _session: Any = field(default=None)
    _audit: AuditLog | None = field(default=None)

    def set_session(self, session: Any) -> None:
        self._session = session

    def clear(self) -> None:
        self._session = None

    @property
    def has_session(self) -> bool:
        return self._session is not None

    async def forward_tools_changed(self) -> None:
        if self._session is None:
            return
        with contextlib.suppress(Exception):
            await self._session.send_tool_list_changed()

    async def forward_resources_changed(self) -> None:
        if self._session is None:
            return
        with contextlib.suppress(Exception):
            await self._session.send_resource_list_changed()

    async def forward_prompts_changed(self) -> None:
        if self._session is None:
            return
        with contextlib.suppress(Exception):
            await self._session.send_prompt_list_changed()

    async def forward_resource_updated(self, uri: Any) -> None:
        if self._session is None:
            return
        with contextlib.suppress(Exception):
            await self._session.send_resource_updated(uri)

    async def forward_log(self, *, level: str, data: Any, logger: str | None) -> None:
        if self._session is None:
            return
        with contextlib.suppress(Exception):
            await self._session.send_log_message(level=level, data=data, logger=logger)

    async def forward_progress(
        self,
        *,
        progress_token: Any,
        progress: float,
        total: float | None,
    ) -> None:
        if self._session is None:
            return
        with contextlib.suppress(Exception):
            await self._session.send_progress_notification(
                progress_token=progress_token,
                progress=progress,
                total=total,
            )


def make_message_handler(
    *,
    upstream_name: str,
    audit: AuditLog,
    session_id: str,
    forwarder: DownstreamForwarder | None = None,
    invalidator: _PinCacheInvalidator | None = None,
) -> MessageHandlerFnT:
    """Build the `message_handler` callback for `ClientSession`.

    Pass to ClientSession at construction:
        ClientSession(read, write, message_handler=make_message_handler(...))

    The callback:
      1. Audit-logs every server-initiated message (notifications, sampling
         requests, transport errors) with a stable event_type.
      2. On `tools/list_changed`, invalidates the proxy's pin cache so the
         next list_tools re-verifies fingerprints against the new upstream
         tool set (catches a benign upgrade AND a malicious rug-pull alike).
      3. Forwards every notification downstream to the connected MCP client
         via `forwarder` so the client sees a live picture of upstream state.
      4. Logs sampling/elicitation/list_roots requests at "upstream.request"
         (not yet forwarded; that's a v0.2 follow-up, since the gate must
         decide whether to allow the upstream to ask the client for an LLM
         call).
      5. Never raises. The mcp SDK's session loop dies if the handler raises;
         a notification handler that crashes the gate is the worst possible
         failure mode.
    """

    async def handler(message: Any) -> None:
        try:
            # ---- transport / decoding error ---------------------------
            if isinstance(message, Exception):
                with contextlib.suppress(Exception):
                    audit.emit(
                        event_type="upstream.error",
                        session_id=session_id,
                        agent_id=f"upstream:{upstream_name}",
                        risk="high",
                        payload={
                            "upstream": upstream_name,
                            "error_type": type(message).__name__,
                            "error_repr": repr(message)[:512],
                        },
                        force_fsync=True,
                    )
                return

            # ---- server-initiated request (sampling/elicitation) -----
            if isinstance(message, RequestResponder):
                # Observed but not yet auto-forwarded. The gate has to
                # adjudicate before letting upstream make the client do
                # an LLM call - that lands in the v0.2 sampling work.
                with contextlib.suppress(Exception):
                    audit.emit(
                        event_type="upstream.request",
                        session_id=session_id,
                        agent_id=f"upstream:{upstream_name}",
                        risk="medium",
                        payload={
                            "upstream": upstream_name,
                            "request_type": type(getattr(message, "request", None)).__name__,
                        },
                    )
                return

            # ---- server-initiated notification -----------------------
            root = getattr(message, "root", None)
            if root is None:
                return
            kind = type(root).__name__
            event_type = _classify(root)

            # Redacted audit payload: keys only, no values, since
            # LoggingMessageNotification can carry data the upstream chose
            # to emit and we don't want it in the chain.
            payload: dict[str, Any] = {"upstream": upstream_name, "kind": kind}
            params = getattr(root, "params", None)
            if params is not None:
                with contextlib.suppress(Exception):
                    if hasattr(params, "model_dump"):
                        payload["param_keys"] = sorted(params.model_dump().keys())

            with contextlib.suppress(Exception):
                audit.emit(
                    event_type=event_type,
                    session_id=session_id,
                    agent_id=f"upstream:{upstream_name}",
                    risk="low",
                    payload=payload,
                )

            # ---- side effects on specific kinds ----------------------
            if forwarder is None:
                return

            if event_type == "upstream.tools.list_changed":
                if invalidator is not None:
                    with contextlib.suppress(Exception):
                        invalidator.invalidate(upstream_name)
                await forwarder.forward_tools_changed()

            elif event_type == "upstream.resources.list_changed":
                await forwarder.forward_resources_changed()

            elif event_type == "upstream.prompts.list_changed":
                await forwarder.forward_prompts_changed()

            elif event_type == "upstream.resource.updated":
                with contextlib.suppress(Exception):
                    await forwarder.forward_resource_updated(getattr(params, "uri", ""))

            elif event_type == "upstream.log":
                with contextlib.suppress(Exception):
                    await forwarder.forward_log(
                        level=str(getattr(params, "level", "info")),
                        data=getattr(params, "data", None),
                        logger=getattr(params, "logger", None),
                    )

            elif event_type == "upstream.progress":
                with contextlib.suppress(Exception):
                    await forwarder.forward_progress(
                        progress_token=getattr(params, "progressToken", None),
                        progress=float(getattr(params, "progress", 0.0) or 0.0),
                        total=getattr(params, "total", None),
                    )

            # cancelled is intentionally not auto-forwarded; the proxy's
            # task-cancellation logic owns that.
        except Exception:  # pragma: no cover - handler must never raise
            return

    return handler


def make_sampling_callback(
    *,
    upstream_name: str,
    audit: AuditLog,
    session_id: str,
    allow: bool = False,
) -> Any:
    """Adjudicate `sampling/createMessage` requests from an upstream MCP.

    Upstream MCP servers can ask Quill to invoke an LLM on their behalf
    via `sampling/createMessage`. The downstream client (Claude Code,
    Cursor) is the one with the LLM; without Quill in the middle, the
    upstream would talk directly to the client.

    The threat: an attacker-controlled upstream uses sampling to make
    the client's LLM do attacker work - e.g. "summarize this file at
    /etc/passwd" - laundering a read through the client's context.

    Default: REFUSE every sampling request. Quill emits an
    `upstream.sampling.refused` audit event so the user sees the
    attempt; the mcp SDK propagates an `ErrorData` back to the upstream
    so it knows sampling is unavailable.

    Opt-in (`allow=True`) is for trusted upstreams that legitimately
    use sampling. Even then, every request is audit-logged with the
    canonical hash of the messages array, so the user can review what
    the upstream asked for.

    Returns a callable suitable for ClientSession's `sampling_callback=`.
    """
    import hashlib

    import mcp.types as mcp_types

    async def _refuse(context: Any, params: mcp_types.CreateMessageRequestParams) -> Any:
        # Hash the messages array so the audit shows shape but not content.
        try:
            body = params.model_dump() if hasattr(params, "model_dump") else {}
        except Exception:
            body = {}
        digest = hashlib.sha256(
            (str(body.get("messages") or "") + str(body.get("modelPreferences") or "")).encode()
        ).hexdigest()
        with contextlib.suppress(Exception):
            audit.emit(
                event_type=("upstream.sampling.allowed" if allow else "upstream.sampling.refused"),
                session_id=session_id,
                agent_id=f"upstream:{upstream_name}",
                risk="high",
                payload={
                    "upstream": upstream_name,
                    "messages_hash": digest,
                    "max_tokens": getattr(params, "maxTokens", None),
                    "stop_sequences": list(getattr(params, "stopSequences", []) or []),
                },
                force_fsync=True,
            )
        if allow:
            # Caller must wire forwarding to the downstream client. For now,
            # even with allow=True we don't have a downstream LLM, so we
            # refuse. Forwarding is a v0.3 follow-up.
            return mcp_types.ErrorData(
                code=-32601,
                message="quill: sampling forwarding not yet implemented (allow=True is reserved for v0.3)",
            )
        return mcp_types.ErrorData(
            code=-32601,
            message="quill: sampling refused by policy (default-deny). "
            "set allow_sampling=true in [[upstream]] config for trusted servers.",
        )

    return _refuse
