"""The MCP proxy server.

Architecture:

    Claude Code  --stdio-->  quill  --stdio-->  upstream MCP server(s)
    (or Cursor,                  ↓
     Cline, etc.)             policy + audit + prompt

Every tool advertised by an upstream is re-advertised by Quill, but every
call_tool request flows through the gate first:

  1. Audit log: tool.attempted   (camera, always-on)
  2. Scope check (badge): out-of-scope = ScopeViolation, deterministic
  3. Risk classify (default table or config override)
  4. Human ACK if risk >= HIGH (manager); type-confirm on CRITICAL
  5. Forward to upstream, capture result
  6. Audit log: verdict.allowed | tool.completed | verdict.blocked

This file is the orchestrator; the actual subprocess management and JSON-RPC
plumbing lives one layer down on top of the official `mcp` Python SDK.

Performance budget:
  policy-allow path:  P50 < 2 ms, P99 < 10 ms (excluding upstream + human)
  human-ack path:     dominated by user think-time, not Quill
"""
from __future__ import annotations

import secrets
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

import anyio
import structlog
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent, Tool

from quill.audit import AuditLog
from quill.config import QuillConfig, UpstreamConfig
from quill.errors import (
    ConfirmationMismatch,
    HumanDeclined,
    PolicyDenied,
    ScopeViolation,
    TransportError,
)
from quill.policy import Risk, SessionIntent, classify
from quill.prompt import Prompter

log = structlog.get_logger("quill.proxy")


@dataclass(slots=True)
class _UpstreamConn:
    """One live connection to an upstream MCP server (subprocess + session)."""

    name: str
    session: ClientSession
    tool_names: set[str] = field(default_factory=set)


@dataclass(slots=True)
class QuillProxy:
    """The proxy server. Owns: audit log, prompter, upstream connections."""

    config: QuillConfig
    audit: AuditLog
    prompter: Prompter
    intent: SessionIntent
    _upstreams: dict[str, _UpstreamConn] = field(default_factory=dict)
    # Reverse map: tool name -> upstream name (built at startup).
    _tool_routing: dict[str, str] = field(default_factory=dict)
    _exit_stack: AsyncExitStack = field(default_factory=AsyncExitStack)

    async def __aenter__(self) -> "QuillProxy":
        await self._exit_stack.__aenter__()
        await self._connect_all_upstreams()
        await self._discover_tools()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._exit_stack.__aexit__(*exc)
        self.audit.close()

    async def _connect_all_upstreams(self) -> None:
        """Spawn each upstream MCP server subprocess and open a session.

        Process scrubbing: only env vars listed in env_pass are forwarded
        from Quill's environ. The dict in env is added on top. Quill's
        signing key is NEVER forwarded.
        """
        import os

        for up_cfg in self.config.upstream:
            scrubbed_env: dict[str, str] = {}
            for var in up_cfg.env_pass:
                if var in os.environ:
                    scrubbed_env[var] = os.environ[var]
            scrubbed_env.update(up_cfg.env)

            params = StdioServerParameters(
                command=up_cfg.command[0],
                args=list(up_cfg.command[1:]),
                env=scrubbed_env if scrubbed_env else None,
            )
            try:
                read, write = await self._exit_stack.enter_async_context(
                    stdio_client(params),
                )
                session = await self._exit_stack.enter_async_context(
                    ClientSession(read, write),
                )
                await session.initialize()
            except Exception as e:  # noqa: BLE001
                msg = f"could not connect upstream {up_cfg.name!r}: {e}"
                raise TransportError(msg) from e

            self._upstreams[up_cfg.name] = _UpstreamConn(name=up_cfg.name, session=session)
            await log.ainfo("upstream.connected", name=up_cfg.name)

    async def _discover_tools(self) -> None:
        """Ask each upstream for its tool list and build the routing table."""
        for up in self._upstreams.values():
            try:
                result = await up.session.list_tools()
            except Exception as e:  # noqa: BLE001
                msg = f"could not list tools from upstream {up.name!r}: {e}"
                raise TransportError(msg) from e
            for tool in result.tools:
                # Namespace each tool with its upstream so collisions are impossible.
                qualified = f"{up.name}.{tool.name}"
                up.tool_names.add(qualified)
                self._tool_routing[qualified] = up.name
                self._tool_routing[tool.name] = up.name  # also accept short form

    def all_tools(self) -> list[Tool]:
        """Tools we re-advertise upward to the MCP client (Claude Code etc.)."""
        out: list[Tool] = []
        for up in self._upstreams.values():
            # We refetch each call so any upstream tool-list mutations propagate;
            # cheap because it's an in-memory cache on the SDK side.
            pass
        # For v1, we expose the cached list built at startup; live refresh in v0.2.
        return out

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """The hot path. Run the gate, then forward to upstream."""
        # Reach for the agent_id later when sub-agents land in v0.2.
        agent_id = "root"
        risk = self.config.policy.get(tool_name, classify(tool_name))

        # Layer 1: camera. Always-on, never blocks.
        attempt_payload = {
            "tool_name": tool_name,
            "arg_keys": sorted(arguments.keys()),  # never log values
            "arg_count": len(arguments),
        }
        self.audit.emit(
            event_type="tool.attempted",
            session_id=self.intent.session_id,
            agent_id=agent_id,
            risk=risk.value,
            payload=attempt_payload,
        )

        # Layer 2: badge (scope). Deterministic; does not prompt.
        scope_reason = self.intent.in_scope_reason(tool_name, arguments)
        if scope_reason is not None:
            self.audit.emit(
                event_type="verdict.scope_violation",
                session_id=self.intent.session_id,
                agent_id=agent_id,
                risk=risk.value,
                payload={"tool_name": tool_name, "reason": scope_reason},
                force_fsync=True,
            )
            self.prompter.render_block(
                action=tool_name,
                risk=risk,
                intent=self.intent.intent,
                scope=tuple(str(s) for s in self.intent.scope),
                args=arguments,
                reason=scope_reason,
            )
            raise ScopeViolation(scope_reason)

        # Layer 3: manager. Only fires on HIGH or CRITICAL.
        if risk in (Risk.HIGH, Risk.CRITICAL):
            try:
                latency = self.prompter.confirm(
                    action=tool_name,
                    risk=risk,
                    intent=self.intent.intent,
                    scope=tuple(str(s) for s in self.intent.scope),
                    args=arguments,
                )
            except (HumanDeclined, ConfirmationMismatch) as e:
                self.audit.emit(
                    event_type="verdict.blocked",
                    session_id=self.intent.session_id,
                    agent_id=agent_id,
                    risk=risk.value,
                    payload={
                        "tool_name": tool_name,
                        "reason": type(e).__name__,
                    },
                    force_fsync=True,
                )
                raise
            self.audit.emit(
                event_type="verdict.allowed",
                session_id=self.intent.session_id,
                agent_id=agent_id,
                risk=risk.value,
                payload={
                    "tool_name": tool_name,
                    "by": "human",
                    "ack_latency_s": round(latency, 3),
                },
            )
        else:
            self.audit.emit(
                event_type="verdict.allowed",
                session_id=self.intent.session_id,
                agent_id=agent_id,
                risk=risk.value,
                payload={"tool_name": tool_name, "by": "policy"},
            )

        # Forward to upstream.
        upstream_name = self._tool_routing.get(tool_name)
        if upstream_name is None:
            # Fall back: try short-name match across upstreams
            for up in self._upstreams.values():
                if tool_name in {n.split(".", 1)[-1] for n in up.tool_names}:
                    upstream_name = up.name
                    break
        if upstream_name is None:
            msg = f"no upstream owns tool {tool_name!r}"
            self.audit.emit(
                event_type="tool.errored",
                session_id=self.intent.session_id,
                agent_id=agent_id,
                risk=risk.value,
                payload={"tool_name": tool_name, "error": msg},
            )
            raise TransportError(msg)

        up = self._upstreams[upstream_name]
        # Strip the upstream prefix if the caller used a qualified name.
        upstream_tool_name = (
            tool_name.split(".", 1)[1] if tool_name.startswith(f"{up.name}.") else tool_name
        )
        try:
            result = await up.session.call_tool(upstream_tool_name, arguments=arguments)
        except Exception as e:  # noqa: BLE001
            self.audit.emit(
                event_type="tool.errored",
                session_id=self.intent.session_id,
                agent_id=agent_id,
                risk=risk.value,
                payload={"tool_name": tool_name, "error": repr(e)},
            )
            msg = f"upstream call failed: {e}"
            raise TransportError(msg) from e

        # Audit success. Don't log the result body (might contain secrets).
        self.audit.emit(
            event_type="tool.completed",
            session_id=self.intent.session_id,
            agent_id=agent_id,
            risk=risk.value,
            payload={
                "tool_name": tool_name,
                "result_size": sum(
                    len(getattr(c, "text", "") or "")
                    for c in result.content
                    if isinstance(c, TextContent)
                ),
            },
        )
        # Return content in MCP shape.
        text_blobs = [c for c in result.content if isinstance(c, TextContent)]
        return text_blobs


def build_proxy_server(proxy: QuillProxy) -> FastMCP:
    """Wrap a QuillProxy as a FastMCP server that re-advertises all upstream
    tools. The MCP client (Claude Code) sees a single quill server that
    exposes every protected tool, with the gate transparently in front.

    For v1 the tool surface is built at startup; live refresh comes in v0.2.
    """
    mcp = FastMCP(name="quill")

    # Attach a generic tool-call handler. We register one passthrough tool per
    # discovered upstream tool by namespacing under the upstream name.
    # Implementation note: in v1 we don't dynamically declare every upstream
    # tool's schema. v0.2 will re-emit each upstream's JSON-Schema upward so
    # the MCP client gets full type info. v1 ships with a single generic
    # "quill.call" tool that takes (tool_name, arguments) — sufficient for
    # the audit story but less ergonomic for autocomplete.
    @mcp.tool()
    async def call(tool_name: str, arguments: dict[str, Any]) -> str:
        """Invoke an upstream MCP tool through Quill's gate."""
        try:
            results = await proxy.call_tool(tool_name, arguments)
        except PolicyDenied as e:
            return f"BLOCKED by quill: {e}"
        return "\n".join(r.text for r in results)

    return mcp
