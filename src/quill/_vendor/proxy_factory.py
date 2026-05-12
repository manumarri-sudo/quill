"""Create a per-upstream MCP server that proxies requests through a ClientSession.

Adapted from sparfenyuk/mcp-proxy v0.11.0
(https://github.com/sparfenyuk/mcp-proxy/blob/v0.11.0/src/mcp_proxy/proxy_server.py)
under the MIT license - see ./sparfenyuk_LICENSE.

Quill modifications vs. upstream:
  1. Accept a `gate` callable that receives every tool/resource/prompt call;
     the gate decides whether to forward, refuse, or modify args.
  2. Accept an `upstream_name` for tool-name namespacing
     (e.g. `filesystem.read_file` vs. just `read_file`).
  3. Preserve upstream JSON-RPC error codes: `McpError` re-raises instead of
     being swallowed into `CallToolResult(isError=True)`. The official mcp SDK
     converts the re-raised McpError back into a JSON-RPC error response,
     preserving the upstream error code (-32602, -32601, etc.) for clients.
"""
from __future__ import annotations

import logging
import typing as t

from mcp import server, types
from mcp.client.session import ClientSession
from mcp.shared.exceptions import McpError

logger = logging.getLogger(__name__)


# Type of the gate callable injected into call_tool / read_resource / get_prompt.
# Returns the result the proxy should return to the downstream client. If the
# gate decides to refuse, it returns a CallToolResult/ReadResourceResult/etc.
# with isError=True (or raises McpError for protocol-level refusal).
ToolGate = t.Callable[
    [str, t.Mapping[str, t.Any], t.Callable[..., t.Awaitable[t.Any]]],
    t.Awaitable[t.Any],
]


async def create_proxy_server(
    remote_app: ClientSession,
    *,
    upstream_name: str,
    gate: ToolGate | None = None,
) -> server.Server[object]:
    """Build a Server that forwards every request to remote_app, with the gate
    interposed on call_tool / read_resource / get_prompt.

    The returned Server has request_handlers and notification_handlers populated
    based on the upstream's advertised capabilities. Caller is responsible for
    running the Server (e.g. via mcp.server.stdio.stdio_server).
    """
    logger.debug("initializing upstream %s", upstream_name)
    response = await remote_app.initialize()
    capabilities = response.capabilities

    app: server.Server[object] = server.Server(
        name=f"quill-proxy({response.serverInfo.name})",
    )

    # ----- prompts -----------------------------------------------------------
    if capabilities.prompts:
        async def _list_prompts(_: t.Any) -> types.ServerResult:
            return types.ServerResult(await remote_app.list_prompts())

        app.request_handlers[types.ListPromptsRequest] = _list_prompts

        async def _get_prompt(req: types.GetPromptRequest) -> types.ServerResult:
            async def _forward(args: t.Mapping[str, t.Any] | None) -> t.Any:
                return await remote_app.get_prompt(req.params.name, dict(args or {}))

            if gate is None:
                return types.ServerResult(await _forward(req.params.arguments))
            result = await gate(
                f"prompt:{upstream_name}.{req.params.name}",
                req.params.arguments or {},
                _forward,
            )
            return types.ServerResult(result)

        app.request_handlers[types.GetPromptRequest] = _get_prompt

    # ----- resources ---------------------------------------------------------
    if capabilities.resources:
        async def _list_resources(_: t.Any) -> types.ServerResult:
            return types.ServerResult(await remote_app.list_resources())

        app.request_handlers[types.ListResourcesRequest] = _list_resources

        async def _list_resource_templates(_: t.Any) -> types.ServerResult:
            return types.ServerResult(await remote_app.list_resource_templates())

        app.request_handlers[types.ListResourceTemplatesRequest] = _list_resource_templates

        async def _read_resource(req: types.ReadResourceRequest) -> types.ServerResult:
            async def _forward(_args: t.Mapping[str, t.Any]) -> t.Any:
                return await remote_app.read_resource(req.params.uri)

            if gate is None:
                return types.ServerResult(await _forward({}))
            result = await gate(
                f"resource:{upstream_name}.read",
                {"uri": str(req.params.uri)},
                _forward,
            )
            return types.ServerResult(result)

        app.request_handlers[types.ReadResourceRequest] = _read_resource

        async def _subscribe_resource(req: types.SubscribeRequest) -> types.ServerResult:
            await remote_app.subscribe_resource(req.params.uri)
            return types.ServerResult(types.EmptyResult())

        app.request_handlers[types.SubscribeRequest] = _subscribe_resource

        async def _unsubscribe_resource(req: types.UnsubscribeRequest) -> types.ServerResult:
            await remote_app.unsubscribe_resource(req.params.uri)
            return types.ServerResult(types.EmptyResult())

        app.request_handlers[types.UnsubscribeRequest] = _unsubscribe_resource

    # ----- logging -----------------------------------------------------------
    if capabilities.logging:
        async def _set_logging_level(req: types.SetLevelRequest) -> types.ServerResult:
            await remote_app.set_logging_level(req.params.level)
            return types.ServerResult(types.EmptyResult())

        app.request_handlers[types.SetLevelRequest] = _set_logging_level

    # ----- tools -------------------------------------------------------------
    if capabilities.tools:
        async def _list_tools(_: t.Any) -> types.ServerResult:
            tools = await remote_app.list_tools()
            return types.ServerResult(tools)

        app.request_handlers[types.ListToolsRequest] = _list_tools

        async def _call_tool(req: types.CallToolRequest) -> types.ServerResult:
            async def _forward(args: t.Mapping[str, t.Any]) -> t.Any:
                # Re-raise McpError so the SDK encodes it back as a JSON-RPC
                # error envelope, preserving the upstream error code.
                # (The original sparfenyuk swallowed everything into isError;
                # that breaks client retry logic that depends on -32602 etc.)
                return await remote_app.call_tool(
                    req.params.name,
                    dict(args or {}),
                )

            qualified = f"{upstream_name}.{req.params.name}"
            try:
                if gate is None:
                    result = await _forward(req.params.arguments or {})
                else:
                    result = await gate(
                        qualified,
                        req.params.arguments or {},
                        _forward,
                    )
                return types.ServerResult(result)
            except McpError:
                # Protocol error from upstream - let the SDK preserve the code.
                raise
            except Exception as e:
                logger.exception("upstream tool call failed: %s", qualified)
                return types.ServerResult(
                    types.CallToolResult(
                        content=[types.TextContent(type="text", text=str(e))],
                        isError=True,
                    ),
                )

        app.request_handlers[types.CallToolRequest] = _call_tool

    # ----- progress (client → upstream) --------------------------------------
    async def _send_progress(req: types.ProgressNotification) -> None:
        await remote_app.send_progress_notification(
            req.params.progressToken,
            req.params.progress,
            req.params.total,
        )

    app.notification_handlers[types.ProgressNotification] = _send_progress

    # ----- cancellation (client → upstream) ----------------------------------
    # The mcp SDK's `send_notification` accepts a ClientNotification union;
    # forward CancelledNotification through verbatim so the upstream knows
    # to abort an in-flight call. Without this, a cancelled request leaks
    # CPU/IO upstream until the upstream's own timeout fires.
    async def _send_cancelled(req: types.CancelledNotification) -> None:
        import contextlib as _ctx
        with _ctx.suppress(Exception):
            await remote_app.send_notification(types.ClientNotification(req))

    app.notification_handlers[types.CancelledNotification] = _send_cancelled

    # ----- completion --------------------------------------------------------
    async def _complete(req: types.CompleteRequest) -> types.ServerResult:
        return types.ServerResult(
            await remote_app.complete(req.params.ref, req.params.argument.model_dump()),
        )

    app.request_handlers[types.CompleteRequest] = _complete

    return app
