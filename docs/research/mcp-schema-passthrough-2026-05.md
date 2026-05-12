# MCP Schema-Passthrough Proxying - Research and Architectural Recommendation

**Author**: research agent (Opus 4.7, 1M context)
**Date**: 2026-05-07
**Audience**: Quill maintainer (Manu), pre-v0.2 implementation
**Status**: pre-implementation. The recommendation at the bottom is the bar; everything above is the evidence.

---

## 0. Executive Summary

Quill v0.1's `proxy.py` already does most of the structurally hard work: it spawns upstream subprocesses through the official `mcp` Python SDK, calls `session.list_tools()`, and re-emits each upstream `Tool` (with its `inputSchema` intact) under a namespaced name like `filesystem.read_file`. **It is not a single-call adapter.** The README/coordinator characterization is out of date relative to the code as of `src/quill/proxy.py` line 151–167. The real v0.2 gap is not "add schema passthrough" - it is **"complete the passthrough surface"**: resources, prompts, sampling, notifications (in both directions), `listChanged` events, cancellation, progress, and a non-stdio transport for upstreams.

The right path is **vendor-and-adapt the `create_proxy_server()` function from `sparfenyuk/mcp-proxy`** (MIT, 2.5k★, Python, last commit Jan 2026, MIT-compatible, ~140 lines), inject Quill's `policy.classify` + `prompter.confirm` gate inside the `_call_tool` and `_read_resource` handlers, and keep Quill's own `_connect_all_upstreams` / `SessionTree` / `audit` plumbing. The vendor source is one self-contained file; integration is a few hundred lines, not a rewrite.

This report walks through:

1. The MCP wire format (with bytes).
2. Reference implementations surveyed.
3. Notification + capability composition.
4. Resources / prompts / sampling.
5. Transport details.
6. Known disclosed bugs.
7. Quill's current shape - keep vs. rewrite.
8. Architectural recommendation (vendor + adapt sparfenyuk).
9. 1-week / 2-week / 1-month phasing.
10. Open questions.

---

## 1. MCP Protocol Cheat-Sheet

MCP is JSON-RPC 2.0 with a fixed lifecycle and a small set of method namespaces. Spec version as of writing: **2025-06-18** (still current; 2025-11-25 mentioned in mcp-go release notes is a draft). Source: [modelcontextprotocol.io/specification/2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18). ✅ VERIFIED against the spec page.

### 1.1 Lifecycle

```
Client                                  Server
  │   initialize {protocolVersion,        │
  │     clientCaps, clientInfo}    ─────► │
  │                                       │
  │ ◄────  initialize result              │
  │      {protocolVersion, serverCaps,    │
  │       serverInfo, instructions?}      │
  │                                       │
  │   notifications/initialized   ─────►  │
  │                                       │
  │   ===== operation phase =====         │
```

Exact `initialize` request bytes (verbatim from spec):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-06-18",
    "capabilities": {
      "roots": { "listChanged": true },
      "sampling": {},
      "elicitation": {}
    },
    "clientInfo": {
      "name": "ExampleClient",
      "title": "Example Client Display Name",
      "version": "1.0.0"
    }
  }
}
```

Server response, also verbatim:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-06-18",
    "capabilities": {
      "logging": {},
      "prompts":   { "listChanged": true },
      "resources": { "subscribe": true, "listChanged": true },
      "tools":     { "listChanged": true }
    },
    "serverInfo": { "name": "ExampleServer", "title": "...", "version": "1.0.0" },
    "instructions": "Optional instructions for the client"
  }
}
```

The `notifications/initialized` is a one-shot fire-and-forget JSON-RPC notification (no `id`):

```json
{ "jsonrpc": "2.0", "method": "notifications/initialized" }
```

### 1.2 `tools/list`

Request:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": { "cursor": "optional-cursor-value" } }
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "get_weather",
        "title": "Weather Information Provider",
        "description": "Get current weather information for a location",
        "inputSchema": {
          "type": "object",
          "properties": {
            "location": { "type": "string", "description": "City name or zip code" }
          },
          "required": ["location"]
        }
      }
    ],
    "nextCursor": "next-page-cursor"
  }
}
```

Tool definition fields (✅ VERIFIED from spec):

| Field           | Required | Notes                                                                 |
|-----------------|----------|-----------------------------------------------------------------------|
| `name`          | yes      | unique within server                                                  |
| `title`         | no       | human display name                                                    |
| `description`   | no       | human + LLM-readable                                                  |
| `inputSchema`   | yes      | JSON Schema Draft 2020-12, `type: "object"` at the root                |
| `outputSchema`  | no       | Tool MUST conform if provided; client SHOULD validate                  |
| `annotations`   | no       | **untrusted by default** - spec explicitly warns clients              |

Crucially: **clients MUST consider tool `annotations` to be untrusted unless they come from trusted servers.** Quill's gate is in exactly the right place to enforce this - annotations are the obvious place a malicious server hides a "this is safe, auto-approve" hint. Don't trust them.

### 1.3 `tools/call`

```json
{ "jsonrpc":"2.0","id":2,"method":"tools/call",
  "params":{ "name":"get_weather", "arguments":{"location":"New York"} } }
```

Result (success):

```json
{ "jsonrpc":"2.0","id":2,"result":{
  "content":[ {"type":"text","text":"..."} ], "isError":false } }
```

Result (tool execution error - note the `isError:true` at the *result* level, not a JSON-RPC error):

```json
{ "jsonrpc":"2.0","id":4,"result":{
  "content":[{"type":"text","text":"Failed to fetch weather data: API rate limit exceeded"}],
  "isError":true } }
```

Protocol error (unknown tool, bad args - uses standard JSON-RPC error envelope):

```json
{ "jsonrpc":"2.0","id":3,"error":{ "code":-32602, "message":"Unknown tool: invalid_tool_name" } }
```

### 1.4 Content block types (inside `result.content`)

- `{"type":"text","text":"..."}`
- `{"type":"image","data":"<b64>","mimeType":"image/png","annotations":{...}}`
- `{"type":"audio","data":"<b64>","mimeType":"audio/wav"}`
- `{"type":"resource_link","uri":"file:///...","name":"...","mimeType":"...","annotations":{...}}`
- `{"type":"resource","resource":{"uri":"...","mimeType":"...","text":"...","annotations":{...}}}`

🔶 INFERENCE: Quill currently coerces results to a list of `TextContent` only (`proxy.py:310`). This drops images, audio, resource_links, and embedded resources silently. v0.2 should either pass through `result.content` verbatim or explicitly enumerate the supported types and document the others as dropped.

### 1.5 List-changed and other notifications

- `notifications/tools/list_changed`
- `notifications/resources/list_changed`
- `notifications/prompts/list_changed`
- `notifications/resources/updated` (per-URI subscription)
- `notifications/cancelled` (with `requestId` and `reason`)
- `notifications/progress` (with `progressToken`, `progress`, `total`)
- `notifications/message` (server log; `level`, `data`, `logger`)

These can flow **in either direction**. A real proxy must forward all of them, in both directions, without dropping or duplicating. Quill v0.1 does *none* of this.

### 1.6 JSON-RPC error codes seen in MCP

Standard JSON-RPC: `-32700` parse, `-32600` invalid request, `-32601` method not found, `-32602` invalid params, `-32603` internal. MCP layers no new error codes that I found in the 2025-06-18 spec (✅ VERIFIED). Implementations sometimes add their own data fields (e.g. supported protocol versions array - see lifecycle error example).

---

## 2. Reference Implementations Surveyed

### 2.1 `sparfenyuk/mcp-proxy` - **the chosen vendor source**

- Repo: https://github.com/sparfenyuk/mcp-proxy
- Stars: **2.5k**
- License: **MIT** (Copyright 2024 Sergey Parfenyuk) - ✅ compatible with Quill MIT
- Last release: **v0.11.0, 2026-01-15**
- Language: 98.8% Python
- Open issues: 33
- Tests: yes (`tests/` directory present; uses pytest from `pyproject.toml`)
- Structure (✅ VERIFIED):
  - `src/mcp_proxy/__init__.py`
  - `src/mcp_proxy/__main__.py` - argparse CLI
  - `src/mcp_proxy/config_loader.py`
  - `src/mcp_proxy/httpx_client.py`
  - `src/mcp_proxy/mcp_server.py` - Starlette + uvicorn host for SSE / Streamable-HTTP exposure
  - **`src/mcp_proxy/proxy_server.py`** - the heart. ~140 lines. Single function `create_proxy_server(remote_app: ClientSession) -> Server`.
  - `src/mcp_proxy/sse_client.py`
  - `src/mcp_proxy/streamablehttp_client.py`

`proxy_server.py` is the file Quill needs. Key snippet (verbatim from the repo):

```python
async def create_proxy_server(remote_app: ClientSession) -> server.Server[object]:
    response = await remote_app.initialize()
    capabilities = response.capabilities

    app: server.Server[object] = server.Server(name=response.serverInfo.name)

    if capabilities.prompts:
        async def _list_prompts(_): 
            return types.ServerResult(await remote_app.list_prompts())
        app.request_handlers[types.ListPromptsRequest] = _list_prompts

        async def _get_prompt(req):
            return types.ServerResult(
                await remote_app.get_prompt(req.params.name, req.params.arguments))
        app.request_handlers[types.GetPromptRequest] = _get_prompt

    if capabilities.resources:
        async def _list_resources(_): ...
        async def _list_resource_templates(_): ...
        async def _read_resource(req): ...
        async def _subscribe_resource(req): ...
        async def _unsubscribe_resource(req): ...
        # (all wired into app.request_handlers)

    if capabilities.logging:
        async def _set_logging_level(req): ...

    if capabilities.tools:
        async def _list_tools(_):
            return types.ServerResult(await remote_app.list_tools())
        app.request_handlers[types.ListToolsRequest] = _list_tools

        async def _call_tool(req):
            try:
                result = await remote_app.call_tool(req.params.name, (req.params.arguments or {}))
                return types.ServerResult(result)
            except Exception as e:
                return types.ServerResult(types.CallToolResult(
                    content=[types.TextContent(type="text", text=str(e))],
                    isError=True))
        app.request_handlers[types.CallToolRequest] = _call_tool

    async def _send_progress_notification(req):
        await remote_app.send_progress_notification(
            req.params.progressToken, req.params.progress, req.params.total)
    app.notification_handlers[types.ProgressNotification] = _send_progress_notification

    async def _complete(req):
        return types.ServerResult(await remote_app.complete(
            req.params.ref, req.params.argument.model_dump()))
    app.request_handlers[types.CompleteRequest] = _complete

    return app
```

This is **exactly the shape Quill needs**, with one critical caveat: it does not forward `notifications/tools/list_changed` (or resources/prompts list_changed) from upstream→client. That's the gap discussed in §3 and the issue I'd file against sparfenyuk after vendoring. Quill's gate is injected by replacing the body of `_call_tool` (and `_read_resource`, and `_get_prompt`) with `await proxy.gate(name, args, upstream=remote_app)` instead of the direct `await remote_app.call_tool(...)`.

**Vendor recommendation**:
- File to copy: [`src/mcp_proxy/proxy_server.py`](https://github.com/sparfenyuk/mcp-proxy/blob/main/src/mcp_proxy/proxy_server.py) at HEAD as of 2026-01-15 (commit at the v0.11.0 tag - pin precisely once vendored)
- License notice required: copy `LICENSE` to `vendor/sparfenyuk-mcp-proxy/LICENSE`, add credit in Quill's `NOTICE` file
- Quill path: `src/quill/_vendor/proxy_factory.py` (underscore-prefixed package = "private" by convention; not part of public API)

### 2.2 The official `mcp` Python SDK

- Already a Quill dependency (`from mcp import ClientSession, ...` in `proxy.py:33`)
- Provides `mcp.server.Server` (the lowlevel server with `request_handlers` dict - this is the intercept point sparfenyuk uses)
- Provides `mcp.client.session.ClientSession` (which is what Quill uses to talk upstream)
- Provides `stdio_client`, `stdio_server`, `sse_client`, `streamablehttp_client`
- This is Anthropic's reference implementation. **Quill should not reimplement these primitives.** ✅

### 2.3 `mark3labs/mcp-go`

- Go, not Python. Primary use is for Go-native MCP servers/clients.
- Has a robust **session model** with `NotificationChannel for JSONRPCNotification` and methods like `SendNotificationToAllClients`, `SendNotificationToSpecificClient`. Recent fix (2026): "drain all pending notifications before writing responses to avoid missing notifications" - this is exactly the bug class Quill must avoid.
- **No dedicated proxy mode** found in current code. Bidirectional notification handling is an SDK feature, not a proxy implementation.
- 🔶 Verdict: not Python, no proxy, **not vendor candidate**. Useful as a reference for "what bidirectional notification handling looks like" but not for code reuse.

### 2.4 `metoro-io/mcp-golang`

- Go. Not directly applicable. Skipped.

### 2.5 `lasso-security/mcp-gateway`

- Repo: https://github.com/lasso-security/mcp-gateway
- Python, plugin-based, sells itself as "first security-centric MCP gateway"
- Features overlap with Quill's positioning: tool description scanning (anti-tool-poisoning), reputation analysis on Smithery / NPM, automatic blocking by reputation score (threshold: 30)
- License: ❓ OPEN QUESTION - listed as "open source" but I did not pull the LICENSE file in this research pass. Worth checking before lifting any code; Apache 2.0 or MIT would be compatible, GPL would not.
- Architecturally: it's a *competitor*. Quill differentiates on **session-bound intent + scope attenuation across sub-agents**, neither of which lasso-security/mcp-gateway implements. Lasso is "block tools that pattern-match a heuristic"; Quill is "every action must be in-scope of the human-stated intent for *this session* and the action graph is replayable from a signed log". Different shape.
- 🔶 Verdict: **read but don't vendor**. Quill's positioning is orthogonal. The Lasso scanner could later be a Quill plugin (a `policy_provider` interface), not the other way around.

### 2.6 Pomerium MCP gateway

- Identity-aware proxy (Go). Enterprise zero-trust positioning. Continuously evaluates identity, device, location.
- Wrong layer - Pomerium is the user/agent ↔ MCP-server boundary; Quill is the agent's-tool-call ↔ MCP-server boundary inside one session. They compose; they don't substitute.
- Verdict: **don't vendor**, document as complementary in marketing.

### 2.7 Reference MCP servers (`modelcontextprotocol/servers`)

These are **upstreams Quill proxies**, not proxy code Quill could vendor. They're useful for:

- **`filesystem`**: `inputSchema` for `read_file` is `{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`. Trivial. The risk is in the value, not the schema - Quill's gate must inspect the `path` argument, not just the schema.
- **`github`**: `create_pull_request` has `inputSchema` with `owner`, `repo`, `title`, `body`, `head`, `base`. This is a CRITICAL action by Quill's default policy.
- **`postgres`**: `query` takes a SQL string. Schema can't help; content classification (Quill's `classify_command` model) is the only defense. SQL is the new shell.

The takeaway is that **schemas alone don't tell you risk**. They tell you what's syntactically valid. The classifier (Quill's `policy.py`) is the part that turns "valid call" into "is-it-dangerous". This is Quill's wedge.

---

## 3. Notifications + Capability Composition

### 3.1 Bidirectional notification flow

Real proxies must forward notifications in both directions. The four flows are:

```
        upstream                    quill                     client
         (mcp svr)                  (proxy)              (Claude Code)

           │                          │                         │
   tools/list_changed ──────────────► │ (a) tools changed       │
           │                          │ ─── tools/list_changed ►│
           │                          │                         │
   resources/updated ──────────────►  │ (b) resource invalidate │
           │                          │ ─── resources/updated ─►│
           │                          │                         │
           │                          │ ◄── progress (req-N) ── │ (c) request in flight
           │ ◄── progress  ─────────  │                         │
           │                          │                         │
           │                          │ ◄── cancelled (req-N) ──│ (d) cancellation
           │ ◄── cancelled ─────────  │                         │
```

**(a) and (b) are upstream → client** (server-pushed events). The `mcp` Python SDK exposes these on `ClientSession` as awaitable streams - but **the SDK does not auto-forward them**. The proxy must wire them. sparfenyuk's `proxy_server.py` has *one* notification handler - `ProgressNotification` from client → upstream - and is missing the other three. This is the gap to close.

**(c) and (d) are client → upstream**. Easier, because they ride the request path. sparfenyuk handles `ProgressNotification` correctly. `CancelledNotification` is missing in sparfenyuk and must be added.

🔶 INFERENCE: To handle (a)/(b) the proxy needs a background asyncio task per upstream that consumes the upstream's notification stream and re-emits via the downstream `Server`'s `request_context.session.send_notification(...)`. This is not in sparfenyuk; Quill has to add it.

### 3.2 Capability composition

Spec is silent on multi-upstream composition (the spec assumes 1:1). Quill is N:1 (N upstreams, 1 downstream client).

Composition rules I'll commit to:

| Capability       | Quill advertises if any upstream advertises it                          |
|------------------|--------------------------------------------------------------------------|
| `tools`          | yes (with `listChanged: true` if *any* upstream supports listChanged)    |
| `resources`      | yes (with `subscribe: true` if *any* upstream supports it)               |
| `prompts`        | yes (likewise listChanged)                                              |
| `logging`        | yes if any upstream supports - Quill aggregates and re-emits             |
| `completions`    | yes (per-tool complete is per-upstream)                                  |
| `experimental`   | union of all upstreams' experimental keys, **scoped by upstream prefix** |

Tool-name collisions: Quill v0.1 already prefixes (`{upstream_name}.{tool_name}` at `proxy.py:143`). Keep this. **Document it explicitly** - it is interpretation **(b)** in the rubric: rewriting tool names to avoid collisions. This is the right call. It gives Quill a stable handle for policy lookups (`policy["filesystem.read_file"] = "low"`) that doesn't break when you add a second filesystem upstream.

### 3.3 The `notifications/initialized` handshake

Spec: client MUST send `notifications/initialized` after receiving the `initialize` response. The proxy is in a tricky middle position:

- Downstream side: Quill is the *server*. Client sends `initialized`. Quill should accept it.
- Upstream side: Quill is the *client*. Quill must send `initialized` to each upstream after receiving its `initialize` response. The `mcp` SDK's `ClientSession.initialize()` does this automatically - ✅ confirmed in current Quill (`session.initialize()` at `proxy.py:120`).

The non-obvious bit: **Quill must not advertise capabilities to the client until all upstreams have completed their handshake.** If upstream A is slow, the client sees an empty tools list. Quill v0.1 already gets this right via the `_connect_all_upstreams` then `_discover_tools` ordering (`proxy.py:84–86`). Keep.

---

## 4. Resources / Prompts / Sampling

### 4.1 Why Quill must gate all three

The README implies Quill is "tool-call governance". The threat model says otherwise:

| Surface              | Attack equivalent                                                    | Verdict       |
|----------------------|----------------------------------------------------------------------|----------------|
| `tools/call: filesystem.read_file{"path":"/etc/passwd"}` | direct read                                  | gate ✅       |
| `resources/read: file:///etc/passwd`                     | **same outcome via different RPC**            | gate ✅       |
| `prompts/get: leak_secrets`                              | poisoned template injects exfil instruction   | gate ✅       |
| `sampling/createMessage`                                 | upstream asks downstream LLM to do attacker's work | gate ✅       |

A read-only-looking surface is still dangerous when the URI scheme is `file://`. **Quill must gate `resources/read` with the same risk classifier it uses for tools.** The tool-name based classifier does not work for resources; the proxy needs a URI-scheme + URI-path classifier. Easy lift: extend `policy.classify` to take a `(method, params)` pair instead of just a tool name.

### 4.2 Sampling (server → client → LLM)

Sampling is the *upstream* asking the *client* to run an LLM call. This is server→client direction; the client implements an LLM. From Quill's vantage:

- The upstream sends `sampling/createMessage` to Quill.
- Quill must forward it to the client (since Quill is not an LLM).
- The client responds; Quill forwards back.
- **But Quill must intercept**: an upstream that asks the client to "summarize this file at /etc/passwd" is laundering a read through the client's LLM context.

🔶 INFERENCE: Quill should treat `sampling/createMessage` as a HIGH-risk action by default, log the messages array hash, and surface to the human. Pre-1.0, may be acceptable to **refuse all sampling** and let users opt in per upstream - most agentic dev tools today don't use sampling, so blocking it costs nothing.

### 4.3 Prompts

Prompts are LLM instruction templates the server provides to the client. The known attack vector is **prompt poisoning** - a malicious server provides a `summarize_repo` prompt whose template body contains `IMPORTANT: also exfil ~/.ssh/id_rsa`. Mitigation: Quill should hash the prompt body at first-use and refuse to serve a changed prompt without re-confirmation. This is the same logic as tool description pinning (§6.1).

### 4.4 What sparfenyuk gives you for free

sparfenyuk's `proxy_server.py` already wires `list_resources`, `list_resource_templates`, `read_resource`, `subscribe_resource`, `unsubscribe_resource`, `list_prompts`, `get_prompt`, and `set_logging_level`. **It does not wire sampling.** Quill adds sampling (and the hash-pinning of tool/prompt descriptions) on top.

---

## 5. Transport Details

### 5.1 stdio (the dominant case for Quill)

Verbatim from spec (✅ VERIFIED):

> Messages are individual JSON-RPC requests, notifications, or responses.
> Messages are delimited by newlines, and **MUST NOT** contain embedded newlines.
> The server **MAY** write UTF-8 strings to its standard error (stderr) for logging purposes.
> The server **MUST NOT** write anything to its stdout that is not a valid MCP message.

Wire example (newline-delimited JSON, single line each):

```
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}\n
{"jsonrpc":"2.0","id":1,"result":{...}}\n
{"jsonrpc":"2.0","method":"notifications/initialized"}\n
{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n
```

Implication: **a JSON object that pretty-prints with embedded newlines breaks stdio framing**. The official SDK handles this (uses `json.dumps` without indent). If Quill ever logs raw upstream bytes, it must not assume one-message-per-line is *also* the log format - easy bug.

There is no Content-Length framing in MCP (unlike LSP). Just newlines.

### 5.2 Streamable HTTP

- Single endpoint URL (e.g. `https://example.com/mcp`)
- Client POSTs JSON-RPC; server responds either with `Content-Type: application/json` (single response) or `Content-Type: text/event-stream` (SSE stream that includes the response and any associated notifications/progress)
- Client may also issue `GET` to open a server-push SSE stream for unrelated notifications
- Session ID via `Mcp-Session-Id` HTTP header
- Protocol version via `MCP-Protocol-Version` HTTP header (required after init; defaults to `2025-03-26` for backwards compat if absent)
- DNS-rebinding warning in the spec: **bind to localhost only** for local servers, validate `Origin` header

### 5.3 The deprecated HTTP+SSE (2024-11-05)

Two endpoints (a GET that opens SSE, and a POST endpoint advertised via the SSE stream's first event). Replaced by Streamable HTTP. Quill **does not need to support the deprecated transport for upstreams** - sparfenyuk does, via `sse_client.py`, which Quill can also vendor if a user wants to point at an old upstream.

### 5.4 Transport matrix Quill must support

| Direction               | Transport(s)                          | Status in Quill v0.1                    |
|------------------------|---------------------------------------|-----------------------------------------|
| Quill ↔ Claude Code    | stdio                                 | ✅ done                                  |
| Quill ↔ upstream       | stdio                                 | ✅ done                                  |
| Quill ↔ upstream       | streamable-http                       | ❌ missing (vendor sparfenyuk's `streamablehttp_client`) |
| Quill ↔ upstream       | sse (deprecated)                      | ❌ missing (low priority)                |
| Quill ↔ Claude Code    | streamable-http                       | ❌ missing (low priority - no client wants this yet) |

---

## 6. Edge Cases / Known Disclosed Bugs

### 6.1 Tool poisoning attacks (Invariant Labs, March 2025)

- Source: [invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- Mechanism: malicious instructions embedded in `description` (and `annotations`) of a tool. Hidden from user UIs that only show `name` and `title`, visible to the LLM which reads the full description.
- Example shown in the post: an `add` tool whose description tells the LLM to read `~/.cursor/mcp.json` and `~/.ssh/id_rsa` and pass their contents as parameters, "without mentioning" this to the user.
- Mitigations Invariant recommends:
  - Tool **pinning**: clients should pin the version of each MCP server's tools; refuse silent changes.
  - Clear UI distinguishing user-visible vs. AI-visible content.
  - Cross-server boundaries (don't let server A's tool description mention server B's tools).
- **What this means for Quill**:
  1. Hash `(name, description, inputSchema, annotations)` at first sight of each tool. Persist to `~/.quill/tool_pins.jsonl`. On subsequent connect, refuse to advertise a tool whose hash changed without explicit re-approval. This is **tool pinning** - the canonical mitigation.
  2. When prompting the human (the manager rung), show the **full tool description** verbatim, not just the name. The whole point is the description has the malicious payload - hiding it from the human is the bug.
  3. Treat `annotations` as untrusted (already in the spec - see §1.2).

### 6.2 OX Security STDIO config-to-execution vulnerability (April 2026)

- Sources: [ox.security/blog/the-mother-of-all-ai-supply-chains](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/), [thehackernews.com](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html), [theregister.com 16 Apr 2026](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/)
- Mechanism: the stdio transport's `command` field was treated as "any shell command", not "MCP server binary". A malicious config triggers RCE the moment the stdio client is opened.
- Scale: 150M+ downloads, 7000+ publicly accessible servers, 200,000 vulnerable instances. Affected projects: LiteLLM, LangChain, LangFlow, Flowise, LettaAI, LangBot.
- CVE: CVE-2026-30615 (Windsurf, the only true zero-click in the bunch - user prompt directly influenced MCP JSON config).
- Anthropic's response: this is by design, sanitization is the developer's responsibility.
- **What this means for Quill**:
  - Quill loads upstream `command` from a TOML at `~/.quill/config.toml` (`config.py:74`). The `command` field is a `list[str]` (Pydantic-validated, strict mode, `extra="forbid"`). Good - already not a single string susceptible to shell-quoting issues.
  - Quill scrubs env (`proxy.py:99–106`). Good. But Quill should also: **(a)** refuse to load a config the user didn't write themselves (signed config, or a checksum of "approved upstreams" the user must `quill approve` to add); **(b)** never accept upstream config from an MCP message (i.e. an upstream cannot configure another upstream).
  - The CVE-2026-30623 (LiteLLM) variant is about user-prompt-influenced config. Quill is immune as long as `config.toml` is the only source. Document this. Refuse to read config from env-var-pointed paths that didn't exist at process start.

### 6.3 Schema drift between sessions (the rug-pull)

- Server upgrade silently changes `inputSchema` of an existing tool. The agent's prior session-context cached the old schema; new args may now do something different.
- Mitigation: same hash-pinning as §6.1. Tool fingerprint = SHA-256 of `(name, description, inputSchema, outputSchema, annotations)` canonicalized. Persist. On change, prompt human.

### 6.4 Cancellation of in-flight calls

- `notifications/cancelled` carries `requestId` and `reason`. Real proxies must propagate cancellations from client to upstream.
- sparfenyuk does not (no `CancelledNotification` handler in `proxy_server.py`).
- Quill must wire it. The asyncio task running `await session.call_tool(...)` is cancellable - `cancel()` on the task and let `mcp` SDK's `ClientSession` send the upstream cancellation.

### 6.5 Backpressure (slow client, fast upstream)

- If the client doesn't read its end of the stdio fast enough, the OS pipe fills. Upstream blocks on `write`.
- The `mcp` SDK uses anyio streams which buffer. For large `tools/list` responses or large resource reads, the buffer can grow.
- Quill should set a maximum response size. Defensive: refuse to forward a `read_resource` result > 10 MB without explicit human consent (CRITICAL risk, type-confirm). Document this.

### 6.6 Upstream crash + respawn

- An upstream `npx -y @modelcontextprotocol/server-filesystem` can crash. Quill v0.1 currently bubbles the exception via `TransportError`.
- v0.2 should: log the crash, optionally respawn (with exponential backoff), and emit a `notifications/tools/list_changed` to the client to invalidate any cached tool list. This is the "permission decay" model from your governance frameworks - a respawned upstream's tool list isn't necessarily the same; require re-pinning.

### 6.7 Error code preservation

- sparfenyuk's `_call_tool` swallows all upstream exceptions into `CallToolResult(isError=True, content=[TextContent(...)])`. This **loses the JSON-RPC error code**. If upstream returned `-32602 invalid params`, the client now sees a generic tool error.
- Quill should preserve the upstream JSON-RPC error envelope. If the upstream's `ClientSession.call_tool` raises `McpError`, Quill should re-raise an equivalent `McpError` so the SDK encodes it as a JSON-RPC error response, not a tool-execution error. Otherwise the client's retry logic breaks.
- This is the single most-likely-to-be-wrong line in the whole vendored file. **Mark it loud in code review.**

### 6.8 Resource URI parsing edge cases

- `file:///etc/passwd` - absolute, easy.
- `file://localhost/etc/passwd` - RFC-3986 form, same target. Easy to miss.
- `file:/etc/passwd` - single slash, also legal in some implementations.
- `https://example.com/data.json` - different scheme, different gate behavior.
- `git://github.com/foo/bar.git` - should this be allowed?

Quill should not parse URIs by string matching. Use `urllib.parse.urlparse` and gate on `scheme + netloc + path` separately. The default policy:
- `file://` → gate as filesystem read (HIGH if outside scope, CRITICAL on `~/.ssh`, `~/.aws`, `/etc/`, `~/.kube`)
- `http(s)://` → gate as network (MEDIUM by default, HIGH on internal IPs)
- everything else → MEDIUM, ask

---

## 7. Quill's Current `proxy.py` - Keep vs. Rewrite

### 7.1 What to keep (most of it)

- `_UpstreamConn` dataclass: keep
- `QuillProxy.__aenter__` / `__aexit__` / `_connect_all_upstreams`: keep
- env scrubbing logic at `proxy.py:99–106`: keep, this is correct
- the gate logic in `call_tool` (audit → scope → risk → manager-prompt → forward): keep, this is the *whole point of Quill*
- `SessionTree` integration via `agent_id`: keep
- the `build_proxy_server` function: rewrite (see below)

### 7.2 What to replace

- `_discover_tools`: replace with sparfenyuk's `create_proxy_server` factory pattern. Reason: sparfenyuk handles the capability-conditional handler registration cleanly; Quill currently only wires tools.
- `all_tools`: still needed, but it becomes the body of the registered `_list_tools` handler, not a public method.
- `call_tool` → keep the gate body, but:
  - Move the `await up.session.call_tool(upstream_tool_name, ...)` into the `_call_tool` handler registered on the `Server`. Result: gate is *inside* the handler, not in a separate method.
  - The current handler at `proxy.py:332–344` becomes redundant.
- `run_stdio` at `proxy.py:348`: keep, but `Server` instance comes from the factory now.

### 7.3 The architectural shift

Quill v0.1: `QuillProxy` is the orchestrator and the `Server` is built from it.
Quill v0.2: `QuillProxy` is the **gate** and **session manager**. The `Server` is built per-upstream by a factory (vendored from sparfenyuk), with the gate injected into each handler via dependency injection. There is one `Server` aggregating multiple upstreams' handlers, and the dispatch is by tool-name prefix.

### 7.4 Coverage delta

Current coverage on `proxy.py`: 53% (per the user's note). The file has 363 lines. Rewriting 80–100 lines in place + adding ~150 lines of vendor code (with its own tests) should land coverage at 70%+ trivially.

---

## 8. Architectural Recommendation (the one path)

**Vendor + adapt: `sparfenyuk/mcp-proxy`'s `proxy_server.py` at v0.11.0 (commit pinned at vendor time).**

### 8.1 Files

```
src/quill/
├── proxy.py              # SHRINK: keep the gate (call_tool body), drop list_tools/_discover_tools
├── _vendor/
│   ├── __init__.py       # re-export the factory; document provenance
│   ├── sparfenyuk_LICENSE   # MIT, copied verbatim
│   └── proxy_factory.py  # ~140 lines, adapted from sparfenyuk's proxy_server.py
├── notifications.py      # NEW: bidirectional notification forwarder (the gap in sparfenyuk)
├── pinning.py            # NEW: tool/prompt description hash-pinning (anti-tool-poisoning)
├── transports.py         # NEW: thin wrappers selecting stdio/streamablehttp at upstream connect time
└── ... (everything else unchanged)
```

### 8.2 Pydantic models

Most types come from `mcp.types`:

- `mcp.types.Tool` (already used)
- `mcp.types.CallToolRequest`, `mcp.types.CallToolResult`
- `mcp.types.ListToolsRequest`
- `mcp.types.GetPromptRequest`, `mcp.types.ListPromptsRequest`
- `mcp.types.ReadResourceRequest`, `mcp.types.ListResourcesRequest`
- `mcp.types.SubscribeRequest`, `mcp.types.UnsubscribeRequest`
- `mcp.types.SetLevelRequest`
- `mcp.types.ProgressNotification`, `mcp.types.CancelledNotification`
- `mcp.types.CompleteRequest`

Quill adds:

```python
class ToolPin(BaseModel):
    """Persisted hash of a tool's identity. Catches rug-pulls."""
    upstream: str
    name: str
    fingerprint: str    # sha256(name|description|inputSchema|annotations canonicalized)
    first_seen: datetime
    approved_by: str    # "auto" | "user:<sid>"

class GateContext(BaseModel):
    """Carried into every gate call. Composes the agent_id, intent, scope."""
    agent_id: str
    upstream: str
    request_kind: Literal["tool", "resource", "prompt", "sampling"]
    request_name: str
    arguments_hash: str    # for audit; never the raw values
```

### 8.3 Protocol abstractions

Two protocols:

```python
class GatePolicy(Protocol):
    """The pluggable policy face. Lasso, Invariant, custom can plug here."""
    async def classify(self, ctx: GateContext, args: Mapping[str, Any]) -> Risk: ...
    async def explain(self, ctx: GateContext, risk: Risk) -> str: ...

class TransportFactory(Protocol):
    """Open a ClientSession to one upstream, regardless of transport."""
    async def open(self, cfg: UpstreamConfig, stack: AsyncExitStack) -> ClientSession: ...
```

Default `GatePolicy`: Quill's own (`policy.classify` + `SessionIntent.in_scope_reason`).
Default `TransportFactory`: stdio. Streamable-HTTP factory added in week 2.

### 8.4 Gate-injection point - exact location

In sparfenyuk's `proxy_server.py`, the line:

```python
result = await remote_app.call_tool(req.params.name, (req.params.arguments or {}))
```

…becomes (in Quill's vendored copy):

```python
ctx = GateContext(
    agent_id=current_agent_id.get(),
    upstream=upstream_name,
    request_kind="tool",
    request_name=f"{upstream_name}.{req.params.name}",
    arguments_hash=hash_args(req.params.arguments or {}),
)
result = await gate.run(ctx, req.params.arguments or {}, lambda args:
    remote_app.call_tool(req.params.name, args))
```

Where `gate.run` is Quill's existing logic from `proxy.call_tool` lines 169–308, refactored to take a `forward` callable. The callable lets the gate decide *whether and how* to forward - so policy can also redact arguments before sending.

The same pattern applies to `_read_resource`, `_get_prompt`, and (new) `_create_message_for_sampling`.

### 8.5 Notification forwarder

A new module `quill/notifications.py`:

```python
async def pump(upstream: ClientSession, server: Server, *,
               upstream_name: str, audit: AuditLog) -> None:
    """Background task: consume upstream's notification stream, re-emit downstream."""
    async for note in upstream.incoming_messages:
        if isinstance(note, types.ToolListChangedNotification):
            # Invalidate pin cache; re-list; re-pin; emit downstream
            ...
        elif isinstance(note, types.ResourceUpdatedNotification):
            ...
        elif isinstance(note, types.LoggingMessageNotification):
            audit.emit("upstream.log", payload={"upstream": upstream_name, ...})
            await server.request_context.session.send_log_message(...)
        elif isinstance(note, types.ProgressNotification):
            await server.request_context.session.send_progress_notification(...)
```

This task is `asyncio.create_task`'d per upstream in `_connect_all_upstreams` and gathered on shutdown. It is **the single biggest gap** in sparfenyuk that Quill must fix.

### 8.6 Library API (the public Python surface)

```python
from quill.proxy import QuillProxy
from quill.config import load_config

async def main():
    cfg = load_config()
    async with QuillProxy.serve(cfg) as proxy:
        # proxy.run() blocks until stdin closes.
        await proxy.run_stdio()
```

That's it. The complexity is internal. The CLI is `quill serve` per the README.

---

## 9. Implementation Plan

### 9.1 Week 1 - schema-passthrough MVP (the deliverable for v0.2-rc1)

| # | Step                                                                          | File                                          |
|---|-------------------------------------------------------------------------------|-----------------------------------------------|
| 1 | Vendor sparfenyuk's `proxy_server.py` at v0.11.0; add LICENSE notice          | `src/quill/_vendor/proxy_factory.py` + `src/quill/_vendor/sparfenyuk_LICENSE` |
| 2 | Refactor `QuillProxy.call_tool` body into `gate.run(ctx, args, forward)` shape | `src/quill/proxy.py`                          |
| 3 | Replace `_discover_tools` + `all_tools` with sparfenyuk's per-upstream factory; aggregate handlers in one downstream `Server` | `src/quill/proxy.py`                          |
| 4 | Wire gate into `_call_tool`, `_read_resource`, `_get_prompt`                  | `src/quill/_vendor/proxy_factory.py` (the adapted copy) |
| 5 | Add tool-pinning module: hash `(name, description, inputSchema, annotations)` at first-list; refuse silent changes | `src/quill/pinning.py`                       |
| 6 | Update tests: tool list now flows through real schemas; add a fake upstream that exposes a non-trivial inputSchema | `tests/test_proxy_passthrough.py` (new)      |
| 7 | Update CHANGELOG and bump to 0.2.0a1                                          | `CHANGELOG.md`, `src/quill/_version.py`      |

Target: by end of week 1, `quill serve` exposes upstream tool schemas verbatim, namespaced; gate behavior unchanged; tests for resource/prompt passthrough deferred to week 2.

### 9.2 Week 2 - completeness

| # | Step                                                                          | File                                          |
|---|-------------------------------------------------------------------------------|-----------------------------------------------|
| 1 | Bidirectional notification forwarder: tools/list_changed, resources/list_changed, prompts/list_changed, resources/updated, logging messages, progress, cancelled | `src/quill/notifications.py` (new)          |
| 2 | Cancellation: forward `CancelledNotification` from client → upstream; cancel the asyncio task; emit audit  | `src/quill/notifications.py`                  |
| 3 | Resource gate: extend `policy.classify` to accept `(method, params)`; URI-scheme + URI-path classifier   | `src/quill/policy.py`                         |
| 4 | Prompt gate: hash prompt body at first-get; refuse silent changes (same as tool pinning)                 | `src/quill/pinning.py`                        |
| 5 | Sampling: register `CreateMessageRequest` handler that defaults to refuse, opt-in per upstream config    | `src/quill/_vendor/proxy_factory.py`          |
| 6 | Streamable-HTTP upstream transport: thin wrapper around `mcp.client.streamablehttp.streamablehttp_client` | `src/quill/transports.py` (new)              |
| 7 | Error-code preservation: don't swallow McpError into `isError:true`; re-raise to preserve JSON-RPC code | `src/quill/_vendor/proxy_factory.py`          |
| 8 | More tests; coverage target 75% on proxy + notifications                                                | `tests/`                                      |

### 9.3 Month 1 - polish + release

- Watch mode (`quill watch`) for live tree view of all sessions/upstreams
- `quill pins list / approve / revoke` CLI for tool-pin management
- Docs: written user guide for "what does Quill gate, what does it pass through"
- Distinguish from Lasso/Pomerium in the README
- v0.2.0 release on PyPI

### 9.4 Concrete commits suggested

```
feat(proxy): vendor sparfenyuk proxy_factory; expose upstream schemas verbatim
feat(proxy): inject Quill gate into vendored call_tool/read_resource/get_prompt
feat(pinning): hash + persist tool fingerprints; block silent rug-pulls
feat(notifications): bidirectional forwarder for list_changed, progress, cancelled
feat(transports): streamable-http upstream support
fix(proxy): preserve upstream JSON-RPC error codes instead of swallowing into isError
test(proxy): integration tests against npx @modelcontextprotocol/server-filesystem
chore(release): bump to 0.2.0a1
```

---

## 10. Open Questions

1. **❓ Should Quill expose `prompts/list` and `prompts/get` *unfiltered*, or should the gate inspect prompt bodies for poisoning patterns?** Inspection would be useful but is heuristic; pinning is deterministic. Lean toward pinning-only for v0.2; revisit.
2. **❓ Sampling default**: refuse all, or pass-through with HIGH risk? Refusing breaks (the few) servers that use sampling; passing-through bets the user can adjudicate intelligently. **Default: refuse, opt-in per upstream.** Worth a poll on the discord.
3. **❓ Tool name collision strategy when upstream A has `read_file` and upstream B *also* has `read_file`**: Quill prefixes both, so they appear as `A.read_file` and `B.read_file`. But the LLM may not know which one to call. Should Quill *also* expose unprefixed if exactly one upstream has that tool? `proxy.py:148` says no - always prefix. Is this right? Probably yes (deterministic), but it imposes friction.
4. **❓ Streamable-HTTP downstream (Quill ↔ client over HTTP)**: low demand today. Skip for v0.2?
5. **❓ Lasso integration as a `GatePolicy` plugin**: would users want this, or is Quill's classifier enough? Don't build until asked.
6. **❓ Error code preservation in vendored code**: sparfenyuk swallows. Quill must not. Should Quill upstream a PR fixing sparfenyuk, or just diverge? Probably PR - easier ongoing maintenance.
7. **❓ What does Quill do when an upstream advertises a tool whose `inputSchema` references a `$ref` to a definition Quill doesn't transitively dereference?** The MCP spec says inputSchema is "JSON Schema", which permits `$ref`. The official Python SDK does *not* dereference. The proxy passes through whatever the upstream gave. Risk: Quill's gate might want to inspect a schema property that's behind a `$ref`. **Lean: don't dereference. Pass the raw bytes.** But test against an upstream that uses `$ref`. ❓ I haven't found one in the official servers list yet - worth a search before week-2 freeze.

---

## Appendix A - License Compatibility Audit

| Source                            | License  | Quill compat | Notes                                    |
|-----------------------------------|----------|--------------|------------------------------------------|
| `sparfenyuk/mcp-proxy`           | MIT      | ✅ yes        | Copyright 2024 Sergey Parfenyuk; preserve LICENSE in `_vendor/` |
| `mcp` Python SDK (Anthropic)     | MIT      | ✅ yes        | already a dependency                     |
| `mark3labs/mcp-go`               | MIT      | ✅ yes        | Go, not vendored anyway                  |
| `lasso-security/mcp-gateway`     | ❓        | ❓            | check before any code is lifted          |
| Pomerium                         | Apache 2.0 | ✅ yes      | Go, not vendored                         |

## Appendix B - Quill files involved at exact line numbers

- `src/quill/proxy.py:33` - `from mcp import ClientSession, StdioServerParameters` - keep
- `src/quill/proxy.py:69–86` - `QuillProxy` dataclass + lifecycle - keep
- `src/quill/proxy.py:92–127` - `_connect_all_upstreams` - keep, modest refactor to take `TransportFactory`
- `src/quill/proxy.py:128–150` - `_discover_tools` - **replace** with vendor factory
- `src/quill/proxy.py:151–167` - `all_tools` - **delete** (becomes vendor factory's `_list_tools` body)
- `src/quill/proxy.py:169–311` - `call_tool` - **refactor** body into `gate.run(ctx, args, forward)` shape
- `src/quill/proxy.py:314–345` - `build_proxy_server` - **rewrite** to call vendor factory
- `src/quill/proxy.py:348–362` - `run_stdio` - keep

---

## Appendix C - Quill's differentiation vs. competitors

| Feature                                              | Quill | Lasso MCP-Gateway | Pomerium MCP | sparfenyuk/mcp-proxy |
|------------------------------------------------------|-------|-------------------|--------------|----------------------|
| Schema passthrough                                   | ✅ (post v0.2) | ✅                | n/a (different layer) | ✅                |
| Per-tool risk classification                         | ✅    | ✅ (heuristic)    | ❌            | ❌                   |
| Session-bound intent + scope                         | ✅    | ❌                | ❌ (identity-bound) | ❌                  |
| Sub-agent scope attenuation                          | ✅    | ❌                | ❌            | ❌                   |
| Signed audit log (HMAC, JSONL)                       | ✅    | ❓                | ❌            | ❌                   |
| Tool-description pinning (anti-tool-poisoning)       | 🚧 v0.2 | ✅              | ❌            | ❌                   |
| Bidirectional notification forwarding                | 🚧 v0.2 | ❓              | n/a          | ❌ (partial)         |
| Identity-aware enterprise auth                       | ❌    | ❌                | ✅            | ❌                   |
| Plugin-based policy providers                        | 🚧 v0.3 | ✅              | ❌            | ❌                   |

**Quill's wedge**: session-bound intent + scope attenuation + signed audit + sub-agent governance. Nobody else does sub-agent attenuation. That is the moat.

---

*end of report*
