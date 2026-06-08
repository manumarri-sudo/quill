# BYO agents — wiring Quill into an agent loop you wrote yourself

If you're not on Claude Code, Cursor, Codex CLI, or one of the framework SDKs Quill has an adapter for (LangGraph, OpenAI Agents, CrewAI, Pydantic AI, Google ADK, MS Agent Framework — all on the v0.3 ship list), but you do have an agent loop you wrote yourself, this is the page for you.

Two paths today, one library API coming in v0.3. Pick whichever fits the loop you've already got.

---

## Path 1 — MCP proxy (works today, no Python changes)

If your agent already supports MCP servers as upstream tools, you don't need to touch Quill's Python at all. Run `quill serve` and wire it in as an MCP server in whatever config your loop reads. Every tool call your agent routes through MCP flows through Quill's gate, gets risk-classified, audit-logged with an HMAC chain, and either passes through, asks for approval, or is denied with a paste-able alternative.

```bash
# in the same shell your agent runs from
quill serve
```

Your agent's MCP config:

```json
{
  "mcpServers": {
    "quill": { "command": "quill", "args": ["serve"] }
  }
}
```

If you put real upstream MCP servers (filesystem, github, postgres, slack) *behind* Quill in [`~/.quill/config.toml`](../README.md#path-b-external-mcp-servers-filesystem-github-postgres-slack) under `[[upstream]]` blocks, Quill becomes a single MCP entry point that fans out to all of them and gates the whole subtree. Your agent only ever talks to `quill`; Quill talks to everything else.

What this doesn't cover: tool calls your agent dispatches *directly* (a Python `subprocess.run(...)`, a direct `requests.post(...)`, a `psycopg2.execute(...)` you wired into the loop without going through MCP). For those, you need Path 2.

---

## Path 2 — wrap each tool dispatch in `quill.gate()` (coming in v0.3)

If your loop dispatches tool calls directly in Python rather than going through MCP, the v0.3 ship target is a single `quill.gate()` library entry point you call before dispatching. Designed in [`docs/research/universal-adapter-strategy-2026-05.md`](research/universal-adapter-strategy-2026-05.md) §4 and on the Day-4 deliverable list of the v0.3 plan. The contract:

```python
from quill import gate, HookDecision

verdict: HookDecision = await gate(
    tool_name="Bash",
    tool_input={"command": "rm -rf node_modules"},
    runtime="my-agent",            # for the audit log + per-runtime policy
    agent_id="loomiq-builder-01",  # optional, threads into receipts
    session_id="ses_a4f1",         # optional, threads into the trifecta + receipts
    cwd="/repo",                   # optional, governs trust-scope downshifts
    timeout_s=5.0,
)

if verdict.severity == "deny":
    # don't run the call; tell the model why
    return {"is_error": True, "content": verdict.reason}
elif verdict.severity == "ask":
    # surface verdict.fix (the paste-able alternative) and the approve token
    # to whoever drives your loop's human-in-the-loop UX, then re-try
    raise quill.NeedsApproval(verdict)
else:  # "allow"
    result = run_my_tool(...)
```

The same `gate()` call is what every Quill framework adapter wraps for its specific protocol — `RunHooks.on_tool_start` for OpenAI Agents, `@before_tool_call` for CrewAI, `HumanInTheLoopMiddleware` for LangGraph, `FunctionMiddleware` for MS Agent Framework, `before_tool_callback` for Google ADK, `@hooks.on.before_tool_execute` for Pydantic AI. One function, ten integrations. If you write your own framework adapter, that's the function to wrap.

A sync wrapper `quill.gate_sync(...)` is on the ship list too for loops that don't use asyncio.

### The universal bare-loop template

Any agent loop that uses Anthropic's `messages` API directly (or anything isomorphic to it — OpenAI tool-use, Google's function-calling, Pydantic's) plugs Quill in at the dispatch site. The whole pattern:

```python
import anthropic, quill

client = anthropic.Anthropic()
messages = [{"role": "user", "content": "ship to prod"}]

while True:
    resp = client.messages.create(
        model="claude-sonnet-4-7",
        tools=[...],
        messages=messages,
    )
    if resp.stop_reason != "tool_use":
        break

    for block in resp.content:
        if block.type != "tool_use":
            continue

        verdict = await quill.gate(
            tool_name=block.name,
            tool_input=block.input,
            runtime="anthropic-bare",
        )

        if verdict.severity == "deny":
            tool_result = {"is_error": True, "content": verdict.reason}
        elif verdict.severity == "ask":
            # let your caller surface the approve token and decide
            raise quill.NeedsApproval(verdict)
        else:
            tool_result = run_tool(block.name, block.input)

        messages.append({"role": "assistant", "content": resp.content})
        messages.append({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": tool_result,
            }],
        })
```

Replace `anthropic-bare` with whichever runtime tag fits your loop; the audit log uses it to namespace decisions so you can slice "what did my custom agent attempt last week" cleanly without it getting mixed up with Claude Code or Cursor traffic.

---

## Until `quill.gate()` ships — the interim pattern

If your loop runs locally and you can't wait for v0.3, the workable interim is: route every direct tool dispatch through your own MCP server, point that MCP server at Quill, and let Path 1 above do the gating. The wiring is heavier than `gate()` will be (you write a tiny stdio MCP server that re-exports your loop's tools), but it works today against the shipped v0.2.0a5 proxy.

---

## What you get either way

Once Quill is in the loop:

- Every tool call is risk-classified and either allowed, denied with a one-line plain-English reason, or held for approval with a single-use 10-minute token bound to the exact `(tool_name, args_digest)` that was refused.
- Every decision lands in `~/.quill/audit.log.jsonl` with an HMAC-chained signature you can verify with `quill doctor`.
- Critical-risk blocks fan to whatever notification channels you opted in to in `~/.quill/config.toml` (`[notify]` block: macOS banners, email, Slack webhook, generic JSON webhook), so a misbehaving agent can't `rm -rf` while you're in another tab and have you find out an hour later.
- If you wired Quill in with a `session_id`, the session-level surfaces in the README (Agent Receipts, Lethal-Trifecta exposure tracking, A2A Bridge handoff edges) work for your agent the same way they work for Claude Code.

---

## Reference

- Full design rationale and matrix of every supported runtime: [`docs/research/universal-adapter-strategy-2026-05.md`](research/universal-adapter-strategy-2026-05.md) §3 and §4.
- Per-client MCP-proxy config snippets for IDEs and desktop agents: [`docs/clients.md`](clients.md).
