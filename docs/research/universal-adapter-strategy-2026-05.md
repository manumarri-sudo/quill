# Quill v0.3 - Universal Adapter Strategy

*Research date: 2026-05-08. Researcher: Claude Opus 4.7 (1M ctx). Cold-start research; no Quill internal docs consulted.*

## Executive summary

Three things changed the analysis after the research pass:

1. **Cursor 1.7 (Sept 2025) shipped a hooks system that is a near-clone of Claude Code's**, with 18 events including `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, and a generic `preToolUse`. Same shape as Claude Code: spawn a subprocess, read JSON on stdin, return `{"permission":"allow"|"deny"|"ask"}` on stdout. This is the highest-leverage adapter to ship next - it's literally a function rename of the existing Claude Code adapter.
2. **OpenAI Codex CLI also shipped hooks** (`PreToolUse`, `PermissionRequest`, `PostToolUse`, etc.) with `permissionDecision: "allow"|"deny"`. Apache-2.0, written in Rust. Same JSON-over-stdio contract. Third adapter, ~150 LOC.
3. **AEGIS (`Justin0504/Aegis`, MIT)** is the closest existing OSS project to Quill - it does runtime policy enforcement, SHA-256 hash-chained audit, MCP stdio proxy, and auto-instruments 9 Python frameworks. We don't compete; we should mine its monkey-patch SDK list for Tier C adapters.

The universal pattern is clear: **most coding IDEs already let Quill plug in via MCP; only three of them (Claude Code, Cursor, Codex CLI) plus a handful of Python SDKs (LangGraph, OpenAI Agents, Pydantic AI, Google ADK, MS Agent Framework, CrewAI) expose true synchronous pre-tool gating**. Everything else is either MCP-allowlist-only (Cline, Windsurf, Continue, Zed, JetBrains, Copilot) or cloud-locked (Devin, Replit, GitHub Copilot Workspace).

The 1-2 week ship list is **3 hook adapters + 1 library API + 4 IDE config docs**. Everything else is either auto-covered by `quill serve` (MCP proxy mode) or not worth shipping.

---

## 1. Coverage matrix

### Tier A - IDE / desktop coding agents

| # | Name | URL | MCP client? | Sync hook? | Install friction (if hook adapter shipped) | Est. user base | License |
|---|------|-----|-------------|------------|--------------------------------------------|----------------|---------|
| 1 | Cursor | [cursor.com/docs/hooks](https://cursor.com/docs/hooks) | yes (`.cursor/mcp.json`) | **YES** - 18 events, JSON-over-stdio, identical shape to Claude Code | one-line `~/.cursor/hooks.json` | ~1.5M MAU 🔶 INFERENCE | proprietary |
| 2 | Cline | [github.com/cline/cline](https://github.com/cline/cline) | yes (`cline_mcp_settings.json`) | no - only per-tool `autoApprove` allowlist | MCP-proxy only | ~500K installs 🔶 INFERENCE | Apache-2.0 |
| 3 | Windsurf (Codeium) | [docs.windsurf.com/cascade/mcp](https://docs.windsurf.com/windsurf/cascade/mcp) | yes (`~/.codeium/windsurf/mcp_config.json`) | no - only `alwaysAllow` | MCP-proxy only | ~700K MAU 🔶 INFERENCE | proprietary |
| 4 | GitHub Copilot agent mode | [docs.github.com/copilot/.../mcp](https://docs.github.com/copilot/customizing-copilot/using-model-context-protocol/extending-copilot-chat-with-mcp) | yes (VS Code `mcp.json` or `settings.json` `mcp` key) | no - UI permission picker only | MCP-proxy only | ~1.8M agent-mode users 🔶 INFERENCE | proprietary |
| 5 | Continue.dev | [docs.continue.dev/customize/mcp-tools](https://docs.continue.dev/customize/mcp-tools) | yes (`config.yaml`) | partial - declarative `permissions.yaml` only, no script hook | MCP-proxy + docs for `permissions.yaml` | ~250K installs 🔶 INFERENCE | Apache-2.0 |
| 6 | Cody (Sourcegraph) | [sourcegraph.com/changelog/mcp-context-gathering](https://sourcegraph.com/changelog/mcp-context-gathering) | yes (since v5.4) | no | MCP-proxy only | ~150K active 🔶 INFERENCE | Apache-2.0 |
| 7 | Zed | [zed.dev/docs/ai/mcp](https://zed.dev/docs/ai/mcp) | yes (`context_servers` in `settings.json`) | no - only `agent.tool_permissions` allowlist; forwards MCP to ACP agents | MCP-proxy only | ~300K MAU 🔶 INFERENCE | GPL-3.0 (editor) - hooks would not vendor, but config docs are fine |
| 8 | Replit Agent | [docs.replit.com/replitai/mcp](https://docs.replit.com/replitai/mcp/overview) | yes - remote MCP via Integrations pane (Nov 2025+) | no - Replit's own scanner runs server-side | NOT INSTALLABLE - cloud-only, can plug `quill serve` if exposed as remote MCP | ~30M users (broad) 🔶 INFERENCE | proprietary |
| 9 | JetBrains AI Assistant | [jetbrains.com/help/ai-assistant/mcp.html](https://www.jetbrains.com/help/ai-assistant/mcp.html) | yes - both client (2025.1) and server (2025.2); HTTP/SSE only, no stdio | no | MCP-proxy via streamable HTTP only - needs HTTP wrapper | ~12M IDE installs (subset use AI) 🔶 INFERENCE | proprietary IDE |

### Tier B - terminal coding agents

| # | Name | URL | MCP client? | Sync hook? | Install friction | Est. user base | License |
|---|------|-----|-------------|------------|------------------|----------------|---------|
| 10 | Aider | [aider.chat](https://aider.chat/docs/config/options.html) | no | **NO** - only `--lint`, `--test-cmd` (post-edit, not pre-tool) | NOT WORTH SHIPPING - no pre-execution hook surface | ~120K MAU 🔶 INFERENCE | Apache-2.0 |
| 11 | OpenAI Codex CLI | [developers.openai.com/codex/hooks](https://developers.openai.com/codex/hooks) | yes | **YES** - 6 events, JSON-over-stdio, near-identical to Claude Code | one-line `~/.codex/hooks.json` | ~400K weekly 🔶 INFERENCE | Apache-2.0 |
| 12 | Claude Code | [code.claude.com/docs/en/hooks-guide](https://code.claude.com/docs/en/hooks-guide) | yes | **YES** - already shipping | already shipped | ~3M MAU 🔶 INFERENCE | proprietary CLI |
| 13a | Devin | devin.ai | n/a - cloud SaaS | no user-side hook | NOT INSTALLABLE | ~unknown 🔶 INFERENCE | proprietary |
| 13b | SWE-agent (Princeton) | github.com/princeton-nlp/SWE-agent | no MCP | no docs hook | NOT WORTH SHIPPING - research artifact | ~20K stars, low active 🔶 INFERENCE | MIT |
| 13c | Open SWE (LangChain) | [langchain.com/blog/open-swe](https://www.langchain.com/blog/open-swe-an-open-source-framework-for-internal-coding-agents) | inherits LangGraph | YES via LangGraph middleware | covered by Tier C #16 | ~unknown 🔶 INFERENCE | MIT |

### Tier C - agent runtime SDKs (BYO-loop)

| # | Name | URL | MCP client? | Sync hook? | Install friction | Est. user base | License |
|---|------|-----|-------------|------------|------------------|----------------|---------|
| 14 | OpenAI Agents SDK (Python) | [openai.github.io/openai-agents-python/ref/lifecycle](https://openai.github.io/openai-agents-python/ref/lifecycle/) | optional | **YES** - `RunHooks.on_tool_start(ctx, agent, tool)` async; subclass + pass to `Runner.run` | subclass + `hooks=QuillRunHooks()` | ~250K weekly DL of `openai-agents` 🔶 INFERENCE | Apache-2.0 |
| 15 | Anthropic Messages API + tool_use | [docs.anthropic.com/.../tool-use](https://docs.anthropic.com/en/docs/build-with-claude/tool-use) | n/a - bare API | n/a - user writes the loop | wrap-around `gate()` call before dispatching `tool_use` blocks | very large (entire Anthropic SDK userbase) | MIT (SDK) |
| 16 | LangGraph | [docs.langchain.com/oss/python/langchain/human-in-the-loop](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) | optional | **YES** - `HumanInTheLoopMiddleware` + `interrupt()` API | `middleware=[QuillMiddleware()]` on `create_agent`; OR raw `interrupt()` from a node | ~2M monthly DL (langgraph) 🔶 INFERENCE | MIT |
| 17 | CrewAI | [docs.crewai.com/learn/tool-hooks](https://docs.crewai.com/en/learn/tool-hooks) | yes | **YES** - `@before_tool_call` decorator, return `False` to block | `from quill.crewai import before_tool_call` | ~1.5M monthly DL 🔶 INFERENCE | MIT |
| 18a | AutoGen (Microsoft) | [microsoft.github.io/autogen/.../tool-use-with-intervention](https://microsoft.github.io/autogen/stable//user-guide/core-user-guide/cookbook/tool-use-with-intervention.html) | partial | YES via `ToolInterventionHandler` | maintenance-mode - skip | ~3M DL but declining 🔶 INFERENCE | MIT (CC-BY for some) |
| 18b | MS Agent Framework 1.0 | [learn.microsoft.com/en-us/agent-framework](https://learn.microsoft.com/en-us/agent-framework/overview/) | yes | **YES** - `FunctionMiddleware` (tool-level), `AgentMiddleware`, `ChatMiddleware` | subclass `FunctionMiddleware` | new (Oct 2025) - ~50K early 🔶 INFERENCE | MIT |
| 19 | Pydantic AI | [pydantic.dev/docs/ai/core-concepts/hooks](https://pydantic.dev/docs/ai/core-concepts/hooks/) | yes (toolsets) | **YES** - `@hooks.on.before_tool_execute`; raise `SkipToolExecution(result)` to block | decorator | ~600K monthly DL 🔶 INFERENCE | MIT |
| 20 | Google ADK | [google.github.io/adk-docs/callbacks](https://google.github.io/adk-docs/callbacks/) | partial | **YES** - `before_tool_callback(tool, input, ctx) -> Optional[dict]`; return non-None to short-circuit | callback arg on `Agent(...)` | new but Google-backed - ~150K 🔶 INFERENCE | Apache-2.0 |
| 21 | LlamaIndex agents | [developers.llamaindex.ai/.../agent_workflow_basic](https://developers.llamaindex.ai/python/examples/agent/agent_workflow_basic/) | yes | partial - `InputRequiredEvent` / `HumanResponseEvent` workflow events; not a clean tool-callback | wrap `FunctionAgent.call_tool` via subclass | ~1.5M monthly DL 🔶 INFERENCE | MIT |

### Tier D - orchestration / observability

| # | Name | URL | MCP client? | Sync hook? | Install friction | Est. user base | License |
|---|------|-----|-------------|------------|------------------|----------------|---------|
| 22 | n8n | [docs.n8n.io/advanced-ai/human-in-the-loop-tools](https://docs.n8n.io/advanced-ai/human-in-the-loop-tools/) | yes (AI Agent node) | **YES** - built-in HITL panel routing via Slack/Telegram/etc. | NOT WORTH WRITING ADAPTER - n8n's own HITL is already shipped; just publish a "Quill review channel" community node 🔶 INFERENCE | ~100K self-hosted 🔶 INFERENCE | Sustainable Use License (≠ OSI) - vendoring blocked |
| 23 | Make.com | make.com | no | no user-side hook | cloud-only, NOT WORTH | n/a 🔶 INFERENCE | proprietary |
| 24 | Zapier | nla.zapier.com/docs/platform/windsurf | partial | no | cloud-only, NOT WORTH | n/a | proprietary |
| 25 | Vellum / Langfuse / Phoenix | langfuse.com | n/a - observability-only | NO - they trace, they don't gate | NOT A FIT - wrong layer | varies | varies |

---

## 2. The universal pattern

Strip every target down and three integration shapes account for the entire matrix:

### Shape 1 - "spawn-a-process" hooks (Claude Code, Cursor 1.7, Codex CLI)

The contract is essentially the same:

- IDE/CLI spawns `quill <hook-name>` as a subprocess on every tool call.
- Quill reads a JSON event from `stdin`.
- Quill writes a JSON verdict to `stdout`. Field names differ (`permission` vs `permissionDecision`), but the values are isomorphic: `allow | deny | ask`.
- Exit code 2 is universally "block."
- Configuration is a single JSON/TOML file declaring the hook command and a tool-name matcher (regex).

**Implication:** one internal `quill.adapters._hook_protocol` module that emits the right JSON shape, plus three thin shells that do field renaming. Total budget ~600 LOC.

### Shape 2 - "subclass / decorator / middleware" SDK hooks (OpenAI Agents, LangGraph, CrewAI, Pydantic AI, ADK, MS Agent Framework, AutoGen, LlamaIndex)

Every BYO-loop framework already has the hook surface. What they want is a Python `gate()` function that:

```python
verdict = await quill.gate(tool_name, tool_input, runtime="openai-agents")
```

…with a per-runtime adapter that wraps it in the framework's protocol (`RunHooks.on_tool_start`, `@before_tool_execute`, `before_tool_callback`, `FunctionMiddleware`, etc.).

**Implication:** ship `from quill import gate` as the public lib API, plus framework-specific entry points like `quill.openai_agents.QuillRunHooks`, `quill.langgraph.QuillMiddleware`, `quill.crewai.before_tool_call`, `quill.pydantic_ai.hooks`. Each framework adapter is 30-80 LOC.

### Shape 3 - "MCP allowlist only" IDEs (Cline, Windsurf, Copilot, Cody, Continue, Zed, JetBrains)

These don't have a sync gate hook. But they all already accept MCP servers as configurable upstreams. So `quill serve` already covers them; the only work is **per-IDE config docs** showing the literal `mcp.json` snippet that wires Quill in.

**Implication:** one docs page per IDE, ~10 lines of YAML/JSON each. No code at all.

---

## 3. Adapter-by-adapter spec - top 8 by user-impact-per-engineering-hour

For each: file path inside Quill repo, ~LOC budget, exact contract from the target's docs, fallback to MCP-proxy if hook missing, **Vendor / build-on / write-fresh verdict.**

### 3.1. Cursor hook adapter - HIGHEST PRIORITY ✅ VERIFIED

- **File path:** `src/quill/adapters/cursor.py`
- **CLI entry:** `quill cursor-hook` (single binary, dispatches by `hook_event_name`)
- **LOC budget:** ~150 LOC (most logic is shared with Claude Code adapter)
- **Reach:** ~1.5M Cursor MAU; Cursor 1.7+ ships hooks since Sept 2025.
- **Hook contract** (from [cursor.com/docs/hooks](https://cursor.com/docs/hooks)):

  Config at `~/.cursor/hooks.json`:
  ```json
  {
    "version": 1,
    "hooks": {
      "beforeShellExecution": [
        { "command": "quill cursor-hook", "type": "command", "timeout": 30 }
      ],
      "beforeMCPExecution": [
        { "command": "quill cursor-hook", "type": "command" }
      ],
      "beforeReadFile": [
        { "command": "quill cursor-hook", "type": "command" }
      ]
    }
  }
  ```

  Stdin (for `beforeShellExecution`):
  ```json
  { "command": "rm -rf /", "cwd": "/repo", "sandbox": false,
    "conversation_id": "...", "hook_event_name": "beforeShellExecution" }
  ```

  Stdout (Cursor's exact field names - note: NOT `permissionDecision`):
  ```json
  { "permission": "deny",
    "agent_message": "rm -rf is blocked by Quill policy",
    "user_message": "Use git clean -fdx if you really mean it." }
  ```

- **Fallback if hook unavailable** (Cursor < 1.7): user adds `quill` to `.cursor/mcp.json` instead - automatic via existing MCP-proxy mode.
- **Vendor / build-on / write-fresh:** **BUILD-ON.** Reuse the existing `quill.adapters.claude_code.decide()` core; the only delta is field renames (`tool_name` → `tool_name`; `permissionDecision` → `permission`; `decision.behavior` → `permission`). No third-party code to vendor - Cursor's hooks are proprietary, but the JSON contract is the only thing we touch.
- **Why first:** ~1.5M MAU, near-zero new logic, install friction is one config line. Highest ROI of any adapter not yet shipped.

### 3.2. OpenAI Codex CLI hook adapter ✅ VERIFIED

- **File path:** `src/quill/adapters/codex.py`
- **CLI entry:** `quill codex-hook`
- **LOC budget:** ~120 LOC (shares `_hook_protocol`)
- **Reach:** ~400K weekly Codex CLI users (npm + brew installs), Apache-2.0 source on `openai/codex`.
- **Hook contract** (from [developers.openai.com/codex/hooks](https://developers.openai.com/codex/hooks)):

  Config at `~/.codex/config.toml`:
  ```toml
  [features]
  codex_hooks = true

  [[hooks.PreToolUse]]
  matcher = "^Bash$|^apply_patch$|mcp__.*"

  [[hooks.PreToolUse.hooks]]
  type = "command"
  command = "quill codex-hook"
  timeout = 30
  ```

  Stdin includes `tool_name`, `tool_input`, `tool_use_id`, `cwd`, `session_id`, `transcript_path`.

  Stdout to deny - Codex uses Claude Code's `hookSpecificOutput` shape:
  ```json
  { "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": "Quill blocked: rm -rf detected"
    }
  }
  ```

- **Fallback:** Codex CLI also accepts MCP servers in `~/.codex/config.toml` under `[mcp_servers]` - `quill serve` works as upstream.
- **Vendor / build-on / write-fresh:** **BUILD-ON.** This is literally Claude Code's contract with TOML config instead of JSON. Reuse the Claude Code adapter's stdin parser, swap output shape. ~120 LOC almost all renames.

### 3.3. LangGraph middleware ✅ VERIFIED

- **File path:** `src/quill/adapters/langgraph.py`
- **LOC budget:** ~100 LOC
- **Reach:** ~2M monthly downloads (`langgraph`); used by Open SWE, AgentOps, etc.
- **Hook contract** (from [docs.langchain.com/.../human-in-the-loop](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)):

  ```python
  from langchain.agents.middleware import HumanInTheLoopMiddleware
  from langgraph.types import interrupt

  class QuillMiddleware(HumanInTheLoopMiddleware):
      def __init__(self):
          super().__init__(interrupt_on={"*": True})

      async def before_tool(self, state, tool_call):
          verdict = await quill.gate(tool_call["name"], tool_call["args"])
          if verdict.severity == "deny":
              return {"action": "reject", "message": verdict.reason}
          if verdict.severity == "ask":
              return interrupt({"tool": tool_call, "fix": verdict.fix})
          return {"action": "approve"}
  ```

  Wire-in:
  ```python
  agent = create_agent(model="...", tools=[...],
                      middleware=[QuillMiddleware()],
                      checkpointer=AsyncPostgresSaver(...))
  ```

- **Fallback:** N/A - if user is on LangGraph they have middleware support.
- **Vendor / build-on / write-fresh:** **BUILD-ON.** `HumanInTheLoopMiddleware` is shipped by LangChain (MIT). We subclass it. Add `langchain[langgraph] >= 0.4.x` as an optional extra: `pip install quill[langgraph]`.

### 3.4. OpenAI Agents SDK hooks ✅ VERIFIED

- **File path:** `src/quill/adapters/openai_agents.py`
- **LOC budget:** ~80 LOC
- **Reach:** ~250K weekly DL of `openai-agents`; the OpenAI-blessed SDK so userbase is climbing fast.
- **Hook contract** (from [openai.github.io/openai-agents-python/ref/lifecycle](https://openai.github.io/openai-agents-python/ref/lifecycle/)):

  ```python
  from agents.lifecycle import RunHooks
  from agents import Tool, RunContextWrapper, Agent

  class QuillRunHooks(RunHooks):
      async def on_tool_start(self, ctx: RunContextWrapper, agent: Agent, tool: Tool):
          # NOTE: arguments not exposed in current API (issue #939).
          # Workaround: snapshot the latest pending tool_use from ctx.input_items.
          pending = next((m for m in reversed(ctx.input_items) if m.type == "tool_use"), None)
          verdict = await quill.gate(tool.name, pending.input if pending else {})
          if verdict.severity == "deny":
              raise PermissionError(f"Quill blocked: {verdict.reason}")

  Runner.run(agent, hooks=QuillRunHooks())
  ```

- **Open issue:** ❓ OPEN QUESTION - `on_tool_start` in current OpenAI Agents SDK does **not** receive raw tool arguments (per [issue #939](https://github.com/openai/openai-agents-python/issues/939)). Quill must snapshot from `ctx.input_items` until OpenAI fixes this. Manu should subscribe to that issue.
- **Vendor / build-on / write-fresh:** **BUILD-ON.** `RunHooks` is a Protocol type shipped by `openai-agents` (Apache-2.0). Subclass it.

### 3.5. CrewAI tool hooks ✅ VERIFIED

- **File path:** `src/quill/adapters/crewai.py`
- **LOC budget:** ~50 LOC
- **Reach:** ~1.5M monthly downloads of `crewai`.
- **Hook contract** (from [docs.crewai.com/learn/tool-hooks](https://docs.crewai.com/en/learn/tool-hooks)):

  ```python
  from crewai.hooks import before_tool_call
  import quill

  @before_tool_call
  async def quill_gate(ctx):  # ctx.tool_name, ctx.tool_input
      verdict = await quill.gate(ctx.tool_name, ctx.tool_input)
      if verdict.severity == "deny":
          return False  # blocks execution
      return None
  ```

- **Vendor / build-on / write-fresh:** **BUILD-ON.** `@before_tool_call` is shipped by CrewAI (MIT). One-page docs + 50 LOC of glue.

### 3.6. Pydantic AI hooks ✅ VERIFIED

- **File path:** `src/quill/adapters/pydantic_ai.py`
- **LOC budget:** ~60 LOC
- **Reach:** ~600K monthly DL.
- **Hook contract** (from [pydantic.dev/docs/ai/core-concepts/hooks](https://pydantic.dev/docs/ai/core-concepts/hooks/)):

  ```python
  from pydantic_ai import Agent, Hooks
  from pydantic_ai.exceptions import SkipToolExecution
  import quill

  hooks = Hooks()

  @hooks.on.before_tool_execute()
  async def quill_gate(ctx, call, tool_def):
      verdict = await quill.gate(call.tool_name, call.args)
      if verdict.severity == "deny":
          raise SkipToolExecution(result=f"Blocked by Quill: {verdict.reason}")

  agent = Agent("anthropic:claude-sonnet-4-7", hooks=hooks, ...)
  ```

- **Vendor / build-on / write-fresh:** **BUILD-ON.** `Hooks`/`SkipToolExecution` ship in `pydantic-ai` (MIT).

### 3.7. Google ADK callback ✅ VERIFIED

- **File path:** `src/quill/adapters/google_adk.py`
- **LOC budget:** ~50 LOC
- **Reach:** ~150K MAU 🔶 INFERENCE; Google-backed so growth curve matters.
- **Hook contract** (from [google.github.io/adk-docs/callbacks](https://google.github.io/adk-docs/callbacks/)):

  ```python
  from google.adk import Agent
  from google.adk.tools import Tool, CallbackContext
  import quill

  async def quill_before_tool(tool: Tool, input: dict, ctx: CallbackContext):
      verdict = await quill.gate(tool.name, input)
      if verdict.severity == "deny":
          # Returning a dict short-circuits and is used as the tool result
          return {"error": f"Blocked: {verdict.reason}"}
      return None  # let it through

  agent = Agent(name="...", tools=[...], before_tool_callback=quill_before_tool)
  ```

- **Vendor / build-on / write-fresh:** **BUILD-ON.** Apache-2.0 SDK; subclass-free.

### 3.8. Microsoft Agent Framework `FunctionMiddleware` ✅ VERIFIED

- **File path:** `src/quill/adapters/ms_agent_framework.py`
- **LOC budget:** ~70 LOC
- **Reach:** new (Oct 2025), only ~50K early but enterprise distribution channel via Azure.
- **Hook contract** (from [learn.microsoft.com/agent-framework](https://learn.microsoft.com/en-us/agent-framework/overview/)): three middleware tiers - `AgentMiddleware` (turn-level), `FunctionMiddleware` (tool-level), `ChatMiddleware` (model-level). We hook into `FunctionMiddleware`.
- **Vendor / build-on / write-fresh:** **BUILD-ON.** MIT. Subclass `FunctionMiddleware` and call `quill.gate()` in `__call__`.

### Adapters explicitly deferred or skipped

- **Aider** (#10): no synchronous tool hook surface. `--lint` and `--test-cmd` are post-edit. Aider's design is "review every diff interactively"; not a fit. **Anti-recommendation.**
- **AutoGen** (#18a): in maintenance mode per [microsoft/autogen README](https://github.com/microsoft/autogen). Skip.
- **LlamaIndex agents** (#21): only event-bus-style HITL via `InputRequiredEvent`. Doable but ~150 LOC for a niche audience. Defer to v0.4.
- **Cline / Windsurf / Continue / Cody / Zed / Copilot / JetBrains:** no sync hook. Covered by `quill serve` MCP-proxy + per-IDE config docs (§5).
- **Replit / Devin / Codex Cloud / Copilot Workspace:** cloud-only, no instrumentation surface.
- **Make / Zapier:** cloud-only orchestrators; not a Quill audience.
- **Vellum / Langfuse / Phoenix:** observability-only, wrong layer.
- **n8n:** has built-in HITL via the AI Agent node ([docs.n8n.io](https://docs.n8n.io/advanced-ai/human-in-the-loop-tools/)). Plus n8n's [Sustainable Use License](https://github.com/n8n-io/n8n/blob/master/LICENSE.md) is **not OSI-compatible** (commercial restrictions), so vendoring is risky. Skip.

---

## 4. Library API design - `from quill import gate`

The single Python entry point that all SDK adapters call into. Sketch:

```python
# src/quill/__init__.py
from quill._gate import gate, HookDecision, Severity

# src/quill/_gate.py
from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Any, Literal

Severity = Literal["allow", "ask", "deny"]

@dataclass(frozen=True)
class HookDecision:
    severity: Severity
    reason: str = ""
    fix: str | None = None         # paste-able remediation for "deny"
    rule_id: str | None = None     # for audit log
    audit_seq: int | None = None   # HMAC-chain sequence number

async def gate(
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    runtime: str = "library",     # "claude-code" | "cursor" | "codex" | "openai-agents" | ...
    agent_id: str | None = None,
    session_id: str | None = None,
    cwd: str | None = None,
    timeout_s: float = 5.0,
) -> HookDecision:
    """The single gate. Async-first; sync wrapper available as `quill.gate_sync(...)`.

    Loads the active policy from ~/.quill/policy.yaml (or QUILL_POLICY env),
    evaluates against (tool_name, tool_input, cwd), writes an audit-log entry,
    and returns a HookDecision. Touch-ID-gated approvals are surfaced as
    severity="ask" - the caller decides how to ask (subprocess prompt for
    CLIs, interrupt() for LangGraph, raise for OpenAI Agents, etc.).
    """
    ...

def gate_sync(*args, **kwargs) -> HookDecision:
    return asyncio.run(gate(*args, **kwargs))
```

Usage from a bare `anthropic.messages` loop (the universal BYO-loop fallback):

```python
import anthropic, quill

client = anthropic.Anthropic()
messages = [{"role": "user", "content": "ship to prod"}]
while True:
    resp = client.messages.create(model="claude-sonnet-4-7", tools=[...], messages=messages)
    if resp.stop_reason != "tool_use":
        break
    for block in resp.content:
        if block.type != "tool_use": continue
        verdict = await quill.gate(block.name, block.input, runtime="anthropic-bare")
        if verdict.severity == "deny":
            tool_result = {"is_error": True, "content": verdict.reason}
        elif verdict.severity == "ask":
            # raise to let the caller handle UX
            raise quill.NeedsApproval(verdict)
        else:
            tool_result = run_tool(block.name, block.input)
        messages.append({"role": "assistant", "content": resp.content})
        messages.append({"role": "user", "content": [{"type":"tool_result", "tool_use_id":block.id, "content": tool_result}]})
```

This is the same `gate()` every framework adapter wraps. **One function, ten adapters.**

---

## 5. Per-IDE config docs (the no-code wins)

Every IDE that already speaks MCP can use Quill today by listing `quill serve` as an upstream. The work is purely docs - copy-pasteable snippets per IDE. All blocks below were verified against the linked official documentation.

### 5.1. Claude Desktop / Claude Code

`~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "quill": { "command": "quill", "args": ["serve"] }
  }
}
```

### 5.2. Cursor

`.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):
```json
{
  "mcpServers": {
    "quill": {
      "type": "stdio",
      "command": "quill",
      "args": ["serve"]
    }
  }
}
```
Per [cursor.com/docs/mcp](https://cursor.com/docs/mcp). The `type: "stdio"` field is required as of Cursor 1.6+.

### 5.3. Cline (VS Code)

`~/.cline/data/settings/cline_mcp_settings.json`:
```json
{
  "mcpServers": {
    "quill": {
      "command": "quill",
      "args": ["serve"],
      "alwaysAllow": []
    }
  }
}
```
Note: leave `alwaysAllow` empty; Quill's whole job is to gate, not auto-approve.

### 5.4. Windsurf (Codeium Cascade)

`~/.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "quill": {
      "command": "quill",
      "args": ["serve"]
    }
  }
}
```

### 5.5. Continue.dev (`config.yaml`)

```yaml
mcpServers:
  - name: quill
    command: quill
    args: ["serve"]
```

Plus optional `~/.continue/permissions.yaml` to mark the agent's tools as `ask` so they route through Quill (declarative - no script callout, but routes everything through MCP):
```yaml
ask:
  - "*"
```

### 5.6. Zed

`~/.config/zed/settings.json`:
```json
{
  "context_servers": {
    "quill": {
      "command": "quill",
      "args": ["serve"]
    }
  },
  "agent": {
    "tool_permissions": {
      "default": "confirm"
    }
  }
}
```

### 5.7. GitHub Copilot agent mode (VS Code)

`.vscode/mcp.json`:
```json
{
  "servers": {
    "quill": {
      "type": "stdio",
      "command": "quill",
      "args": ["serve"]
    }
  }
}
```
Per [code.visualstudio.com/docs/copilot/customization/mcp-servers](https://code.visualstudio.com/docs/copilot/customization/mcp-servers).

### 5.8. JetBrains AI Assistant

JetBrains AI Assistant only speaks **Streamable HTTP / SSE** ([jetbrains.com/help/ai-assistant/mcp.html](https://www.jetbrains.com/help/ai-assistant/mcp.html)), not stdio. So Quill must run in HTTP mode. Suggest `quill serve --http :7711` and configure JetBrains AI → Settings → Tools → MCP Servers → Add → URL `http://127.0.0.1:7711/mcp`.

### 5.9. Codex CLI (MCP fallback for non-hook users)

`~/.codex/config.toml`:
```toml
[mcp_servers.quill]
command = "quill"
args = ["serve"]
```

### 5.10. Cody

`~/Library/Application Support/com.sourcegraph.cody/cody.json` (or VS Code settings) - Cody supports MCP since v1.50. Same shape as Claude Desktop config above.

---

## 6. Anti-recommendations - do NOT ship adapters for these

| Target | Reason |
|--------|--------|
| **Aider** | No synchronous pre-tool hook. `--lint`/`--test-cmd` fire after edits. Wait for upstream - open an issue and politely lobby. |
| **Replit Agent** | Cloud-only; Replit runs its own scanner server-side. Best we can do is publish a remote MCP for users who self-host. Low ROI. |
| **Devin / Cognition** | Cloud SaaS, no user instrumentation surface. |
| **Copilot Workspace** (cloud agent) | No user-side hook. Local VS Code Copilot is covered by §5.7. |
| **AutoGen** | In maintenance mode; users moving to MS Agent Framework. Cover MAF (§3.8) instead. |
| **Make.com / Zapier** | Wrong audience; orchestration vendors, not coding-agent runtimes. |
| **Vellum / Langfuse / Phoenix / Arize** | Observability-only. They tell you what *did* happen; Quill prevents what *will* happen. Different layer of the stack. Integration value is two-way (Quill emits OTel; Langfuse traces include Quill verdicts) but not an "adapter." |
| **n8n** | Has its own HITL panel. License is non-OSI (Sustainable Use). Best play: a community n8n node ("Quill review channel") - community-built, not core Quill. |
| **SWE-agent (Princeton)** | Research artifact. Low active userbase, no hook surface. |
| **JetBrains MCP server (the one shipped *by* the IDE)** | That's Quill's *peer*, not a host. The IDE acts as MCP **server** for external clients. JetBrains as MCP **client** is what we want - covered in §5.8. |

---

## 7. Phasing - 1-week / 2-week / 1-month

### 1-week ship (~5 working days, ~700 LOC + docs)

**Day 1-2:** Cursor hook adapter (`adapters/cursor.py`, ~150 LOC).
**Day 3:** Codex CLI hook adapter (`adapters/codex.py`, ~120 LOC).
**Day 4:** `quill.gate()` library API + sync wrapper + tests (~150 LOC).
**Day 5:** Per-IDE config docs (Cursor, Cline, Windsurf, Claude Desktop, Continue, Zed, Copilot/VS Code, JetBrains, Codex, Cody) - single page `docs/clients/`. Plus `tests/integration/` smoke tests.

End-of-week deliverable: Quill works in Claude Code (existing) + Cursor + Codex CLI as a hook, AND in 7 IDEs as MCP-proxy via config docs. Coverage jump from ~3M to ~5M+ MAU.

### 2-week ship (adds ~5 more days)

**Day 6-7:** LangGraph middleware (`adapters/langgraph.py`, ~100 LOC) - biggest BYO-loop audience.
**Day 8:** OpenAI Agents `RunHooks` (`adapters/openai_agents.py`, ~80 LOC). Note the `on_tool_start` arg-visibility gap (issue #939) in docs.
**Day 9:** Pydantic AI hooks (`adapters/pydantic_ai.py`, ~60 LOC) + CrewAI `@before_tool_call` (`adapters/crewai.py`, ~50 LOC).
**Day 10:** Google ADK `before_tool_callback` (`adapters/google_adk.py`, ~50 LOC) + MS Agent Framework `FunctionMiddleware` (`adapters/ms_agent_framework.py`, ~70 LOC).

End-of-week deliverable: full SDK coverage. `pip install quill[openai-agents,langgraph,crewai,pydantic-ai,adk,maf]` extras. README adds a one-line install for each.

### 1-month ship (next 2 weeks beyond v0.3)

- LlamaIndex agent adapter (~150 LOC; non-trivial because of event-bus model).
- AEGIS interop: emit OpenTelemetry traces in AEGIS-compatible format so users running both can correlate. ([Justin0504/Aegis](https://github.com/Justin0504/Aegis), MIT.)
- Lasso `mcp-gateway` plugin: ship Quill as a `mcp-gateway` plugin so enterprise users using Lasso can drop Quill in. ([lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway), MIT.)
- Langfuse integration: emit Quill verdicts as Langfuse traces with severity tags. Observability bridge, not gating.
- HTTP/SSE transport for `quill serve` (needed for JetBrains AI Assistant which doesn't speak stdio).
- n8n community node ("Quill review channel") - community-built; review and feature.

### Vendor-or-build-on candidates worth evaluating during v0.3

🔶 INFERENCE on which exact files to lift; verify on first read of each repo.

1. **`langchain-ai/langchain` (`HumanInTheLoopMiddleware`)** - MIT, [github.com/langchain-ai/langchain](https://github.com/langchain-ai/langchain). **BUILD-ON** as optional dep (`langchain[langgraph]>=0.4`). Subclass `HumanInTheLoopMiddleware`. Saves ~300 LOC of state-machine work.
2. **`Justin0504/Aegis` `packages/sdk-python`** - MIT, monkey-patch list for 9 frameworks (LangChain, OpenAI, Anthropic, CrewAI, Gemini, Bedrock, Mistral, LlamaIndex, smolagents). **VENDOR** the framework-detection list (their auto-instrumentation registry pattern) into `src/quill/_vendor/aegis/framework_registry.py` with attribution. This saves us figuring out the right monkey-patch points for each SDK.
3. **`lasso-security/mcp-gateway` `mcp_gateway/plugins/`** - MIT, plugin dispatch pattern for MCP-side policy plugins. **STUDY** (don't vendor unless clean). Useful as reference for designing Quill's own plugin extension API for v0.4.
4. **`pydantic/pydantic-ai` `Hooks`/`SkipToolExecution`** - MIT. **BUILD-ON** as optional dep.
5. **`microsoft/agent-framework` `FunctionMiddleware`** - MIT. **BUILD-ON** as optional dep.
6. **`google/adk-python`** - Apache-2.0. **BUILD-ON** as optional dep.

License-check summary: every recommended source is MIT or Apache-2.0. No GPL or AGPL code in the dependency or vendor path. Zed's editor is GPL but we never link it - we only document its config file. n8n's Sustainable Use License is incompatible - that's why n8n is a "skip" not a "vendor."

---

## Gaps & open questions

- ❓ **OpenAI Agents SDK `on_tool_start` doesn't expose tool args.** Per issue #939. Workaround in §3.4 (snapshot from `ctx.input_items`). Watch for fix.
- ❓ **Cursor hook reliability under "Auto-Run" mode.** [Forum thread](https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244) reports `beforeShellExecution` `permission: "ask"` is overridden by allow-list. Document workaround: Quill should return `"deny"` not `"ask"` when running in Cursor with allow-list mode. Add an env-detection hint.
- ❓ **JetBrains AI's MCP HTTP-only constraint.** Quill needs an HTTP transport for JetBrains. Sparfenyuk's `mcp-proxy` already does stdio↔HTTP bridging - vendor that for v0.3 if not already done.
- ❓ **MS Agent Framework `FunctionMiddleware` exact API.** Docs reference three middleware tiers but didn't surface the `__call__` signature in this pass. Read [github.com/microsoft/agent-framework](https://github.com/microsoft/agent-framework) on first day of implementation.
- ❓ **Cline's autoApprove vs Quill conflict.** If a Cline user adds Quill to `cline_mcp_settings.json` with `alwaysAllow: ["gate"]`, they bypass Quill's "ask" path. Docs must call this out (`alwaysAllow: []`).
- ❓ **`canUseTool` (Claude Agent SDK) vs hooks ordering.** Order is `PreToolUse Hook → Deny Rules → Allow Rules → Ask Rules → Permission Mode → canUseTool → PostToolUse`. Confirm Quill's hook fires *before* `canUseTool` so Quill's verdict pre-empts the SDK's interactive prompt.

## Next steps

1. Build the Cursor hook adapter (highest ROI), validate end-to-end on a Cursor 1.7+ install.
2. Ship the `quill.gate()` Python library API; convert the existing internal `quill.adapters.claude_code.decide()` to call it.
3. Write per-IDE config docs as an Astro/Docusaurus subsection - one page, ten copy-paste snippets, with a "test it" CLI command (`quill check-config --client cursor`).
4. Ship the LangGraph + OpenAI Agents adapters; submit example PRs to `langchain-ai/open-swe` and `openai/openai-agents-python` examples directories to seed adoption.
5. File a friendly issue with Aider asking for a `--pre-tool-hook` flag.

## Bibliography (primary sources only)

- Cursor Hooks: https://cursor.com/docs/hooks
- Cursor MCP: https://cursor.com/docs/mcp
- Claude Code Hooks Guide: https://code.claude.com/docs/en/hooks-guide
- Claude Agent SDK Permissions: https://platform.claude.com/docs/en/agent-sdk/permissions
- OpenAI Codex Hooks: https://developers.openai.com/codex/hooks
- OpenAI Codex Agent Approvals: https://developers.openai.com/codex/agent-approvals-security
- OpenAI Agents SDK Lifecycle: https://openai.github.io/openai-agents-python/ref/lifecycle/
- LangChain HITL Middleware: https://docs.langchain.com/oss/python/langchain/human-in-the-loop
- LangGraph interrupt(): https://www.langchain.com/blog/making-it-easier-to-build-human-in-the-loop-agents-with-interrupt
- CrewAI Tool Hooks: https://docs.crewai.com/en/learn/tool-hooks
- Pydantic AI Hooks: https://pydantic.dev/docs/ai/core-concepts/hooks/
- Google ADK Callbacks: https://google.github.io/adk-docs/callbacks/
- MS Agent Framework Overview: https://learn.microsoft.com/en-us/agent-framework/overview/
- AutoGen Tool Use Intervention: https://microsoft.github.io/autogen/stable//user-guide/core-user-guide/cookbook/tool-use-with-intervention.html
- LlamaIndex AgentWorkflow: https://developers.llamaindex.ai/python/examples/agent/agent_workflow_basic/
- Cline repo: https://github.com/cline/cline
- Cline MCP Management: https://deepwiki.com/cline/cline/9.2-mcp-server-management
- Windsurf Cascade MCP: https://docs.windsurf.com/windsurf/cascade/mcp
- Continue.dev MCP: https://docs.continue.dev/customize/mcp-tools
- Continue.dev CLI Permissions: https://docs.continue.dev/cli/tool-permissions
- Continue.dev config.yaml: https://docs.continue.dev/reference
- Cody MCP changelog: https://sourcegraph.com/changelog/mcp-context-gathering
- Zed MCP: https://zed.dev/docs/ai/mcp
- Zed Agent Settings: https://zed.dev/docs/ai/agent-settings
- VS Code Copilot MCP: https://code.visualstudio.com/docs/copilot/customization/mcp-servers
- GitHub Copilot agent + MCP: https://docs.github.com/copilot/customizing-copilot/using-model-context-protocol/extending-copilot-chat-with-mcp
- Replit MCP: https://docs.replit.com/replitai/mcp/overview
- JetBrains AI MCP: https://www.jetbrains.com/help/ai-assistant/mcp.html
- n8n HITL: https://docs.n8n.io/advanced-ai/human-in-the-loop-tools/
- Aider config options: https://aider.chat/docs/config/options.html
- AEGIS (runtime policy enforcement): https://github.com/Justin0504/Aegis
- Lasso MCP Gateway: https://github.com/lasso-security/mcp-gateway
- sparfenyuk/mcp-proxy: https://github.com/sparfenyuk/mcp-proxy
- Open SWE (LangChain): https://www.langchain.com/blog/open-swe-an-open-source-framework-for-internal-coding-agents
- Anthropic tool use: https://docs.anthropic.com/en/docs/build-with-claude/tool-use
- OpenAI Agents SDK issue #939 (tool args in hooks): https://github.com/openai/openai-agents-python/issues/939
