# Clients

Where Quill plugs into. Each section is copy-pasteable; the assumption is `quill` is on your PATH (`uvx quillx start` or `pipx install quillx` already done).

Quill governs an agent's tool path in one of three shapes. Pick the one that matches the client you're running; some clients support more than one and you should prefer the leftmost.

| Shape | What it gates | Clients today |
|-------|---------------|---------------|
| **Hook** (synchronous pre-tool) | the client's *built-in* tools (Bash, Edit, Write, shell, file IO) plus its MCP calls | Claude Code, Cursor 1.7+ |
| **MCP proxy** (`quill serve`) | every MCP-routed tool call the client makes, including any custom MCP servers you add | Claude Desktop, Claude Cowork, Cline, Windsurf, Continue, Cody, Zed, GitHub Copilot agent mode, JetBrains AI, OpenAI Codex CLI (fallback) |
| **Library** (`from quill import gate`) | every tool call in an agent loop you wrote yourself | BYO agents — see [`byo-agent.md`](byo-agent.md). v0.3 surface, not yet shipped. |

For everything in the MCP-proxy column, the *built-in* tools of that client are not gated by Quill — only the calls that flow through MCP are. That distinction matters and is called out per-client below.

---

## Hook adapters (shipped)

### Claude Code

The hero path; covered end-to-end in the top-level README under "Path A: Claude Code's built-in tools." `quill start` installs the hook into `~/.claude/settings.json`'s `PreToolUse` block and every `Bash`, `Edit`, `Write`, and `NotebookEdit` is gated synchronously before it fires. The contract and reply shape live in [`src/quill/adapters/claude_code.py`](../src/quill/adapters/claude_code.py).

### Cursor (1.7+)

Cursor shipped a hooks system in Sept 2025 with `beforeShellExecution`, `beforeMCPExecution`, and `beforeReadFile`. Quill installs into `~/.cursor/hooks.json`:

```bash
quill cursor-hook-install
```

The contract and the deny-instead-of-ask defense (Cursor's Auto-Run allow-list silently overrides `permission: "ask"`, so Quill returns `deny` on HIGH-risk and routes through the same `quill approve <token>` flow Claude Code uses) live in [`src/quill/adapters/cursor.py`](../src/quill/adapters/cursor.py).

---

## MCP-proxy clients

Every client below speaks MCP, so the integration is the same: declare `quill` as an MCP server, point it at `quill serve`, and every tool call the agent routes through MCP flows through the gate. What the gate sees and what it doesn't is identical across these clients — *it sees every MCP call (including ones to custom MCP servers you've added behind Quill), and it does not see the client's own built-in tools.* If you want built-ins gated, you need the hook adapter for that client, which only Claude Code and Cursor have today.

### Claude Desktop / Claude Cowork / Claude.ai desktop

Claude Cowork (Anthropic's desktop agentic product, GA'd 2026-04-09) and Claude Desktop share the same MCP config file on macOS, so configuring once works for both. Path: `~/Library/Application Support/Claude/claude_desktop_config.json`.

```json
{
  "mcpServers": {
    "quill": { "command": "quill", "args": ["serve"] }
  }
}
```

After saving, restart Cowork / Desktop. From the next session on, Quill gates every tool call routed through MCP. Cowork's own UI plan-approval gate still governs its built-in tools (file edits, scheduled task execution, the Anthropic-managed connectors for Google Drive / Gmail / DocuSign / FactSet); those don't flow through the local MCP layer and Quill cannot see them today, the same way Quill can't see Cline's or Windsurf's built-ins.

If you'd rather wire Quill in through Cowork's UI instead of the config file, Customize → Connectors → "+" → name `quill` → URL pointing at a public-internet MCP server. That path is cloud-side (Anthropic calls into your URL), so it only makes sense if you've stood Quill up behind a public endpoint; for a normal local install, the `claude_desktop_config.json` path above is what you want.

Enterprise Cowork tenants get OpenTelemetry ingestion in the admin dashboard. Quill already emits OTel from [`src/quill/otel.py`](../src/quill/otel.py); set `QUILL_OTEL_ENDPOINT` to your collector and gate decisions land in the same dashboard as the rest of the agent's traces.

### Cursor (MCP path, if you're not on 1.7+ or prefer MCP-only)

`.cursor/mcp.json` (per-project) or `~/.cursor/mcp.json` (global):

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

The `type: "stdio"` field is required as of Cursor 1.6+. The hook adapter from the section above gives strictly more coverage; only use the MCP path if you can't run hooks.

### Cline (VS Code)

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

Leave `alwaysAllow` empty. Quill's whole job is to gate; an entry there silently bypasses the gate and there is no warning.

### Windsurf (Codeium Cascade)

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

### Continue.dev

`config.yaml`:

```yaml
mcpServers:
  - name: quill
    command: quill
    args: ["serve"]
```

If you want Continue to route everything through ask-by-default (so all MCP traffic hits Quill regardless of per-tool defaults), add to `~/.continue/permissions.yaml`:

```yaml
ask:
  - "*"
```

### Cody (Sourcegraph)

Cody supports MCP since v5.4. Same shape as Claude Desktop above; the config file lives at `~/Library/Application Support/com.sourcegraph.cody/cody.json` on macOS, or in VS Code settings under the Cody extension.

### Zed

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

Zed forwards MCP to ACP agents downstream; Quill sits in front of that whole subtree.

### GitHub Copilot agent mode (VS Code)

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

### JetBrains AI Assistant

JetBrains AI only speaks Streamable HTTP / SSE, not stdio. Run Quill in HTTP mode and add it from Settings → Tools → MCP Servers → Add with the URL pointing at the local Quill HTTP endpoint. HTTP transport for `quill serve` is on the v0.3 ship list; until it lands, the [`sparfenyuk/mcp-proxy`](https://github.com/sparfenyuk/mcp-proxy) stdio↔HTTP bridge in front of `quill serve` works as a stopgap.

### OpenAI Codex CLI (MCP fallback)

Codex CLI shipped hooks of its own and a Codex hook adapter is on the v0.3 ship list. If you'd rather not wait, the MCP fallback covers every MCP call (but not Codex's built-ins). Add to `~/.codex/config.toml`:

```toml
[mcp_servers.quill]
command = "quill"
args = ["serve"]
```

---

## What's not on this list, and why

- **Replit Agent / Devin / Copilot Workspace / Codex Cloud:** cloud-only, no user-side instrumentation surface. Best we can do is publish a remote MCP for users who self-host. Low ROI.
- **Aider:** no synchronous pre-tool hook. `--lint` / `--test-cmd` fire after edits, so there's nothing to gate before the bad thing happens. Waiting on upstream for a `--pre-tool-hook` flag.
- **AutoGen:** in maintenance mode; users moving to MS Agent Framework. The MAF middleware adapter is on the v0.3 ship list instead.
- **n8n / Make / Zapier:** orchestration vendors, not coding-agent runtimes, and n8n's Sustainable Use License is not OSI-compatible so vendoring is blocked. n8n's own HITL panel covers most of what Quill would do at that layer; if a community n8n node ("Quill review channel") gets built, we'll feature it.
- **Vellum / Langfuse / Phoenix / Arize:** observability-only. They trace what happened; Quill prevents what's about to happen. Different layer of the stack. Quill emits OTel and Langfuse can ingest those traces if you want the verdicts in your existing dashboard — that's a bridge, not an adapter.

---

## Reference

The full coverage matrix, integration shape derivation, and per-target LOC budgets live in [`docs/research/universal-adapter-strategy-2026-05.md`](research/universal-adapter-strategy-2026-05.md). This page is the user-facing config sheet; that doc is the build plan behind it.
