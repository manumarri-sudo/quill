# Hook path vs proxy path: what fires where

Quill gates two different surfaces, and they are NOT equivalent. Treating
the MCP proxy as if it ran every protection the PreToolUse hook runs is the
over-trust trap this document exists to prevent: the proxy path is the
weaker of the two for payload inspection, and an operator who routes a risky
upstream through the proxy expecting hook-grade scanning will be
disappointed.

This page is the capability matrix. It is derived directly from the code:
the hook path is `src/quill/adapters/claude_code.py` (`decide` /
`classify_event` / `run_hook`), the proxy path is `src/quill/proxy.py`
(`QuillProxy.call_tool` / `QuillProxy.all_tools`) plus
`src/quill/notifications.py`.

## Why there are two paths at all

Claude Code's built-in tools (Bash, Edit, Write, NotebookEdit, Read, ...)
never travel over MCP, so the MCP proxy cannot see them. The PreToolUse
**hook** is the only place Quill can gate those built-ins. Conversely, an
upstream MCP server's tools never trigger a PreToolUse hook for their MCP
identity (tool description, JSON schema, rug-pulls), so only the **proxy**
can adjudicate the MCP supply chain. Each path covers what the other
structurally cannot, and the protections do not overlap fully.

## Capability matrix

Legend: YES = runs on this path; no = does not run on this path.

| Protection                                   | HOOK (built-ins) | PROXY (MCP tools) | Where in code |
| -------------------------------------------- | ---------------- | ----------------- | ------------- |
| Risk classify (LOW/MED/HIGH/CRITICAL)        | YES              | YES               | hook `classify_event`; proxy `classify` + `config.policy` |
| Scope / badge check (deny out-of-scope)      | no (1)           | YES               | proxy `intent.in_scope_reason` |
| Secret scan on writes (escalate to CRITICAL) | YES              | no                | hook `secrets.scan_args` |
| Gate self-tamper block (config/hook files)   | YES              | no                | hook `_is_gate_config_path` |
| Taint / lethal-trifecta enforcement          | YES              | no                | hook `taint.would_close_trifecta` |
| One-shot approval tokens (`quill approve`)   | YES              | no (2)            | hook `approvals.ApprovalStore` |
| Session-scoped approval memory               | YES              | no                | hook `session_approvals` |
| Permission decay / promoted overrides        | YES              | no                | hook `decay` / `learning` |
| Bypass-mode + overnight-mode downshifts      | YES              | no                | hook `_detect_bypass_mode` / `overnight` |
| Out-of-band notify (macOS/email/Slack/webhook)| YES             | no                | hook `_maybe_notify` |
| Interactive human ACK / type-confirm         | no (3)           | YES               | proxy `Prompter.confirm` |
| Tool-description poisoning scan              | no               | YES               | proxy `all_tools` -> `PinStore.verify` -> `tool_scan.scan` |
| Tool-pinning rug-pull / schema-drift detect  | no               | YES               | proxy `all_tools` -> `PinStore.verify` |
| Upstream `sampling/createMessage` refusal    | no               | YES               | proxy `make_sampling_callback` (default-deny) |
| Upstream notification audit + forwarding     | no               | YES               | proxy `make_message_handler` |
| HMAC-chained audit of every decision         | YES              | YES               | both via `AuditLog.emit` |
| Self-test fail-closed on startup             | YES              | no (4)            | hook `self_test` |
| Pause recovery hatch (`quill off`)           | YES              | no                | hook `_handle_paused` |

Notes:

1. The hook has no SessionIntent scope allow-list; it classifies each
   built-in by risk and content. Scope enforcement is a proxy-only concept,
   because the proxy is the one holding the session mandate.
2. The proxy's HIGH/CRITICAL path prompts a human synchronously in the
   terminal; it does not issue or consume `quill approve` tokens. The whole
   token + out-of-band-notify + session-memory machinery is hook-only.
3. The hook never blocks synchronously for a human: it returns
   allow/ask/deny to Claude Code, and "ask" delegates the prompt to Claude
   Code's own UI. The proxy is the path that can hold the call open on a
   `Prompter.confirm` until the human answers.
4. The proxy has no classifier self-test gate; it relies on the same policy
   table and `classify` import. If you need the fail-closed-on-broken-
   classifier guarantee, that lives on the hook path.

## The asymmetry, stated plainly

- **Payload inspection is HOOK-stronger.** Secret scanning, gate
  self-tamper, lethal-trifecta enforcement, and the full approval-token /
  notify / session-memory loop run ONLY on the hook. A credential written
  into source, an edit aimed at `~/.claude/settings.json`, or a
  trifecta-closing exfil step is caught by the hook and is NOT caught by the
  proxy. Do not route a tool through the proxy expecting secret-scan or
  trifecta protection.

- **MCP supply chain is PROXY-stronger.** Tool-description poisoning
  (invisible Unicode, injection imperatives, encoded blobs), rug-pulls
  (digest drift after first trust), schema drift, and upstream sampling
  abuse are caught ONLY by the proxy, because the hook never sees an MCP
  tool's description or schema. Do not assume the hook protects you from a
  poisoned MCP server.

- **Both paths** classify by risk and write an HMAC-chained audit entry for
  every decision, so the *evidence trail* is symmetric even where the
  *enforcement* is not.

## Audit event vocabulary by path

Event-type constants live in `src/quill/events.py`. The two paths emit
overlapping but distinct vocabularies; if you build dashboards or alerts on
the audit log, expect these.

HOOK path emits: `session.open`, `agent.handoff.out`, `agent.handoff.in`,
`agent.cascade.affected`, `session.taint.update`, `tool.attempted`,
`verdict.allowed` (incl. `verdict.allowed.overnight`), `verdict.ask`,
`verdict.blocked`, `gate.paused`, `gate.resumed`. The hook is the only path
that emits the session-lineage and trifecta-taint families.

PROXY path emits: `tool.attempted`, `verdict.scope_violation`,
`verdict.allowed`, `verdict.blocked`, `tool.completed`, `tool.errored`,
`tool.pin_refused`, `gate.scope_empty` (startup finding, see #39), plus the
upstream-side `upstream.tools.list_changed`, `upstream.resource.updated`,
`upstream.log`, `upstream.progress`, `upstream.request`, `upstream.error`,
and `upstream.sampling.refused` / `upstream.sampling.allowed`. The
`tool.pin_refused`, `upstream.*`, and `*.sampling.*` events are proxy-only;
the hook never produces them.

Note the naming split on scope: the proxy writes `verdict.scope_violation`
for an out-of-scope call (and `gate.scope_empty` once at startup when the
session scope is empty, since an empty scope denies every call
fail-closed). There is no hook equivalent, because the hook has no scope
model.

## Practical guidance

- Gate Claude Code's built-ins with the **hook** (install via
  `quill claude-hook` in `~/.claude/settings.json`). This is where secret
  scan, self-tamper, and trifecta live.
- Put untrusted or third-party **MCP servers** behind the **proxy**
  (`quill serve`). This is where tool-poisoning and rug-pull detection live.
- Run BOTH for full coverage. Neither subsumes the other, and the proxy is
  explicitly the weaker path for payload inspection. See
  `docs/SECURITY-MODEL.md` for the full threat model and the limits that
  apply to both paths (application-layer bypass, write-then-run, egress).
