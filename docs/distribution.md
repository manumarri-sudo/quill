# Distribution & promotion

Internal-facing playbook for getting `quill` in front of the people whose AI
agents are about to do something they can't undo. Edit / iterate; the moment a
section becomes stale, delete it.

`LAUNCH.md` covers the messaging (taglines, post drafts, demo ideas). This file
covers the *channels* - registries, package managers, browser/IDE surfaces, and
the cadence of how each one gets pushed.

---

## Channels by surface

### 1. uv / uvx - the hero install

`uvx quillx start` is the install command on the landing page and the README, because it's two seconds end to end with no virtualenv ceremony. `uv tool install quillx` is the persistent variant. uv resolves through PyPI directly, so a PyPI publish is enough and there's no separate uv index to maintain. Per the 2026 launch playbook research, uvx has displaced pipx as the recommended invocation pattern because it's roughly 10-100x faster and bundles Python version management.

### 2. pipx - for users who want it global without uv

`pipx install quillx && quill start`. Same backing as uvx (PyPI), no extra publish step. Pipx is still in wide use, so the README mentions it as the second-listed install.

### 3. PyPI - the canonical distribution underneath both

The dist name on PyPI is `quillx` because the `quill` name on PyPI is held by an unrelated package; the import path, CLI binary, config directory, and brand all stay `quill`. Build + upload mechanics:

```bash
uv build                                     # produces dist/*.whl + dist/*.tar.gz
UV_PUBLISH_TOKEN=... uv publish dist/*       # first upload via bootstrap token
```

After the first upload, register PyPI Trusted Publishing for `quillx` so future releases ship via OIDC and no API token lives anywhere. The `release.yml` workflow handles this end to end once TP is in place. PEP 740 attestations come for free from `pypa/gh-action-pypi-publish@v1.11.0+` with Trusted Publishing and are now expected default behavior for security-adjacent tools.

### 4. Homebrew - `brew install manumarri-sudo/quill/quill`

Two paths:

- **Self-owned tap (fast, recommended for v0.2).** Create `manumarri-sudo/homebrew-quill`, add a `Formula/quill.rb` pointing at the GitHub release tarball plus Python deps. Users get `brew install manumarri-sudo/quill/quill`. CI bumps the formula via a `homebrew-releaser` GitHub Action on each tag.
- **Homebrew core (gated).** Submit to `Homebrew/homebrew-core` once the notability bar is met (≥75 GitHub stars, stable releases, active maintenance). Not worth chasing pre-traction.

### 5. npm wrapper - `npx -y @quill/mcp`

The MCP ecosystem is npm-first. Even though the implementation is Python,
shipping a tiny npm wrapper that shells out to `pipx run quill` (or downloads a
PyOxidizer single-binary) lets MCP-config users say:

```json
{
  "mcpServers": {
    "quill": {
      "command": "npx",
      "args": ["-y", "@quill/mcp"]
    }
  }
}
```

Defer until the proxy schema-passthrough lands (v0.2). Until then, MCP wrapper
distribution would advertise a half-baked surface.

### 6. MCP server registries

Four primary registries plus one upstream canonical:

- **Official MCP Registry** at `registry.modelcontextprotocol.io` is the canonical upstream that the other registries ingest from. Submission requires a `server.json` (already at the repo root, namespace `io.github.manumarri-sudo/quill`) and GitHub-auth ownership verification. **Submit this first; the downstream registries pick up from it automatically.**
- **mcp.so** is the broadest consumer directory (20k+ servers). Self-service submission form.
- **Smithery** at `smithery.ai` accepts `smithery mcp publish` from the CLI and serves the agent-framework user base.
- **Cline marketplace** requires an issue against `github.com/cline/mcp-marketplace` with the repo URL, a 400×400 PNG logo, and pre-verification that Cline can install Quill from the README alone.
- **punkpeye/awesome-mcp-servers** is a PR against the README, alphabetical placement enforced. Cheap and indexes well in search.
- **Cursor MCP directory** submission process is undocumented in public sources; outreach via the Cursor Discord or a PR against `cursor.directory` is the current path.

Order of operations: submit to the official MCP Registry T-1 (the day before Show HN), then mcp.so / Smithery / awesome-mcp-servers PR same-day as the Show HN so they show up in HN comments as proof of distribution. Cline marketplace T+1 (needs the 400×400 logo ready).

### 7. VS Code / Cursor / Cline / Windsurf - extensions

The hook approach (PreToolCall) is what Claude Code does. Cursor, Cline, and
Windsurf each have similar hooks. Build per-IDE adapters (already in
LAUNCH.md's good-first-issues), publish each as an extension only if the IDE's
hook surface alone isn't enough - most aren't. The MCP-proxy path is more
portable than per-IDE extensions; prefer it.

### 8. Chrome extension - **skip**

Earlier discussion question: do MCP servers usually ship a Chrome extension to
help with promotion? Verdict: **no - and Quill specifically should not.**

Reasoning:
- Quill's value is in the *agent's tool path* (PreToolUse hook + MCP proxy). The
  browser is downstream of where the agent is running.
- A Chrome extension would have to either (a) intercept agent calls in
  browser-based agents (e.g. claude.ai/web) - but those don't expose hooks, so
  the extension can't gate anything; or (b) be a glorified docs viewer, which is
  what `quill watch` already is in-terminal.
- Surface-area cost is high (Chrome Web Store review, two builds, two update
  cadences) for ~zero gating value.

If a future browser-native agent surface ships a hook contract, revisit. Until
then, it's a distraction.

---

## DevRel cadence

### Launch arc (T-3 → T+30)

See the **Launch arc** section in `LAUNCH.md` for the full prep / launch / follow-through plan. In short: T-3 to T-1 is prep (demo GIF in the README, smoke-test the install on a clean machine, badges, SECURITY.md / CITATION.cff, official MCP Registry submission, pre-write the Show HN body, pre-draft canned responses), T-0 is the Show HN with same-day registry sweep, T+1 amplifies via LinkedIn / Substack / Cline marketplace, T+7 publishes a retrospective with traffic and feedback, T+30 ships v0.3 with the top feedback-driven change.

### Ongoing (weekly)

- One Tuesday tweet showing a real audit-log gate decision (anonymized).
- Bi-weekly newsletter to `manumarri-sudo/quill` watchers via GitHub Discussions
  pinned threads - release notes, what got blocked in the wild, what's next.

### Conferences / podcast hits

Targets, ranked:
1. **Latent Space** podcast - covers the agent-infra space, has a Cursor /
   Claude Code audience.
2. **AI Engineer Summit** - a workshop or lightning talk on "tamper-evident
   audit logs for AI agents" once v0.2 ships.
3. **PyCon US** - a 30-min talk on the HMAC chain + cross-process flock
   work; technical, narrow, but exactly the right room.

---

## Discoverability levers (cheap, durable)

- **GitHub topics** (set on the repo): `mcp`, `model-context-protocol`,
  `ai-agents`, `claude-code`, `cursor`, `agent-governance`, `ai-safety`,
  `human-in-the-loop`, `audit-log`, `python`. Already in LAUNCH.md.
- **README.md `## Why this exists`** - anchor the Replit/Lemkin incident,
  Tom's Hardware and The Register coverage. Citations matter for credibility.
- **`quill audit show` example screenshots** in the README - concrete output
  beats prose every time.
- **Demo GIFs in `web/`** - the 30-second `rm -rf` save is the highest-leverage
  asset. Record it once; embed everywhere.
- **`open-source-mcp-servers` awesome-lists** - submit PRs to a dozen of these
  in the same afternoon; cheap and they index well in Google.

---

## Anti-patterns

Things we explicitly do NOT do:

- **No paid ads.** Quill is a developer tool; the audience is on Twitter, HN,
  and GitHub. Money buys impressions, not adoption.
- **No "free trial" gating.** MIT, no signup, no email-wall. The instant a
  user hits a wall, the conversion drops to zero.
- **No telemetry-on-by-default.** Hard rule: opt-in only, even if it slows
  product feedback. Trust is the entire product premise; we can't bend it
  for our convenience.
- **No "AI safety" theater language.** The README and landing page talk about
  concrete commands (`rm -rf`, `git push --force`, `DROP TABLE`) - not about
  alignment, existential risk, or governance frameworks at the top. Real
  developers don't trust pitch decks; they trust diffs.
- **No "request a demo" CTA.** The CTA is one paste-able command.

---

## Status as of 2026-05-27

- **PyPI:** live as `quillx` at https://pypi.org/project/quillx/. v0.2.0a4 published with both wheel and sdist. Trusted Publishing not yet registered; bootstrap-token uploads work in the meantime.
- **GitHub:** repo public at `github.com/manumarri-sudo/quill`. CI workflow active at `.github/workflows/ci.yml`. Release workflow at `.github/workflows/release.yml` targets TP and is dormant until TP is registered.
- **v0.2.0a4 GitHub release:** draft only; mark public via `gh release edit v0.2.0a4 --draft=false` once TP is in place.
- **Landing page:** `web/index.html` ready. Not yet deployed to Vercel.
- **Telemetry pipeline:** Supabase schema and Edge Functions still pending deploy. Not blocking launch (Quill itself is local-only).
- **npm wrapper:** still deferred — the proxy schema-passthrough lands in 0.2 but the npm packaging is undogfooded.
- **Homebrew tap:** not yet created. T-3 prep item if going for parity with the launch.
- **MCP registries:** server.json drafted at the repo root for official MCP Registry submission. mcp.so / Smithery / Cline marketplace / awesome-mcp-servers PRs all queued for the launch week.
- **VS Code / Cursor / Cline / Windsurf adapters:** Cursor pre-tool-call hook already supported (A2A captures handoffs for Cursor 1.7+). The other IDEs remain good-first-issues.
