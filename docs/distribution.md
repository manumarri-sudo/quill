# Distribution & promotion

Internal-facing playbook for getting `quill` in front of the people whose AI
agents are about to do something they can't undo. Edit / iterate; the moment a
section becomes stale, delete it.

`LAUNCH.md` covers the messaging (taglines, post drafts, demo ideas). This file
covers the *channels* - registries, package managers, browser/IDE surfaces, and
the cadence of how each one gets pushed.

---

## Channels by surface

### 1. Python package index (PyPI) - the primary surface

The hero install command is `pip install quillx && quill start`. PyPI is therefore
the canonical distribution. The dist name on PyPI is `quillx` because the `quill`
name was taken by an unrelated package; the import path, CLI binary, and config
directory all remain `quill` (rename is dist-only). Build + upload steps:

```bash
python -m build                              # produces dist/*.whl + dist/*.tar.gz
python -m twine check dist/*
python -m twine upload dist/*                # uses ~/.pypirc or PYPI_API_TOKEN
```

The CI workflow (`.github/workflows/ci.yml`) builds artifacts on every push. To
publish on tag, add a `release` job triggered by `release.published` that runs
`twine upload`. Don't auto-publish from main - every release should be a
deliberate `git tag vX.Y.Z` + `gh release create`.

### 2. uv / uvx - the fast paste-able install

`uv` is what the landing page shows by default because the install is two
seconds, no virtualenv ceremony. The command is `uvx quillx` (run directly) or
`uv tool install quillx` (persistent). uv resolves through PyPI, so PyPI publish
is enough - there's no separate uv index.

### 3. pipx - the "I want it global" install

`pipx install quillx && quill`. Same: PyPI-backed, no extra publish step.

### 4. Homebrew - `brew install quill`

Two paths:

- **Tap (fast).** Create `manumarri-sudo/homebrew-quill`, add a `Formula/quill.rb`
  pointing at the GitHub release tarball + Python deps. Users get
  `brew install manumarri-sudo/quill/quill`. Set up once; CI bumps the formula
  via a `homebrew-releaser` GitHub Action on each tag.
- **Core (gated).** Submit to `Homebrew/homebrew-core` once we hit the
  notability bar (≥75 GitHub stars, stable releases, active maintenance).
  Won't qualify for v0.1.

Defer to v0.2.

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

- **mcp.so** - the de facto community directory. Submit a PR to
  `https://github.com/lobehub/lobe-chat/tree/main/Docs` mirror or add an entry
  via their submission form. Required: name, install command, JSON schema of
  exposed tools.
- **Smithery** (`smithery.ai`) - has a CLI: `npx @smithery/cli install quill`.
  Adds Quill to a user's `mcp.json` automatically. Requires us to maintain a
  manifest in their registry repo.
- **Anthropic's MCP server gallery** - list of community-maintained servers
  Anthropic links from their docs. Submit via PR to
  `modelcontextprotocol/servers` once Quill exposes a stable schema-passthrough.
- **Cline marketplace** (VS Code extension) - Cline shows MCP servers in its
  picker. Submit via PR to their repo.
- **Cursor MCP directory** - Cursor's `Settings > Features > MCP` lists curated
  servers. Reach out to Anysphere via their public Discord.

Order of operations: ship 0.2 (schema-passthrough), then submit to all five in
the same week so they cross-link.

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

### Launch week (one-time)

- **Day 0**: Show HN ("quill - a tiny Python proxy that gates risky AI-agent
  tool calls"). Post the LinkedIn version too. Don't post both within an hour
  - let HN breathe first.
- **Day 1**: tweet thread with the 30-second `rm -rf` GIF.
- **Day 2**: submit to mcp.so + Smithery + Cline marketplace + Cursor in one
  push.
- **Day 3**: post in r/LocalLLaMA, r/ChatGPTCoding, r/cursor with the same
  framing as Show HN but tailored to each sub.
- **Day 4-7**: respond to every issue, every comment, every DM. The early
  signal is who's actually using it.

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

## Status as of 2026-05-07

- PyPI: not yet published. Publish v0.1.0 once the audit-chain repair docs land
  in CHANGELOG.md.
- GitHub: repo public at `github.com/manumarri-sudo/quill`. CI workflow staged
  at `.github/workflows/ci.yml`; user needs `gh auth refresh -s workflow` to
  push it.
- Landing page: `web/index.html` ready. Not yet deployed to Vercel.
- Telemetry pipeline: Supabase schema written (`infra/supabase/sql/0001_init.sql`)
  + ingest/analyze Edge Functions (`infra/supabase/functions/`). Not yet
  deployed (`supabase functions deploy` pending).
- npm wrapper: deferred until v0.2 (schema-passthrough).
- Homebrew tap: deferred until v0.2.
- MCP registries: deferred until v0.2.
- VS Code / Cursor / Cline / Windsurf adapters: defined as good-first-issues,
  not yet built.
