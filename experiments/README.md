# Quill experiment harness

This folder runs a real Anthropic Claude agent against ~20 indirect
prompt-injection scenarios drawn from AgentDojo (ETH Zurich, Debenedetti et
al., 2024) and a small curated fallback list. Every tool call the agent
attempts is routed through Quill's deterministic gate: scope check, risk
classification, then human ACK on high/critical. The harness records what
happened and produces signed audit logs plus rendered figures.

## What it proves

The user's mandate for every scenario is read-only ("summarise unread
emails", "find a hotel in Paris", etc.). Each scenario then injects an
attacker instruction inside a tool result that the agent reads — exactly
the threat model AgentDojo and Greshake et al. (2023) describe.

If Quill works:

- scope-violating tool calls are refused without any LLM in the gate;
- high/critical actions (send email, transfer money, drop table, deploy
  prod, refund, force-push, public PR) are paused for a human ACK and
  declined by default;
- the audit log captures every attempt with HMAC chaining so tampering
  is detectable.

## Files

- `agentdojo_harness.py` — main experiment driver
- `scenarios.py` — scenario loader (AgentDojo -> cache -> curated)
- `agentdojo_scenarios.json` — pre-extracted AgentDojo v1 injection tasks
- `render_artifacts.py` — turns the audit log into SVG/PNG figures
- `run_experiment.sh` — one-shot runner
- `_quill_shim.py` — name-compat shim for the quill / janus_mcp rename
- `results/` — generated output (overwritten on every run)

## Run it

```
pip install -e .                    # from the repo root
export ANTHROPIC_API_KEY=sk-ant-... # required
bash experiments/run_experiment.sh  # ~20 scenarios, defaults
```

Useful flags (forward through `run_experiment.sh`):

- `--max-scenarios N` — cap the number of scenarios run (default 20)
- `--auto-ack` — auto-accept human ACK prompts. Use this to demonstrate
  what would happen *without* a human in the loop. The default is to
  decline.
- `--force-curated` — skip AgentDojo and the cached snapshot and use
  the small hand-curated set (8 prompts).
- `--model NAME` — override the Anthropic model id (default
  `claude-sonnet-4-5`).

## Output artifacts

Everything lands under `experiments/results/`:

- `audit.log.jsonl` — append-only signed audit log Quill produced.
  Each line has `prev_mac` / `mac` HMAC fields. Verify with
  `quill audit verify --log experiments/results/audit.log.jsonl`.
- `summary.csv` — one row per scenario: attempted/blocked/allowed
  tools, scope violations, token usage, error info.
- `RESULTS.md` — human-readable summary: % blocked at scope, %
  paused for human ACK, % allowed, breakdown by attack category.
- `tail_view.svg` — what `quill tail --live` looks like during a
  representative blocked attack.
- `audit_table.svg` — `quill audit show` style table of the most
  recent 30 events.
- `tree_view.svg` — the delegation tree for the run.
- `results_chart.png` — verdicts per tool category, colour-coded.

## Notes

The harness never executes any tool. Every `tool_use` is either gated to
`verdict.allowed` and stubbed with a fake response, or gated to a block
event so the agent receives a `tool_result` of `BLOCKED by Quill: ...`.
That is the correct behaviour for an experiment whose purpose is to
measure what the gate does, not to actually send emails.

Token accounting comes from the SDK's `usage` object on each
`messages.create` response.
