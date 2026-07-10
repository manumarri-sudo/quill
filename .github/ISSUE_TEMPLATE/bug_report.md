---
name: Bug report
about: Something Notari should do but doesn't, or shouldn't do but does
title: "bug: "
labels: ["bug"]
---

<!--
Before filing: please confirm the bug reproduces on the latest released
version. `notari version` to check.
-->

## What happened

A clear description of the bug. Include the exact command or tool call
that triggered it.

## What you expected

A description of what Notari should have done instead.

## Steps to reproduce

1.
2.
3.

## Environment

- OS: <!-- macOS / Linux / Windows + version -->
- Notari version: <!-- output of `notari version` -->
- Python version: <!-- output of `python --version` -->
- Coding agent: <!-- Claude Code / Cursor / Cline / etc. and version -->

## Relevant audit log entries

If the bug involves a gate decision, paste the relevant `~/.notari/audit.log.jsonl`
lines. Strip any sensitive args before pasting; Notari's redaction normally
keeps these out but verify.

```json

```

## `notari doctor` output

```

```

## Anything else
