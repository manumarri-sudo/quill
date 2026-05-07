# Security policy

`quill` is a security-critical proxy. A buggy proxy is worse than no proxy: it becomes a credential exfiltration vector for every MCP server it wraps. This document describes what the project protects against, what it does not, and how to report a vulnerability.

## Reporting a vulnerability

Please use [GitHub Security Advisories](https://github.com/manumarri/quill/security/advisories/new). For the most sensitive reports, open a draft advisory before any public discussion.

We aim to respond within 48 hours and to ship a fix within 7 days for high-severity issues.

## Threat model

### What an attacker would try

In rough priority order:

1. **Bypass the gate.** Make a high-risk tool call execute without the human prompt firing. Either by injecting a tool name that escapes the classifier, or by getting the proxy to forward without going through `policy.classify`.
2. **Forge or hide audit log entries.** Make a destructive action look approved when it wasn't, or remove it from the log entirely.
3. **Exfiltrate secrets.** Steal the HMAC signing key (`~/.quill/key`), upstream API tokens passed via `env_pass`, or the audit log itself if it contains arg values that would normally be redacted.
4. **Remote code execution on the host.** Through malformed JSON-RPC frames the proxy doesn't validate, through prompt-injection that gets the proxy to spawn a subprocess with attacker-controlled arguments, or through a vulnerable upstream MCP server the proxy fails to isolate.
5. **Privilege escalation.** Convince Quill to spawn an upstream subprocess with a working directory or env it shouldn't have.

### Most relevant CWEs

- CWE-78 OS command injection (subprocess with attacker-influenced args)
- CWE-22 path traversal (config paths, log paths, working directories)
- CWE-502 deserialization of untrusted data (JSON-RPC frames, config files, tool arguments)
- CWE-367 TOCTOU on file existence/permission checks
- CWE-200 information exposure (log leaking secrets)
- CWE-345 insufficient verification of audit log authenticity
- CWE-732 incorrect file permissions on log/key
- CWE-918 SSRF (if a future feature fetches model-influenced URLs)

## What we protect against

- **Tampering with the audit log.** Every entry includes an HMAC of the previous entry's MAC. A modification or insertion breaks the chain at the next `quill audit verify`.
- **Out-of-scope tool calls.** Deterministic scope check before the human is even prompted. No AI in the gate; no jailbreakable judgment.
- **Yes-spamming critical actions.** Critical-risk actions require typing the action name back. A pure muscle-memory `y` is rejected.
- **Yes-fatigue.** Three rapid approvals in a row triggers a forced pause before the next prompt.
- **Subprocess privilege leakage.** Upstream MCP servers spawn with a scrubbed environment. Only env vars listed in `env_pass` are forwarded; Quill's signing key is never forwarded.
- **World-readable secrets.** The audit log and HMAC key are created `0o600`. The proxy refuses to write either to a path that already exists with broader permissions.

## What we do NOT protect against

- **Compromise of a user with code execution.** If an attacker has shell as the user running Quill, they can read the HMAC key and forge entries. Userspace Python cannot fully defend against this. For hardening, run Quill under `bubblewrap`/`firejail` (Linux), `sandbox-exec` (macOS), or AppContainer (Windows). A starter systemd unit with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp=true` is shipped under [`contrib/quill.service`](contrib/) (post-1.0).
- **Compromised upstream MCP servers.** Quill governs *what* the agent calls. If your upstream server has an RCE itself, Quill's role ends at "logged that the call happened." Pin upstream server versions and prefer those distributed via `pipx`/signed npm packages over `npx -y @latest/foo`.
- **Model-side prompt-injection bypass.** If the model is tricked into not calling a tool at all (e.g. simulates output instead), Quill has nothing to gate. Pair with a model-level guardrail.
- **Network attacks against the JSON-RPC transport.** v1 supports stdio (local-only) primarily. Network transports inherit OS-level network security; we make no claims beyond TLS verification on streamable-HTTP upstreams.
- **Streaming-tool-call interruption.** If the LLM is mid-emission of tool args and the policy needs to interrupt, v1 is best-effort. v0.2 hardens this.
- **Memory hygiene of secrets in Python.** We use `pydantic.SecretStr` to keep secrets out of logs and reprs, but cpython's interaction with `mlock` is awkward and we make no claims that secrets are unrecoverable from process memory. Operators who need this level of assurance should run Quill under a dedicated user account with restricted swap.

## Hardening recommendations

- Generate a fresh HMAC key per project: `QUILL_KEY=/path/per/project/key quill serve`
- Rotate the HMAC key periodically. Document old chain head, generate new key, write a `chain.rotate` event marking the boundary.
- Run with `umask 0077` so any temporary files inherit safe permissions.
- Anchor the chain head externally (an hourly write to a backup location) so on-disk tampering is detectable even if the local copy is rewritten.
- Pin upstream MCP server versions in the `command` array. Do not use `npx -y` resolving to `@latest`.

## Supply chain

- Releases are signed via PyPI [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) with PEP 740 attestations.
- The lockfile (`uv.lock`) is committed and tested in CI.
- Dependabot and `pip-audit` run on every PR.
- An OSSF Scorecard report is published; we aim for a score of 8+.
- An SBOM (CycloneDX) is attached to every GitHub release.

## Audit history

| Date | Auditor | Scope | Report |
|---|---|---|---|
| _none yet_ | _scheduled post-1.0_ | | |

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

After 1.0, we will support the latest minor and the previous one with security fixes.
