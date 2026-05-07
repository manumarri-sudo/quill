"""Configuration loading.

Quill config lives at ~/.quill/config.toml by default. Format:

  [session]
  intent = "Help customer c_8e4f, refund cap $100"
  scope = [
    "payments:refund:customer:c_8e4f",
    "customer:c_8e4f:read",
  ]
  budget_usd = 50

  [audit]
  path = "~/.quill/audit.log.jsonl"

  [[upstream]]
  name = "filesystem"
  command = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe"]
  env = { NODE_ENV = "production" }

  [[upstream]]
  name = "github"
  command = ["docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server"]
  env_pass = ["GITHUB_TOKEN"]

  [policy]
  # Per-tool risk overrides. Default classification (see policy.classify) is
  # used when not specified here.
  "fs.delete" = "critical"
  "fs.read_file" = "low"
  "github.list_issues" = "low"

  [telemetry]
  enabled = false   # opt-in only

The config is loaded ONCE at process start, validated through Pydantic, and
then frozen. Hot-path policy code never re-parses TOML.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from quill.errors import ConfigError
from quill.policy import Risk, Scope

# Stdlib tomllib (3.11+); fall back to tomli on older interpreters.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


def default_config_path() -> Path:
    return Path(os.environ.get("QUILL_CONFIG", "~/.quill/config.toml")).expanduser()


def default_audit_path() -> Path:
    return Path(os.environ.get("QUILL_LOG", "~/.quill/audit.log.jsonl")).expanduser()


class UpstreamConfig(BaseModel):
    """One upstream MCP server that Quill proxies."""

    model_config = ConfigDict(strict=True, extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    command: tuple[str, ...] = Field(min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    env_pass: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Names of env vars to forward from Quill's environ "
        "(e.g. GITHUB_TOKEN). NEVER includes Quill's own secrets.",
    )

    @field_validator("env_pass")
    @classmethod
    def _check_env_pass(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        # Refuse to forward anything that smells like Quill's signing key.
        forbidden = {"QUILL_HMAC_KEY", "QUILL_SIGNING_KEY"}
        bad = [e for e in v if e in forbidden]
        if bad:
            msg = f"env_pass cannot include quill secrets: {bad}"
            raise ValueError(msg)
        return v


class SessionConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    intent: str = Field(min_length=1, max_length=2000)
    scope: tuple[str, ...] = Field(default_factory=tuple)
    budget_usd: float | None = Field(default=None, ge=0)

    def parsed_scope(self) -> tuple[Scope, ...]:
        return tuple(Scope.parse(s) for s in self.scope)


class AuditConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    path: str = Field(default="~/.quill/audit.log.jsonl")

    def resolved_path(self) -> Path:
        return Path(self.path).expanduser()


class TelemetryConfig(BaseModel):
    """Telemetry is OPT-IN. Default false. Even when enabled, only aggregate
    counts and timings ship; never tool args, never intent contents, never
    file paths."""

    model_config = ConfigDict(strict=True, extra="forbid")
    enabled: bool = False
    endpoint: str | None = None


class QuillConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    session: SessionConfig
    audit: AuditConfig = Field(default_factory=AuditConfig)
    upstream: tuple[UpstreamConfig, ...] = Field(default_factory=tuple)
    policy: dict[str, Risk] = Field(default_factory=dict)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)


def load_config(path: Path | None = None) -> QuillConfig:
    """Read TOML, validate, return a frozen-shape QuillConfig.

    Raises ConfigError on read or validation failure (never lets a stdlib
    exception leak — keeps the public surface clean for callers).
    """
    p = path or default_config_path()
    if not p.exists():
        msg = f"no config at {p}. write one (see quill init) or set QUILL_CONFIG."
        raise ConfigError(msg)
    try:
        with p.open("rb") as f:
            data = tomllib.load(f)
        return QuillConfig.model_validate(data)
    except (OSError, tomllib.TOMLDecodeError) as e:
        msg = f"could not read config at {p}: {e}"
        raise ConfigError(msg) from e
    except ValueError as e:
        msg = f"invalid config at {p}: {e}"
        raise ConfigError(msg) from e


def render_starter_config() -> str:
    """Return a starter TOML for `quill init`."""
    return """\
# quill config — see https://github.com/manumarri/quill

[session]
# What is the human telling the agent to do? Captured at session start.
intent = "describe what the agent should be doing"
# Granted scopes. Format: "namespace:action[:resource]"
scope = []
# Optional dollar ceiling that propagates across all sub-agents.
# budget_usd = 20

[audit]
# Where the signed JSONL audit log lives. Mode 0o600.
path = "~/.quill/audit.log.jsonl"

# One [[upstream]] block per MCP server you want quill to proxy.
# Tool calls advertised by these upstreams are protected by the gate.
# [[upstream]]
# name = "filesystem"
# command = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe"]

# Per-tool risk overrides. Defaults handle the obvious dangerous actions
# (rm, delete, drop table, force-push, deploy:production, stripe.*) as
# critical, requiring type-to-confirm.
[policy]
# "fs.delete" = "critical"
# "github.list_issues" = "low"

[telemetry]
# Anonymous aggregate counts only. Never tool args, intent contents, or
# file paths. Off by default; turn on if you want to help shape v0.2.
enabled = false
"""
