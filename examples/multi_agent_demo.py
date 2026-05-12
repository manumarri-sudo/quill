"""Multi-agent demo: a parent agent that spawns specialized sub-agents.

This is what a vibe coder watches in a side terminal:

    Terminal A:   python examples/multi_agent_demo.py
    Terminal B:   quill tree --live --log /tmp/quill-demo.log.jsonl

The demo simulates a coder + planner + reviewer trio working a task.
Every action they "attempt" goes through the gate, gets logged, and
shows up live in the tree view.

Run me:
    python examples/multi_agent_demo.py
"""
from __future__ import annotations

import os
import secrets
import sys
import time
from pathlib import Path

# Allow running from the repo without installing the package.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from quill.audit import AuditLog
from quill.policy import Scope
from quill.session import SessionTree, SubAgentExceedsParentScope


LOG_PATH = Path(os.environ.get("QUILL_DEMO_LOG", "/tmp/quill-demo.log.jsonl"))
HMAC_KEY = b"demo" * 8


def main() -> None:
    if LOG_PATH.exists():
        LOG_PATH.unlink()
    print(f"  log → {LOG_PATH}")
    print("  in another terminal, run:")
    print(f"    quill tree --live --log {LOG_PATH}")
    print("  ... pausing 4 seconds so you can open the watcher window")
    time.sleep(4)

    with AuditLog(path=LOG_PATH, hmac_key=HMAC_KEY) as audit:
        with SessionTree.create(
            intent="ship the v1 dashboard, staging only, $20 budget",
            scope=(
                Scope.parse("repo:read"),
                Scope.parse("repo:write:src/dashboard"),
                Scope.parse("deploy:staging"),
            ),
            budget_usd=20.0,
            audit=audit,
        ) as tree:
            time.sleep(1)

            # planner sub-agent: read-only
            with tree.sub_agent(
                name="planner",
                intent="break the dashboard into PRs",
                scope=(Scope.parse("repo:read"),),
            ) as planner:
                _attempt(audit, tree, planner.id, "repo.list_files", risk="low", allowed=True)
                time.sleep(0.6)
                _attempt(audit, tree, planner.id, "repo.read_file", risk="low", allowed=True)
                time.sleep(0.5)
                # planner tries to write - should fail attenuation if declared,
                # but here we just simulate a scope violation event.
                _attempt(audit, tree, planner.id, "repo.write_file",
                         risk="medium", allowed=False, reason="scope_violation")
                time.sleep(0.5)
                _attempt(audit, tree, planner.id, "repo.read_file", risk="low", allowed=True)

            time.sleep(0.6)

            # coder sub-agent: write inside src/dashboard only
            with tree.sub_agent(
                name="coder",
                intent="implement /src/dashboard",
                scope=(Scope.parse("repo:write:src/dashboard"),),
            ) as coder:
                for i in range(4):
                    _attempt(audit, tree, coder.id, "repo.write_file",
                             risk="medium", allowed=True)
                    time.sleep(0.4)

                # coder asks for a high-risk PR
                _attempt(audit, tree, coder.id, "github.create_pull_request",
                         risk="high", allowed=False, reason="human_declined",
                         pause_before_decline=2.0)
                time.sleep(0.5)

                # critical: trying to deploy to production (out of scope)
                _attempt(audit, tree, coder.id, "deploy.production",
                         risk="critical", allowed=False, reason="scope_violation")
                time.sleep(0.5)

            time.sleep(0.6)

            # reviewer: nested sub-agent under coder is also possible
            with tree.sub_agent(
                name="reviewer",
                intent="review the staging deploy",
                scope=(Scope.parse("deploy:staging"),),
            ) as reviewer:
                _attempt(audit, tree, reviewer.id, "deploy.staging",
                         risk="high", allowed=True, pause_before_allow=1.5)
                time.sleep(0.5)

            time.sleep(1.0)

    print()
    print("  done.")
    print(f"  inspect the log:   quill audit show --log {LOG_PATH}")
    print(f"  verify the chain:  quill audit verify --log {LOG_PATH}")
    print(f"  view the tree:     quill tree --snapshot --log {LOG_PATH}")


def _attempt(
    audit: AuditLog,
    tree: SessionTree,
    agent_id: str,
    tool_name: str,
    *,
    risk: str,
    allowed: bool,
    reason: str = "",
    pause_before_allow: float = 0.0,
    pause_before_decline: float = 0.0,
) -> None:
    """Simulate a single tool-call decision through Quill."""
    audit.emit(
        event_type="tool.attempted",
        session_id=tree.root.id,
        agent_id=agent_id,
        risk=risk,
        payload={"tool_name": tool_name, "arg_keys": ["path"], "arg_count": 1},
    )
    tree.record_attempt(agent_id)

    # Simulate human ACK latency for high/critical
    if risk in ("high", "critical") and (pause_before_allow or pause_before_decline):
        time.sleep(pause_before_allow if allowed else pause_before_decline)

    if allowed:
        audit.emit(
            event_type="verdict.allowed",
            session_id=tree.root.id,
            agent_id=agent_id,
            risk=risk,
            payload={"tool_name": tool_name, "by": "human" if risk in ("high", "critical") else "policy"},
        )
        audit.emit(
            event_type="tool.completed",
            session_id=tree.root.id,
            agent_id=agent_id,
            risk=risk,
            payload={"tool_name": tool_name, "duration_ms": 42, "result_size": 256},
        )
        # Pretend the action cost a tiny amount of money.
        if risk in ("high", "critical"):
            tree.record_spend(agent_id, 0.05)
    else:
        evt_type = "verdict.scope_violation" if reason == "scope_violation" else "verdict.blocked"
        audit.emit(
            event_type=evt_type,
            session_id=tree.root.id,
            agent_id=agent_id,
            risk=risk,
            payload={"tool_name": tool_name, "reason": reason},
            force_fsync=True,
        )
        tree.record_block(agent_id)


if __name__ == "__main__":
    main()
