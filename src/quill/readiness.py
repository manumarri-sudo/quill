"""Readiness: tell the human, in one glance, whether the gate is a *real* boundary.

The trap this guards against is the one that matters most: a key sitting in a
file on the same laptop the agent runs on is NOT off the agent's reach — the
agent runs as you and can read it. So readiness never reports "secure" just
because a key file exists. A control only counts as an enforced boundary when
its trust root lives where the agent cannot go:

  * the CI runner (a different machine) — secrets the laptop agent can't read, or
  * a hardware key (YubiKey / HSM / Secure Enclave) — un-exportable even to root.

This module computes a posture — ``enforced`` / ``cooperative`` / ``unconfigured``
— from what it can actually observe, and says exactly what's missing. It is the
"do the thinking for them" surface: run it and you know if you can stop worrying.
"""

from __future__ import annotations

import enum
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from quill import perimeter as perimeter_mod
from quill import provenance as provenance_mod


class Posture(str, enum.Enum):
    ENFORCED = "enforced"  # a real boundary against an adversarial agent
    COOPERATIVE = "cooperative"  # honest review automation; trust root is reachable
    UNCONFIGURED = "unconfigured"  # no perimeter at all


class Level(str, enum.Enum):
    BLOCKER = "blocker"  # without this it is not an enforced boundary
    HARDENING = "hardening"  # recommended, not strictly required


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    level: Level
    detail: str


@dataclass(frozen=True)
class ReadinessReport:
    posture: Posture
    checks: tuple[Check, ...] = field(default_factory=tuple)

    @property
    def blockers(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if not c.ok and c.level is Level.BLOCKER)


def _workflow_pinning(root: Path) -> Check:
    """Is the gate run from a pinned published tag (safe) or the PR's own code (unsafe)?

    Running the action from the PR's checkout (``uses: ./`` / ``install-from-source``)
    lets a PR modify the gate that judges it. A pinned tag (``uses: org/quill@v0``)
    runs trusted code the PR can't alter.
    """
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return Check(
            "gate workflow",
            False,
            Level.BLOCKER,
            "no .github/workflows — the gate isn't wired into CI (run `quill init`)",
        )
    text = "\n".join(p.read_text(errors="replace") for p in wf_dir.glob("*.y*ml") if p.is_file())
    if not re.search(r"quill", text, re.I):
        return Check(
            "gate workflow",
            False,
            Level.BLOCKER,
            "no Quill step found in any workflow",
        )
    pinned = re.search(r"uses:\s*[\w.-]+/quill@", text)
    from_source = "install-from-source" in text and re.search(
        r'install-from-source:\s*["\']?true', text
    )
    if from_source or re.search(r"uses:\s*\./", text):
        return Check(
            "gate workflow",
            False,
            Level.BLOCKER,
            "gate runs from the PR's own checkout (uses: ./ / install-from-source) — "
            "a PR can modify its own judge. Pin to a published tag: uses: manumarri-sudo/quill@v0",
        )
    if pinned:
        return Check("gate workflow", True, Level.BLOCKER, "pinned to a published tag")
    return Check(
        "gate workflow",
        False,
        Level.BLOCKER,
        "Quill referenced but not pinned to org/quill@<tag>",
    )


def assess(root: Path | None = None, env: dict[str, str] | None = None) -> ReadinessReport:
    """Assess whether Change Control is an enforced boundary for the repo at `root`."""
    root = perimeter_mod.perimeter_path(root or Path.cwd()).parent.parent
    env = env if env is not None else dict(os.environ)
    checks: list[Check] = []

    perimeter = perimeter_mod.load(root)
    if perimeter is None:
        return ReadinessReport(
            Posture.UNCONFIGURED,
            (Check("perimeter", False, Level.BLOCKER, "no signed perimeter (run `quill init`)"),),
        )

    # 1. Is the perimeter signed by a trusted approver?
    prov = provenance_mod.verify_artifact(
        perimeter.to_dict(), perimeter_mod.signature_path(root), root, env
    )
    signed_ok = prov.status is provenance_mod.ProvenanceStatus.OK
    checks.append(Check("perimeter signature", signed_ok, Level.BLOCKER, prov.detail))

    # 2. THE key question: is the approver trust root off the agent's reach, or
    #    just a file the agent can read? Env-pinned (CI secret) = off-box.
    #    Committed-only = on the laptop, editable in a PR -> not a boundary.
    env_pinned = bool(env.get(provenance_mod.APPROVER_ENV, "").strip())
    committed = (provenance_mod.approvers_dir(root)).is_dir()
    if env_pinned:
        checks.append(
            Check(
                "approver trust root",
                True,
                Level.BLOCKER,
                f"pinned via {provenance_mod.APPROVER_ENV} (a CI secret a PR can't edit)",
            )
        )
    else:
        checks.append(
            Check(
                "approver trust root",
                False,
                Level.BLOCKER,
                (
                    "approver keys are "
                    + ("committed in-repo only" if committed else "absent")
                    + f"; set {provenance_mod.APPROVER_ENV} as a CI secret so the trust root "
                    "lives where the agent can't reach it (a local/committed key the agent can read "
                    "or a PR can edit is not a boundary)"
                ),
            )
        )

    # 3. Gate signing key for the passport — present as a CI secret (off-box)?
    gate_env = bool(env.get("QUILL_GATE_KEY", "").strip())
    checks.append(
        Check(
            "gate signing key",
            gate_env,
            Level.HARDENING,
            "QUILL_GATE_KEY present (passports are signed)"
            if gate_env
            else "QUILL_GATE_KEY not set — passports won't be gate-signed; "
            "set it as a CI secret so verdicts are independently verifiable",
        )
    )

    # 4. Does the gate run from trusted pinned code, or the PR's own?
    checks.append(_workflow_pinning(root))

    # Posture: an enforced boundary needs the perimeter trusted AND the trust root
    # off-box AND the gate running trusted code. Anything less is cooperative.
    blocker_failed = any(not c.ok and c.level is Level.BLOCKER for c in checks)
    posture = Posture.COOPERATIVE if blocker_failed else Posture.ENFORCED
    return ReadinessReport(posture, tuple(checks))
