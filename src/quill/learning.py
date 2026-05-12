"""Autonomous learning loop. Quill reads its own audit data and updates
its behaviour, within safety bounds.

Design constraints from `docs/research/quill-autonomous-learning-2026-05.md`
(saved to vault). The non-negotiable architectural rules:

  1. Auto-tightening (block more) auto-applies. Auto-loosening (allow
     more) NEVER auto-applies; it surfaces as a suggestion the operator
     must promote explicitly. A security gate that quietly opens
     itself is a category mistake (CrowdStrike July 2024 is the worked
     example of why staged-rollout-with-rollback is non-negotiable).
  2. The hot path (`adapters/claude_code.py:run_hook`) stays
     deterministic. Same input + same on-disk state -> same output.
     This module is called POST-decision so a learning failure cannot
     fail-open or fail-closed the gate.
  3. Updates are persisted via atomic tmp-rename so an interrupted
     write cannot leave a corrupted pattern_stats.json.
  4. Every update appends a timestamped line to ~/.quill/learning.log
     so the operator can tail it and see exactly what changed.

The math is:

  - Beta-binomial conjugate update per pattern. Prior Beta(9, 1)
    encodes "default to 10% baseline approval; require real evidence
    to move." After N fires with K approvals, the posterior is
    Beta(9 + K, 1 + N - K).
  - Wilson 95% interval on the binomial proportion. Beats the normal
    approximation at small N. The lower bound drives loosen-candidate
    surfacing; the upper bound drives auto-tighten.
  - EWMA(0.1) on approval rate. Tracks recent behaviour so a pattern
    that's been auto-approved 100x but suddenly starts getting denied
    shows up before the posterior catches up.

Production exemplar: Falco's auto-tuner. Suggests exceptions daily;
human keeps or discards. https://www.sysdig.com/blog/falco-rule-tuning
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


# ---------------------------------------------------------------------------
# Constants - tunable but with defensible defaults from the research doc.
# Changes here SHOULD be versioned in git and discussed; arbitrary tuning
# during runtime is what produced the alert-fatigue problem in the first
# place.

PRIOR_ALPHA: float = 1.0   # prior "approvals" (operator-bypasses of blocks)
PRIOR_BETA: float = 9.0    # prior "denies" (block stood)
# Prior mean = alpha / (alpha + beta) = 1 / 10 = 0.10. This encodes
# "by default, the operator approves 10% of blocked attempts; the
# other 90% the block stands." A high approval rate is what surfaces
# a pattern as a loosening candidate. The research doc had this flipped
# (Beta(9, 1) was annotated "10%" but gives 0.9); we encode the meaning,
# not the label.
EWMA_ALPHA: float = 0.1    # recency weight; 10 obs to half-decay

# Auto-tightening triggers (safe - never widens attack surface).
TIGHTEN_DENY_STREAK: int = 5         # 5 consecutive denies -> elevate
TIGHTEN_WILSON_UPPER: float = 0.05   # 95% upper on approval < 5% means
                                     # denials dominate -> upgrade pattern

# Loosen-candidate triggers (surfaced only, NEVER auto-applied).
LOOSEN_WILSON_LOWER: float = 0.65    # 95% lower on approval > 65% means
                                     # approvals dominate -> review
LOOSEN_MIN_FIRES: int = 20           # don't suggest below 20 fires

# Operator-anomaly thresholds (rate-based, no autoencoder).
FATIGUE_INTER_ARRIVAL_SEC: float = 2.0
FATIGUE_STREAK_LEN: int = 20
COMPROMISE_BURST_PER_5MIN: int = 50  # 50 approvals in 5 min = suspect


# ---------------------------------------------------------------------------
# Paths. All env-overridable for test isolation.

def _stats_path() -> Path:
    return Path(os.environ.get(
        "QUILL_PATTERN_STATS",
        str(Path.home() / ".quill" / "pattern_stats.json"),
    )).expanduser()


def _suggestions_path() -> Path:
    return Path(os.environ.get(
        "QUILL_SUGGESTIONS",
        str(Path.home() / ".quill" / "suggestions.jsonl"),
    )).expanduser()


def _log_path() -> Path:
    return Path(os.environ.get(
        "QUILL_LEARNING_LOG",
        str(Path.home() / ".quill" / "learning.log"),
    )).expanduser()


# ---------------------------------------------------------------------------
# PatternStats: the integer state per classifier pattern.

@dataclass
class PatternStats:
    """One pattern's running stats. All counters are integers; floats
    are derived. The dataclass round-trips through asdict()/dict
    cleanly so persistence is just json.dumps.
    """

    pattern_id: str
    fires: int = 0
    approvals: int = 0
    denies: int = 0
    last_fire_ts: float = 0.0
    first_fire_ts: float = 0.0
    ewma_approval_rate: float = 0.0
    inter_arrival_sec: list[float] = field(default_factory=list)
    consecutive_denies: int = 0
    consecutive_approvals: int = 0

    @property
    def beta_alpha(self) -> float:
        return PRIOR_ALPHA + self.approvals

    @property
    def beta_beta(self) -> float:
        return PRIOR_BETA + self.denies

    @property
    def posterior_mean(self) -> float:
        a, b = self.beta_alpha, self.beta_beta
        return a / (a + b)

    def wilson_interval(self, confidence: float = 0.95) -> tuple[float, float]:
        """Wilson score interval for a binomial proportion. Beats the
        normal approximation at small N; tight at the boundaries.

        See https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval
        Returns (low, high) on the unit interval. An empty pattern
        returns (0.0, 1.0) - maximum uncertainty.
        """
        n = self.approvals + self.denies
        if n == 0:
            return (0.0, 1.0)
        if confidence == 0.95:
            z = 1.959964
        elif confidence == 0.90:
            z = 1.644854
        else:
            # erf-based inverse for arbitrary confidence; uncommon path.
            from statistics import NormalDist
            z = NormalDist().inv_cdf(1 - (1 - confidence) / 2)
        p = self.approvals / n
        z2 = z * z
        denom = 1 + z2 / n
        center = (p + z2 / (2 * n)) / denom
        half = (z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / denom
        return (max(0.0, center - half), min(1.0, center + half))

    def record(self, decision: Literal["approve", "deny"], now: float) -> None:
        """Apply one labelled observation. Updates fire counters,
        inter-arrival history, EWMA, and the streak counters.
        """
        self.fires += 1
        if self.first_fire_ts == 0.0:
            self.first_fire_ts = now
        if self.last_fire_ts > 0:
            gap = now - self.last_fire_ts
            if gap >= 0:
                self.inter_arrival_sec.append(gap)
                # bounded ring: keep last 50 only so the JSON stays small
                if len(self.inter_arrival_sec) > 50:
                    self.inter_arrival_sec = self.inter_arrival_sec[-50:]
        self.last_fire_ts = now

        outcome = 1.0 if decision == "approve" else 0.0
        self.ewma_approval_rate = (
            EWMA_ALPHA * outcome + (1 - EWMA_ALPHA) * self.ewma_approval_rate
        )

        if decision == "approve":
            self.approvals += 1
            self.consecutive_approvals += 1
            self.consecutive_denies = 0
        else:
            self.denies += 1
            self.consecutive_denies += 1
            self.consecutive_approvals = 0


# ---------------------------------------------------------------------------
# Persistence. Atomic via tmp-rename so an interrupted write cannot
# leave a corrupted file. Mode 0o600 because the pattern_id might be
# operator-identifying.

def load_stats() -> dict[str, PatternStats]:
    p = _stats_path()
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        # If the file is corrupted, treat as empty so the learner restarts
        # rather than crashing the hook. The audit log is the source of
        # truth and could be re-derived if needed.
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, PatternStats] = {}
    for k, v in raw.items():
        if not isinstance(v, dict):
            continue
        # Defensive: drop fields the dataclass doesn't know about so
        # forward-compatible upgrades don't crash older readers.
        known = {f for f in PatternStats.__dataclass_fields__}
        clean = {kk: vv for kk, vv in v.items() if kk in known}
        clean["pattern_id"] = str(k)
        with contextlib.suppress(TypeError):
            out[str(k)] = PatternStats(**clean)
    return out


def save_stats(stats: dict[str, PatternStats]) -> None:
    p = _stats_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    payload = {k: asdict(v) for k, v in stats.items()}
    tmp.write_text(json.dumps(payload, indent=2))
    # tmp-rename is atomic on POSIX. A crash between write and rename
    # leaves the .tmp file behind but the canonical file is untouched.
    tmp.replace(p)
    with contextlib.suppress(OSError):
        p.chmod(0o600)


# ---------------------------------------------------------------------------
# Append-only logs.

def append_suggestion(payload: dict[str, Any]) -> None:
    """Surface a suggestion to the operator. Never auto-applied;
    `quill suggestions promote <id>` is the apply path."""
    p = _suggestions_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, separators=(",", ":")) + "\n"
    with p.open("a") as f:
        f.write(line)
    with contextlib.suppress(OSError):
        p.chmod(0o600)


def log_event(line: str) -> None:
    """Timestamped append to ~/.quill/learning.log. The operator tails
    this to watch the learner update itself in real time."""
    p = _log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
    with p.open("a") as f:
        f.write(f"{ts} {line}\n")
    with contextlib.suppress(OSError):
        p.chmod(0o600)


# ---------------------------------------------------------------------------
# Pure-function detectors. Each returns a suggestion dict or None.
# Tightening detectors WILL auto-apply (caller writes the change).
# Loosening detectors NEVER auto-apply (caller only surfaces).

def detect_tightening(p: PatternStats) -> dict[str, Any] | None:
    """Auto-applies. The two triggers are:
      1. consecutive_denies >= TIGHTEN_DENY_STREAK
      2. Wilson 95% upper bound on approval < TIGHTEN_WILSON_UPPER
    Either signals "the operator agrees with this block class; tighten
    rather than keep prompting."
    """
    if p.consecutive_denies >= TIGHTEN_DENY_STREAK:
        return {
            "type": "tightening_auto_applied",
            "pattern_id": p.pattern_id,
            "evidence": f"{p.consecutive_denies} consecutive denies",
            "applied_change": "elevate to operator-attention queue",
        }
    _, wilson_high = p.wilson_interval(0.95)
    if p.fires >= 10 and wilson_high < TIGHTEN_WILSON_UPPER:
        return {
            "type": "tightening_auto_applied",
            "pattern_id": p.pattern_id,
            "evidence": (
                f"Wilson 95% upper on approval = {wilson_high:.3f} "
                f"(fires={p.fires}, approvals={p.approvals})"
            ),
            "applied_change": "candidate for severity upgrade",
        }
    return None


def detect_loosen_candidate(p: PatternStats) -> dict[str, Any] | None:
    """Surfaced only. Never auto-applied. Operator must run
    `quill suggestions promote <id>` to write the override.
    """
    wilson_low, _ = p.wilson_interval(0.95)
    if p.fires < LOOSEN_MIN_FIRES:
        return None
    if wilson_low <= LOOSEN_WILSON_LOWER:
        return None
    return {
        "type": "loosening_candidate",
        "pattern_id": p.pattern_id,
        "evidence": (
            f"approval rate {p.posterior_mean:.0%} "
            f"(Wilson 95% lower {wilson_low:.0%}, n={p.fires})"
        ),
        "proposal": (
            "Review for per-context override. Promote with "
            "`quill suggestions promote {id}`. Never auto-applied."
        ),
        "expires_ts": time.time() + 30 * 86400,
    }


def detect_operator_fatigue(p: PatternStats) -> dict[str, Any] | None:
    """Fires when the operator has been rapid-fire approving a single
    pattern long enough to suggest they're not reading the prompts
    any more. Rate-based; no model needed."""
    if p.consecutive_approvals < FATIGUE_STREAK_LEN:
        return None
    recent = p.inter_arrival_sec[-FATIGUE_STREAK_LEN:]
    if not recent:
        return None
    median = sorted(recent)[len(recent) // 2]
    if median >= FATIGUE_INTER_ARRIVAL_SEC:
        return None
    return {
        "type": "operator_anomaly",
        "subtype": "fatigue",
        "pattern_id": p.pattern_id,
        "evidence": (
            f"streak {p.consecutive_approvals} approvals, "
            f"median inter-arrival {median:.1f}s "
            f"(< {FATIGUE_INTER_ARRIVAL_SEC}s threshold)"
        ),
        "proposal": "Require Touch ID re-auth on next decision",
    }


# ---------------------------------------------------------------------------
# Public entry. Called from the hook adapter AFTER the verdict is
# rendered. Never blocks the hot path. Failure here is non-fatal.

def post_decision_update(
    pattern_id: str,
    decision: Literal["approve", "deny"],
    now: float | None = None,
) -> list[dict[str, Any]]:
    """Update pattern_stats for one observation; fire detectors; write
    suggestions; append a log line. Returns the list of suggestions
    emitted (for tests / for the caller to optionally surface inline).

    Errors are caught and logged so the calling hook stays robust. The
    audit log is the source of truth; pattern_stats is a cache that
    can be re-derived if it goes bad.
    """
    try:
        now = now if now is not None else time.time()
        stats = load_stats()
        p = stats.get(pattern_id) or PatternStats(pattern_id=pattern_id)
        p.record(decision, now)
        stats[pattern_id] = p

        emitted: list[dict[str, Any]] = []
        for detector in (
            detect_tightening,
            detect_loosen_candidate,
            detect_operator_fatigue,
        ):
            sug = detector(p)
            if sug is None:
                continue
            sug["ts"] = now
            sug["pattern_id"] = sug.get("pattern_id", pattern_id)
            append_suggestion(sug)
            emitted.append(sug)
            log_event(
                f"suggestion[{sug['type']}] pattern={pattern_id} "
                f"evidence={sug.get('evidence', '')[:140]}"
            )

        save_stats(stats)
        log_event(
            f"update pattern={pattern_id} decision={decision} "
            f"fires={p.fires} approvals={p.approvals} denies={p.denies} "
            f"posterior={p.posterior_mean:.3f}"
        )
        return emitted
    except Exception as exc:
        # Learning failures must never break the hook. Log + move on.
        # Test-only env var QUILL_LEARNING_STRICT raises; production stays soft.
        if os.environ.get("QUILL_LEARNING_STRICT"):
            raise
        with contextlib.suppress(OSError):
            log_event(f"ERROR pattern={pattern_id} {type(exc).__name__}: {exc}")
        return []


# ---------------------------------------------------------------------------
# Drift detection (Page-Hinkley statistic).
#
# Detects a sustained shift in the operator's aggregate approval rate
# at session-end. Per-pattern drift is too sparse to be meaningful at
# our event volume (research doc S5).
#
# Math: maintain a running mean m_t and cumulative deviation. Alert
# when (current cumulative) - (running min/max cumulative) > lambda,
# using `delta` as a tolerated-shift slack so noise doesn't fire it.
#
# Defaults from Viinikka et al. (IDS background-noise EWMA paper) +
# the research doc's recommendation.

PH_DELTA: float = 0.005
PH_LAMBDA: float = 10.0


@dataclass
class PageHinkleyResult:
    detected: bool
    direction: Literal["upward", "downward", "none"]
    statistic: float
    n_observations: int
    rate_now: float
    rate_prior_window: float


def page_hinkley(
    observations: Iterable[float],
    delta: float = PH_DELTA,
    lam: float = PH_LAMBDA,
) -> PageHinkleyResult:
    """Bidirectional Page-Hinkley over a binary outcome stream.

    Each observation should be 0.0 (deny/ask) or 1.0 (operator
    approved). Below 20 observations we report no-detect because
    Page-Hinkley is unreliable in that regime.
    """
    xs = list(observations)
    n = len(xs)
    if n < 20:
        return PageHinkleyResult(False, "none", 0.0, n, 0.0, 0.0)

    # Standard Page-Hinkley construction (both directions):
    #   For UP-shift, accumulate (x - mean - delta); the stream rises
    #   over its current floor by (sum - min(sum)). Alert if > lambda.
    #   For DOWN-shift, accumulate (mean - x - delta) - SIGN-FLIPPED
    #   so a drop in x produces a positive cumulative. Same maths
    #   from there: stat = (sum - min(sum)). Track MIN for both.
    mean = 0.0
    sum_dev_up = 0.0
    min_dev_up = 0.0
    sum_dev_down = 0.0
    min_dev_down = 0.0
    for i, x in enumerate(xs, start=1):
        mean = mean + (x - mean) / i
        sum_dev_up += (x - mean - delta)
        min_dev_up = min(min_dev_up, sum_dev_up)
        sum_dev_down += (mean - x - delta)
        min_dev_down = min(min_dev_down, sum_dev_down)

    stat_up = sum_dev_up - min_dev_up
    stat_down = sum_dev_down - min_dev_down
    window = min(20, n)
    rate_now = sum(xs[-window:]) / window
    rate_prior = sum(xs[:max(1, n - window)]) / max(1, n - window)
    if stat_up > lam and rate_now > rate_prior:
        return PageHinkleyResult(True, "upward", stat_up, n, rate_now, rate_prior)
    if stat_down > lam and rate_now < rate_prior:
        return PageHinkleyResult(True, "downward", stat_down, n, rate_now, rate_prior)
    return PageHinkleyResult(False, "none", max(stat_up, stat_down), n,
                             rate_now, rate_prior)


def aggregate_observations_for_session(
    audit_events: Iterable[dict[str, Any]],
    session_id: str,
) -> list[float]:
    """Extract a 0/1 stream for one session. 1=operator approved a
    blocked call via one-shot token; 0=verdict was deny or ask.
    Plain-LOW allows are excluded (no operator signal)."""
    out: list[float] = []
    for e in audit_events:
        if e.get("session_id") != session_id:
            continue
        etype = e.get("type")
        payload = e.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        if etype == "verdict.blocked":
            out.append(0.0)
        elif etype == "verdict.ask":
            out.append(0.0)
        elif etype == "verdict.allowed":
            reason = str(payload.get("reason") or "")
            if reason.startswith("approved one-shot"):
                out.append(1.0)
    return out


def check_drift_for_session(
    audit_events: Iterable[dict[str, Any]],
    session_id: str,
) -> dict[str, Any] | None:
    """Run Page-Hinkley over one session's outcome stream. On detect,
    emit a `drift_detected` suggestion + return it; else None.
    """
    obs = aggregate_observations_for_session(audit_events, session_id)
    result = page_hinkley(obs)
    if not result.detected:
        return None
    sug = {
        "type": "drift_detected",
        "session_id": session_id,
        "direction": result.direction,
        "evidence": (
            f"Page-Hinkley {result.statistic:.2f} > lambda {PH_LAMBDA} "
            f"(n={result.n_observations}, "
            f"rate recent={result.rate_now:.2f}, "
            f"prior={result.rate_prior_window:.2f})"
        ),
        "proposal": (
            f"Approval rate shifted {result.direction}. "
            "Review recent suggestions and pattern_stats; the operator "
            "started behaving differently. Common causes: a new "
            "untrusted repo, a workflow change, or operator fatigue."
        ),
        "ts": time.time(),
    }
    append_suggestion(sug)
    log_event(
        f"drift session={session_id} direction={result.direction} "
        f"stat={result.statistic:.2f} rate_now={result.rate_now:.2f} "
        f"rate_prior={result.rate_prior_window:.2f}"
    )
    return sug


# ---------------------------------------------------------------------------
# Helpers for the CLI.

def read_recent_log(n: int = 50) -> list[str]:
    p = _log_path()
    if not p.exists():
        return []
    lines = p.read_text().splitlines()
    return lines[-n:]


def read_suggestions(limit: int = 100) -> list[dict[str, Any]]:
    p = _suggestions_path()
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with p.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out[-limit:]


def stats_summary(stats: dict[str, PatternStats] | None = None) -> dict[str, Any]:
    """Snapshot for `quill log` and dashboards. Pure read."""
    s = stats if stats is not None else load_stats()
    return {
        "n_patterns": len(s),
        "total_fires": sum(p.fires for p in s.values()),
        "total_approvals": sum(p.approvals for p in s.values()),
        "total_denies": sum(p.denies for p in s.values()),
        "top_by_fires": sorted(
            ((p.pattern_id, p.fires) for p in s.values()),
            key=lambda kv: -kv[1],
        )[:8],
    }
