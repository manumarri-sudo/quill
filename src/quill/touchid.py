"""Touch ID gating for `quill approve`.

The default approve flow is: user types `quill approve <token>`, the token
gets persisted, and the agent's next call is allowed. A compromised terminal
or a hijacked agent can self-approve by typing the token. This module adds
hardware-rooted liveness - Touch ID - so the approval requires a fingerprint
match against the user's enrolled biometrics. The match is performed in the
Secure Enclave; userspace gets only a yes/no and never sees the biometric.

macOS only. On Linux/Windows, on SSH sessions, on Macs without Touch ID
hardware enrolled, `is_available()` returns False and the caller falls
through to today's typed-token-only flow with an `approve.biometric.skipped`
audit event.

Critical security note: we use `LAPolicyDeviceOwnerAuthenticationWithBiometrics`
NOT `LAPolicyDeviceOwnerAuthentication`. The latter falls back to the user's
login password - which a keylogger captures, defeating the whole point.
DO NOT change the policy constant without reading SECURITY.md.

Verified live on Apple Silicon macOS (2026-05-08). The threading.Event +
reply-block pattern fires without requiring a separate NSRunLoop pump.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Final

# Reason strings shown in the Touch ID system banner. Apple guidelines say
# these should be a single concrete sentence; the user reads the banner
# under stress, so be specific about what they're approving.
DEFAULT_REASON: Final[str] = "release a quill-blocked tool call"

# Wait at most this long for the user to fingerprint. Apple's own dialog
# auto-cancels after ~30s; we match.
DEFAULT_TIMEOUT_S: Final[float] = 30.0


@dataclass(slots=True, frozen=True)
class TouchIDResult:
    success: bool
    reason: str  # "ok" | "user_canceled" | "lockout" | "not_available" | "error:<code>"


def is_available() -> bool:
    """True iff Touch ID can fire RIGHT NOW on this machine.

    Checks: macOS LocalAuthentication framework loads, hardware sensor is
    present, user has enrolled fingerprints, the current process context can
    reach the prompter (SSH sessions and launchd-spawned daemons return
    False here, which is correct).
    """
    try:
        import LocalAuthentication  # type: ignore[import-not-found]
    except ImportError:
        return False
    try:
        ctx = LocalAuthentication.LAContext.new()
        # canEvaluatePolicy returns (bool, NSError|None). Don't try to
        # evaluate without enrollment - the SDK call itself throws.
        can, _err = ctx.canEvaluatePolicy_error_(
            LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,
            None,
        )
        return bool(can)
    except Exception:
        return False


def authenticate(
    reason: str = DEFAULT_REASON,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> TouchIDResult:
    """Block until Touch ID fires, returns a structured result.

    Returns TouchIDResult with success=True on a real fingerprint match.
    Failure modes:
      - "not_available"   - Touch ID can't fire (Linux, SSH, no hardware,
                            no enrollment, biometry locked out).
      - "user_canceled"   - user pressed Cancel / closed the dialog.
      - "lockout"         - too many failed attempts; locked until login.
      - "timeout"         - reply block didn't fire in `timeout_s`.
      - "error:<code>"    - any other LAError.

    Never raises. The caller decides whether to fall through to the
    typed-token-only path (when result.success is False) or refuse the
    approval entirely (paranoid mode).
    """
    if not is_available():
        return TouchIDResult(False, "not_available")

    import LocalAuthentication  # type: ignore[import-not-found]

    ctx = LocalAuthentication.LAContext.new()
    event = threading.Event()
    captured: dict[str, object] = {}

    def reply(success: bool, error: object) -> None:
        captured["success"] = bool(success)
        captured["error"] = error
        event.set()

    try:
        ctx.evaluatePolicy_localizedReason_reply_(
            LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,
            reason,
            reply,
        )
    except Exception as e:
        return TouchIDResult(False, f"error:{type(e).__name__}")

    if not event.wait(timeout=timeout_s):
        return TouchIDResult(False, "timeout")

    if captured.get("success"):
        return TouchIDResult(True, "ok")

    err = captured.get("error")
    code = getattr(err, "code", lambda: 0)()
    # LAError codes - see Apple LocalAuthentication framework docs.
    if code == LocalAuthentication.LAErrorUserCancel:
        return TouchIDResult(False, "user_canceled")
    if code == LocalAuthentication.LAErrorBiometryLockout:
        return TouchIDResult(False, "lockout")
    if code == LocalAuthentication.LAErrorAuthenticationFailed:
        return TouchIDResult(False, "auth_failed")
    if code == LocalAuthentication.LAErrorNotInteractive:
        return TouchIDResult(False, "not_available")
    return TouchIDResult(False, f"error:{code}")
