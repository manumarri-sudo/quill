# Hardware-Attested Approvals for `quill approve`

*Research dated 2026-05-08. Audience: Quill maintainers planning v0.2 / v0.3.*

## Executive summary

Quill's current `quill approve <token>` flow is software-only: any process running as the user (a hijacked tty, an agent that owns Quill's stdin, a malicious dev-tool) can self-approve. The fix is a hardware-attested "yes" - a yes/no decision rooted in a key the OS will not release to userspace. Two paths matter:

- **v0.2 (1 week, macOS-only):** Wrap `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` via the official `pyobjc-framework-LocalAuthentication` package (MIT, ships every month, ~30 KB wheel). Pure-Python; no Swift toolchain; no Info.plist needed for Touch-ID-only flows. Gate the *consume* step (release-time), not the persist step. Fall back to today's typed-token path on Linux / SSH / non-biometric Macs and emit a clear telemetry event distinguishing the two.
- **v0.3 (1 month, cross-platform):** Add an opt-in `--with-key` flag that talks to a FIDO2/U2F authenticator over USB-HID via `python-fido2` (BSD-2-Clause, Yubico-maintained). Treat WebAuthn-over-localhost-browser as a stretch goal, not the default - it adds an HTTP server, a TLS dance, and brittle browser dependencies for marginal UX wins.

Everything else (TPM2, PAM modules, Pushover/Twilio "approve from phone", custom Swift binary) is overkill, out-of-scope, or actively hostile to the "MIT, zero-server, offline-capable" constraints.

---

## 1. Survey: what's actually shipped

### macOS Touch ID via PAM (`sudo`, `fish-shell/sudo-touchid`)

- **Apple's stock `pam_tid.so`** is the canonical primitive. As of macOS 14 Sonoma the official enrollment path is `cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local` and editing it to add `auth sufficient pam_tid.so`; this survives OS updates. ([Der Flounder, 2023-10-14](https://derflounder.wordpress.com/2023/10/14/enabling-touch-id-authentication-for-sudo-on-macos-sonoma/), [DEV, 2024](https://dev.to/siddhantkcode/enable-touch-id-authentication-for-sudo-on-macos-sonoma-14x-4d28))
- **`artginzburg/sudo-touchid`** ([github.com/artginzburg/sudo-touchid](https://github.com/artginzburg/sudo-touchid)) - EPL-2.0 (incompatible with our MIT, NO-go for vendoring). It's a Homebrew-installable LaunchDaemon that re-applies the `sudo_local` config across system updates. Mechanism: PAM only - doesn't help us.
- **`mattrajca/sudo-touchid`** is a fork of `sudo` itself - abandoned, 2017-era.
- ✅ VERIFIED: PAM is the wrong layer for Quill. PAM hooks are Apple-stack-specific, require root to install, and become a maintenance burden across OS releases. Cross off.

### `1Password CLI` (`op`)

The most mature implementation of this exact pattern - biometric unlock guarding a CLI signing operation. ([1Password biometric security docs](https://developer.1password.com/docs/cli/biometric-security/), [shell-plugins blog](https://1password.com/blog/shell-plugins))

- **Mechanism:** `op` connects to the 1Password desktop app over a named pipe; the desktop app verifies the connecting process's Authenticode signature, then prompts the user via the OS's native biometric API (Touch ID on macOS, Windows Hello on Windows, PolKit on Linux). 1Password CLI never touches biometric data itself.
- **What we steal:** the architecture pattern (a privileged helper does the auth; the CLI is dumb). What we *don't* steal: 1Password CLI is closed-source, and this pattern requires us to ship a desktop app, which we won't.
- 🔶 INFERENCE: The Authenticode-signature check on the named-pipe peer is what makes this hard to spoof. If we ever build a Quill desktop app, mirror this.

### `python-fido2` (Yubico)

- Repo: [github.com/Yubico/python-fido2](https://github.com/Yubico/python-fido2) - **BSD-2-Clause** ✅ MIT-compatible.
- Latest: 2.2.0 (2026-04-15), Python 3.10+, ~150 KB wheel. Only hard dep is `cryptography`. Optional `pyscard` for NFC.
- Platforms: Windows, macOS, Linux (the latter needs udev rules at `/etc/udev/rules.d/70-u2f.rules`); FreeBSD/OpenBSD via community.
- Min "press your key" flow (from [`examples/hmac_secret.py`](https://github.com/Yubico/python-fido2/blob/main/examples/hmac_secret.py)):
  ```python
  from fido2.client import DefaultClientDataCollector, Fido2Client
  from exampleutils import CliInteraction, enumerate_devices

  for dev in enumerate_devices():
      client = Fido2Client(
          dev,
          client_data_collector=DefaultClientDataCollector("https://example.com"),
          user_interaction=CliInteraction(),  # prints "Touch your authenticator device now..."
      )
      break
  result = client.get_assertion({...})  # blocks on physical touch
  ```
- ✅ VERIFIED: this is the right library for v0.3. CliInteraction.prompt_up() is exactly the UX we want.

### `pyobjc-framework-LocalAuthentication`

- PyPI: [pypi.org/project/pyobjc-framework-LocalAuthentication](https://pypi.org/project/pyobjc-framework-LocalAuthentication/) - **MIT** ✅
- Version 12.1 (2025-11), 29.9 KB sdist, 10–11 KB wheel. Python 3.10+, macOS 10.13+ universal2.
- Pulls in `pyobjc-core` and `pyobjc-framework-Cocoa` transitively (~15 MB combined). That's the *only* meaningful cost.
- Reference implementation: [`lukaskollmer/python-touch-id`](https://github.com/lukaskollmer/python-touch-id/blob/master/touchid.py). Archived 2019, no LICENSE file (so we read it, don't vendor it). The whole thing is 47 lines and uses ctypes for `dispatch_semaphore_*` because the LA reply is a Grand Central Dispatch block that returns asynchronously. The dispatch trick is canonical and we should mirror it.

### `lox/go-touchid` and `jorgelbg/pinentry-touchid`

- [`lox/go-touchid`](https://github.com/lox/go-touchid) - 42 stars, **no LICENSE file**, only 2 commits. Cgo wrapper around `LAContext`. Useful as a reference for the Objective-C invocation; not vendorable due to missing license.
- [`jorgelbg/pinentry-touchid`](https://github.com/jorgelbg/pinentry-touchid) - Apache-2.0 ✅, depends on `lox/go-touchid` plus `keybase/go-keychain`. Production-deployed for several years. Mechanism: stash the GPG passphrase in macOS Keychain with `kSecAttrAccessControl` requiring biometric, then `SecItemCopyMatching` triggers the Touch ID prompt automatically. Two takeaways:
  1. Keychain-gated retrieval is a *cleaner* mechanism than raw LAContext when you actually have a secret to gate. We don't have a secret per approval (just a yes/no), so direct LAContext is fine.
  2. This binary runs unsigned (Homebrew distribution) and the Touch ID prompt works. **Empirical proof we don't need a bundled .app or Info.plist for biometric-only invocations on a desktop Mac.**

### `sigstore`/`cosign` + Fulcio

- Hardware support is **PIV-only**, not FIDO2 ([sigstore docs: Hardware Tokens](https://docs.sigstore.dev/cosign/key_management/hardware-based-tokens/)). `cosign piv-tool generate-key` calls `go-piv` to create a non-extractable key on a YubiKey, then `cosign sign --key <piv>` signs against that key with a touch + PIN.
- Keyless mode (Fulcio) is OIDC-rooted, not hardware-rooted: it gives you ephemeral certs bound to your Google/GitHub identity. Different threat model.
- ❌ Not directly applicable: we want a yes/no, not a signed artifact. But the *pattern* (touch as proof-of-presence on a non-extractable key) is what FIDO2 gives us in v0.3 with less ceremony.

### `age` + `age-plugin-yubikey`

- [`str4d/age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) - Apache-2.0/MIT dual ✅
- Uses **PIV** (not FIDO2) for the encryption key, with configurable PIN-and-touch policy. SSH signing in the same ecosystem (`ed25519-sk`) uses FIDO2.
- Confirms the conventional wisdom: PIV for encrypt-at-rest, FIDO2 for prove-the-human-is-here. Quill is the latter case.

### `yubikey-agent` (Filippo Valsorda)

- [`FiloSottile/yubikey-agent`](https://github.com/FiloSottile/yubikey-agent) - BSD-3-Clause ✅
- ssh-agent that holds a YubiKey-resident PIV key. "Every session requires the PIN, every login requires a touch."
- 🔶 INFERENCE: This is the model Quill could imitate for an *advanced* mode where instead of binding `(tool_name, args_digest) → bool`, we sign the digest with a YubiKey-resident key and the audit log contains a verifiable signature. v0.3+ stretch.

### GitHub CLI / OpenSSH `sk-*`

- OpenSSH 8.2+ added `ecdsa-sk` and `ed25519-sk` key types ([github.blog/2021-05-10](https://github.blog/changelog/2021-05-10-ssh-authentication-with-security-keys/)). Touch is required at every connection ("Confirm user presence for key ECDSA-SK SHA256:... press your security key").
- ✅ VERIFIED: GitHub CLI itself doesn't gate `gh` commands behind WebAuthn - it relies on the underlying SSH transport. Not a model for us.

### `cosign`-style "Beyond Identity" / Strata / Pindrop

- Beyond Identity's [AI Security Suite](https://www.beyondidentity.com/resource/beyond-identity-opens-early-access-for-the-ai-security-suite) is the closest commercial analog: device-bound credentials in TPM/Secure Enclave, a context-aware proxy gating AI agent tool calls. Closed-source; Quill IS the open-source version of this concept.
- ❓ OPEN QUESTION: Is there an open-source library that implements TPM/Secure-Enclave-bound credentials with a clean Python API? Not that I found. `tpm2-pytss` exists (LGPL-2.1 - cross off for vendoring) but the API is gnarly.

### Bitwarden / LastPass CLI

- Bitwarden CLI (`bw`) **does not support biometric unlock natively** as of 2026-05; the official `bw unlock` requires the master password. Community workaround [`jeanregisser/bitwarden-cli-bio`](https://github.com/jeanregisser/bitwarden-cli-bio) talks to the desktop app's IPC named pipe.
- LastPass CLI: no biometric story.
- 🔶 INFERENCE: Even Bitwarden - a security product with billions in funding - hasn't shipped CLI biometrics in 5 years of asks. The implementation cost is non-trivial and the IPC-to-desktop-app pattern dominates. We don't have a desktop app, so we'll go direct via `LAContext`.

### Linux: `systemd-cryptenroll --tpm2-device`

- [Lennart Poettering's blog post](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html), [Arch wiki](https://wiki.archlinux.org/title/Systemd-cryptenroll). Binds a LUKS slot to TPM2 PCRs (Secure Boot state). Useful for *unattended unlock at boot* - exactly the wrong threat model for an interactive approve.
- TPM2 user-presence (PCR 14, "user-presence") exists in spec but adoption is rough. `tpm2-tools` is fine for scripts but no per-action user verification primitive.
- ❌ Not the right tool. For Linux we punt to FIDO2 (security key) or fall back to typed token in v0.2.

### Windows Hello

- Microsoft's `webauthn.h` Win32 API ([learn.microsoft.com/.../webauthn](https://learn.microsoft.com/en-us/windows/win32/webauthn/-webauthn-portal)) is the canonical surface; .NET wrapper `DSInternals.Win32.WebAuthn` ([github.com/MichaelGrafnetter/webauthn-interop](https://github.com/MichaelGrafnetter/webauthn-interop)) is MIT.
- Python wrapper: `python-fido2` v2.2.0 added a `WindowsClient` that proxies to `webauthn.h`. **Best path for Windows Hello in Python today.**
- ✅ VERIFIED: v0.3 with `python-fido2` covers Windows for free.

---

## 2. Threat model + UX trade-offs

### What does Touch ID actually prove?

Touch ID via `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`:

- The fingerprint never leaves the Secure Enclave; userspace gets a `BOOL`.
- An attacker who controls the user's process *cannot* fake the success result. The evaluation runs out-of-process in `coreauthd` (or biometrickitd), which is itself only signaled by the kernel.
- An attacker who controls *the kernel* could in principle spoof the IPC reply. We accept that as out-of-scope (kernel = root + SIP-disabled = game over already).
- **Caveat:** `.deviceOwnerAuthenticationWithBiometrics` does NOT fall back to password. `.deviceOwnerAuthentication` (without "WithBiometrics") falls back to the user's login password, which an attacker watching keystrokes could capture. **We MUST use `.deviceOwnerAuthenticationWithBiometrics` for Quill.** Document this loudly.
- After 3 failed bio attempts, the policy is locked until `.deviceOwnerAuthentication` fallback succeeds OR the user re-logs-in. This is a known DoS vector (attacker mashes a fingerprint to lock you out) - acceptable cost.

### Composing with one-shot approval tokens

Quill's flow today (per [`src/quill/approvals.py`](../../src/quill/approvals.py)):

1. Block fires → `ApprovalStore.issue(...)` writes a pending token to `~/.quill/approvals.json`.
2. User runs `quill approve <token>` → `ApprovalStore.approve(token)` validates the token.
3. Agent retries the call → `ApprovalStore.consume(tool_name, args_digest)` finds the matching active approval, marks it consumed, returns it.

**Where the biometric check should sit:** at step 2 (`approve`), not step 3 (`consume`).

Reasoning:

- Step 2 happens at the human's terminal, where the Touch ID prompt is meaningful. Step 3 happens inside the agent process - the human may not even be present.
- Adding biometric to step 3 would mean *every consume* prompts, which is wrong for the flow: the human already said yes once.
- The risk Touch-ID-at-approve mitigates: an attacker steals the freshly-issued token (e.g. by reading `~/.quill/approvals.json` after it's written but before the human approves) and runs `quill approve` themselves. With biometric, they can't.
- The risk it doesn't mitigate: an attacker waits for a human-issued approval to land in the store and races the legitimate agent for the consume. **Mitigation:** keep approvals tightly bound to `(tool_name, args_digest)` and add a `nonce` so each consume is unique. (Already in scope per the bind.)

🔶 INFERENCE: Step-2 placement is also more forgiving on Linux/SSH where there's no biometric - we degrade to "you typed the token, that's our only signal" without breaking the consume path.

### Fallbacks when Touch ID is unavailable

Pragmatic ladder (configurable via `QUILL_APPROVE_AUTH=auto|biometric|key|token`):

1. **macOS with Touch Bar / T2 / Apple Silicon** → `LAContext` biometric.
2. **Plugged-in FIDO2 key** (any OS) → `python-fido2.get_assertion(...)`. v0.3.
3. **Anything else** → typed-token-only, with a `WARN` event on the audit log noting "no hardware attestation available".

Don't try to be clever. **No "type the token TWICE", no "compute a hash of the token", no time-based shenanigans** - none of that distinguishes a human from a hijacked tty. The honest answer is "we degrade gracefully and log it."

### Approve-from-phone

Out of scope for v0.2 / v0.3:

- Pushover, Twilio Verify, APNs all require a server. Quill v0.x is local-only (audit log on disk).
- Magic-link by email implies an SMTP relay or a hosted endpoint. Same problem.
- 🔶 INFERENCE: A future Quill Cloud might add this as a paid feature. For OSS users, FIDO2 is the right primitive.

---

## 3. Code we can vendor (with paths + license + provenance)

### `pyobjc-framework-LocalAuthentication`

- PyPI install: `pip install 'pyobjc-framework-LocalAuthentication>=12.0,<13'`. **MIT.** Add as `quill[touchid]` extra so non-Mac users don't pull it.
- Reference for usage: [`lukaskollmer/python-touch-id`](https://github.com/lukaskollmer/python-touch-id/blob/master/touchid.py) (no license - read, don't copy verbatim; rewrite the dispatch dance ourselves). The 47-line file is a near-perfect template for the canonical `LAContext` invocation from CPython.

### `python-fido2`

- PyPI: `pip install fido2>=2.2,<3`. **BSD-2-Clause.** Add as `quill[fido2]` extra.
- Vendor target file: [`fido2/client.py`](https://github.com/Yubico/python-fido2/blob/main/fido2/client.py) for the `Fido2Client` class.
- We do NOT need to vendor; we depend.
- Demo we'll mirror in our docs: [`examples/hmac_secret.py`](https://github.com/Yubico/python-fido2/blob/main/examples/hmac_secret.py).

### Optional (v0.3+): tiny Swift CLI shim

If we ever need attestation that the prompt-displaying process is one we control (defense against an attacker who controls the Python process and could just `return True` from `authenticate()`), build a 30-line Swift binary that:

1. Calls `LAContext.evaluatePolicy(...)`.
2. On success, prints a HMAC over the input nonce keyed by an Apple-attested per-machine key (DeviceCheck or App Attest).
3. Exits 0/1.

Codesign + notarize it. Ship it as `bin/quill-touchid`. **Out of scope for v0.2 - but flag it as the eventual hardening path.** No public template I found does exactly this, but `crunchybagel.com/building-command-line-tools-with-swift` is the right starting reference.

---

## 4. Recommendation: v0.2 path (50 lines, macOS-only)

### Dependency

```toml
# pyproject.toml
[project.optional-dependencies]
touchid = ["pyobjc-framework-LocalAuthentication>=12.0,<13; sys_platform == 'darwin'"]
```

User installs: `pip install 'quill[touchid]'`. Non-mac users do not see this dep.

### File: `src/quill/touchid.py` (~50 lines)

```python
"""Touch ID gate for `quill approve`. macOS-only; degrades to no-op elsewhere."""

from __future__ import annotations

import ctypes
import sys
from typing import Final

_REASON: Final = "approve a Quill-gated action"


def is_available() -> bool:
    """True iff the current Mac can perform biometric auth."""
    if sys.platform != "darwin":
        return False
    try:
        from LocalAuthentication import (  # type: ignore[import-not-found]
            LAContext,
            LAPolicyDeviceOwnerAuthenticationWithBiometrics,
        )
    except ImportError:
        return False
    ctx = LAContext.new()
    ok, _err = ctx.canEvaluatePolicy_error_(
        LAPolicyDeviceOwnerAuthenticationWithBiometrics, None
    )
    return bool(ok)


def authenticate(reason: str = _REASON) -> tuple[bool, str | None]:
    """Block until the user approves with Touch ID. Returns (ok, error_msg)."""
    if not is_available():
        return False, "touch-id-unavailable"

    from LocalAuthentication import (  # type: ignore[import-not-found]
        LAContext,
        LAPolicyDeviceOwnerAuthenticationWithBiometrics,
    )

    libdispatch = ctypes.cdll.LoadLibrary(None)
    libdispatch.dispatch_semaphore_create.restype = ctypes.c_void_p
    libdispatch.dispatch_semaphore_create.argtypes = [ctypes.c_int]
    libdispatch.dispatch_semaphore_wait.restype = ctypes.c_long
    libdispatch.dispatch_semaphore_wait.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
    libdispatch.dispatch_semaphore_signal.restype = ctypes.c_long
    libdispatch.dispatch_semaphore_signal.argtypes = [ctypes.c_void_p]

    sema = libdispatch.dispatch_semaphore_create(0)
    state: dict[str, object] = {"ok": False, "err": None}

    def _reply(success: bool, error: object) -> None:
        state["ok"] = bool(success)
        if error is not None:
            state["err"] = str(error.localizedDescription())  # type: ignore[attr-defined]
        libdispatch.dispatch_semaphore_signal(sema)

    ctx = LAContext.new()
    ctx.evaluatePolicy_localizedReason_reply_(
        LAPolicyDeviceOwnerAuthenticationWithBiometrics, reason, _reply
    )
    libdispatch.dispatch_semaphore_wait(sema, sys.maxsize)
    return bool(state["ok"]), state["err"]  # type: ignore[return-value]
```

### Wiring it into `quill approve`

In `src/quill/cli.py`, near the existing `approve` command handler:

```python
from quill import touchid

def cmd_approve(token: str, *, no_biometric: bool = False) -> int:
    store = ApprovalStore.load()
    pending = store.find(token)
    if pending is None or not pending.is_active:
        print("error: no such pending approval", file=sys.stderr)
        return 2

    # Biometric gate - best-effort. Falls through with a logged event on
    # platforms / setups without Touch ID.
    require_bio = config.get("approve.require_biometric", default=False)
    use_bio = touchid.is_available() and not no_biometric
    if use_bio:
        ok, err = touchid.authenticate(f"approve: {pending.tool_name}")
        if not ok:
            audit.log("approve.biometric.deny", token=token, error=err)
            print(f"biometric check failed: {err or 'denied'}", file=sys.stderr)
            return 3
        audit.log("approve.biometric.ok", token=token)
    elif require_bio:
        print("error: biometric required but unavailable", file=sys.stderr)
        return 4
    else:
        audit.log("approve.biometric.skipped", token=token, reason="unavailable")

    store.approve(token)
    print(f"approved: {pending.tool_name}")
    return 0
```

### New failure modes

1. **User has no enrolled fingerprints** → `canEvaluatePolicy` returns false → we log `skipped` and proceed with typed-token. Same security as today.
2. **User cancels the prompt / 3 failed taps** → returns `(False, "User canceled" / "Authentication failed")` → `approve.biometric.deny` audit event, exit 3, approval is NOT marked approved.
3. **`pyobjc-framework-LocalAuthentication` not installed** (user `pip install`'d without `[touchid]` extra) → `is_available()` returns false via `ImportError` → falls through to today's behavior.
4. **Running over SSH** → `canEvaluatePolicy` returns false (Touch ID is gated on local console session). Falls through. Document this.
5. **DoS via biometric lockout** - if the agent calls `authenticate()` 3+ times with bad input, the policy is locked until login. We mitigate by only calling on `approve`, which is human-driven. Worth a unit test.

### Tests

Add to `tests/test_touchid.py`:

- `is_available()` returns False on Linux/Windows (mocked `sys.platform`).
- `authenticate()` returns `(False, "touch-id-unavailable")` when not available.
- `cmd_approve` logs the right audit events for each branch.
- A skipped-on-Linux integration test that actually triggers Touch ID - mark `@pytest.mark.macos_local`.

### Docs

- Update `README.md`: "Quill on Mac auto-prompts for Touch ID at approve time. Set `approve.require_biometric = true` in `~/.quill/config.toml` to make it mandatory."
- Update `SECURITY.md`: add a new "Hardware-attested approvals" section that explains the threat model (this report, condensed).

---

## 5. Recommendation: v0.3 path (cross-platform FIDO2)

### Dependency

```toml
[project.optional-dependencies]
fido2 = ["fido2>=2.2,<3"]
```

`pip install 'quill[fido2]'`. ~150 KB + `cryptography` (already pulled by other Quill deps if applicable).

### Design

Quill maintains a per-user, per-machine FIDO2 *resident credential* under an RP-ID of `quill.local` (note: not a real domain - FIDO2 RP-IDs are namespaces, not URLs). On first run of `quill key enroll`, we call `make_credential()` and store the returned credential ID in `~/.quill/keys.json`. Subsequent `quill approve` calls do `get_assertion()` against that credential ID, with the args_digest as the `challenge`. Touch the key → assertion → verify signature against the stored public key → approve.

This gives us:

- **Cross-platform** (macOS / Linux / Windows / *BSD).
- **Hardware-rooted** (the key is non-extractable).
- **Auditable** (the assertion is a cryptographic signature over the challenge - write it to the audit log).
- **No server.**

### Where the auth call sits

Same place as Touch ID - the `approve` step. The user's invocation becomes:

```text
$ quill approve abc123
> tap your security key... [user touches]
> approved: shell.exec
```

Internally we add `--with-key` as a new flag (default: try biometric, fall back to key, fall back to typed token).

### Vendoring vs. depending

**Depend, don't vendor.** Yubico's library is BSD-2-Clause and actively maintained (2.2.0 ships 2026-04). Vendoring buys us nothing and adds a maintenance debt.

### Audit considerations

- `python-fido2` has had two CVEs since 2020, both quickly patched. Pin to `>=2.2,<3` so security patches flow.
- `cryptography` is the only transitive surface that matters; it's already widely-deployed and well-audited.
- ❓ OPEN QUESTION: the FIDO2 RP-ID model assumes a relying party hosting at a public domain. Using `quill.local` works for assertion verification (we hold the public key), but **other tools' WebAuthn implementations might error on it**. Verify with a Yubikey 5 + a Solo2 + a TPM-backed Windows Hello before claiming cross-platform.

### Localhost-WebAuthn-browser path (REJECTED)

A common alternative: Quill spins up `localhost:NNNN` with HTTPS, runs a static page, calls `navigator.credentials.get(...)`, captures the assertion, kills the server. **Don't do it.** Reasons:

- Need a self-signed cert; browsers throw scary warnings.
- Adds a ~60-line HTTP server to the auth path and a JS surface.
- Doesn't work on a headless Linux box (no browser).
- Direct USB-HID via `python-fido2` works on every platform that has libusb / hidraw. Just go direct.

The one case for the browser dance: some users want to use a *platform authenticator* (Windows Hello, Android cross-device, iPhone) instead of a USB key. Punt that to v0.4+; on Windows we can use `python-fido2`'s `WindowsClient` which talks to `webauthn.h` directly and gets Windows Hello for free.

---

## 6. Anti-recommendations

| Don't                                                  | Why                                                                                                         |
|--------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Roll our own crypto / attestation protocol             | We're MIT-licensed, two-person team. `python-fido2` and `LAContext` are battle-tested.                       |
| Require an internet round-trip per approve             | Quill is offline-first. Phone-tap-to-approve breaks SSH-into-server-with-no-LTE workflows.                  |
| Ship a kernel module or PAM hook                       | Per-OS maintenance bar = 100×. PAM also needs root to install. No.                                          |
| Embed Touch ID as a hard requirement on macOS          | Many devs work over SSH or on Macs without Touch Bar / Touch ID. Make it `default-on, opt-out` not mandatory.|
| Use `.deviceOwnerAuthentication` (with password fallback) | Defeats the purpose - keylogger captures the fallback password. Use `.deviceOwnerAuthenticationWithBiometrics`. |
| Re-prompt biometric on every consume                   | UX death. The human approved at step 2; agents consume at step 3 without the human present.                  |
| Build our own desktop helper app to mirror 1Password   | Multi-OS desktop dev is a separate product. Direct LAContext from Python works fine.                         |
| Vendor `lox/go-touchid` or `lukaskollmer/python-touch-id` | Neither has a LICENSE file. Read for reference, write our own.                                              |
| Ship a localhost HTTPS server for the WebAuthn dance   | Self-signed certs, browser warnings, JS surface, headless-server brokenness. `python-fido2` direct beats it. |
| Add Pushover/Twilio approve-from-phone in v0.x         | Implies a server. Quill is local-only OSS. Save for "Quill Cloud" if it ever exists.                         |
| Treat absence of Touch ID as a *failure*               | It's a configuration. Log `approve.biometric.skipped` with a clear reason and proceed.                       |

---

## 7. Open questions worth flagging

1. **Info.plist / NSFaceIDUsageDescription on macOS.** Apple's docs say Face ID *requires* `NSFaceIDUsageDescription` in the calling binary's Info.plist or the app crashes ([Apple devforums 86779](https://developer.apple.com/forums/thread/86779)). But desktop Macs use Touch ID (Touch Bar / Magic Keyboard sensor / Apple Silicon power button), and **`pinentry-touchid` and `lox/go-touchid` work as unsigned, non-bundled CLI binaries**. Empirical bet: Touch-ID-only flows do not require Info.plist, only Face ID flows do. **Verification step:** before v0.2 ships, test the 50-line code on (a) Apple Silicon MBP with Touch ID, (b) Mac mini with Magic Keyboard Touch ID, (c) Mac with iPhone-as-passkey-authenticator. If (c) errors with `LAErrorPasscodeNotSet` or similar, we may need to adopt `py2app`-style bundling or codesign with an embedded plist using `codesign --entitlements`.
2. **Hardened-runtime / Gatekeeper.** Quill is distributed via PyPI; users invoke it via their own (often unsigned) Python. Will Gatekeeper block the Touch ID prompt on first run? Suspect not (the call is to a system framework, not a quarantined binary), but verify on a fresh macOS install.
3. **`LAErrorNotInteractive`.** [Apple devforums 129480](https://developer.apple.com/forums/thread/129480) reports this in network-extension contexts. Could also fire for a process launched without a controlling tty (e.g. an MCP daemon spawned by launchd). Make sure the audit event distinguishes "user canceled" from "no UI available".
4. **FIDO2 RP-ID for v0.3.** Is `quill.local` accepted by all major authenticators, or do some require a domain that resolves? `python-fido2`'s `Fido2Server` uses RP-ID for origin binding; we need to confirm Yubikey 5, Solo 2, Windows Hello, and `python-fido2`'s WindowsClient all accept a non-DNS RP-ID.
5. **Touch-ID lockout DoS.** An attacker who can spam `quill approve <random>` will lock the biometric subsystem after 3 fails. Mitigation: rate-limit the prompt invocation server-side (e.g. only one biometric attempt per token, never reissue on failure). Worth a hardening pass in v0.2.1.
6. **Audit-log integrity.** With biometrics, the audit event `approve.biometric.ok` becomes a meaningful claim. If an attacker can write to `~/.quill/audit.log`, they can forge the claim. v0.3+ should sign each audit event with the FIDO2 key (this is exactly the `yubikey-agent` pattern). Out of scope for v0.2 but flag it.
7. **Linux PolKit / fprintd story.** PolKit + fprintd works for desktop Linux laptops with fingerprint sensors. There's no Python wrapper as clean as `pyobjc-framework-LocalAuthentication`. Probably not worth chasing - the "Linux user with a fingerprint sensor and no FIDO2 key" intersection is small. v0.4+ if demand surfaces.
8. **Notarization.** If we ever ship a Swift `quill-touchid` shim binary in PyPI wheels, Apple's notarization gate kicks in. PyPI wheels aren't quarantined (they're not downloaded via browser/AirDrop) so Gatekeeper *probably* doesn't block, but verify before relying on it.

---

## Sources

- [`lukaskollmer/python-touch-id` source](https://github.com/lukaskollmer/python-touch-id/blob/master/touchid.py)
- [`lox/go-touchid` source](https://github.com/lox/go-touchid)
- [`jorgelbg/pinentry-touchid` source](https://github.com/jorgelbg/pinentry-touchid)
- [`Yubico/python-fido2`](https://github.com/Yubico/python-fido2) - examples directory has the canonical `prompt_up()` flow
- [`pyobjc-framework-LocalAuthentication` on PyPI](https://pypi.org/project/pyobjc-framework-LocalAuthentication/)
- [1Password CLI biometric security](https://developer.1password.com/docs/cli/biometric-security/)
- [Sigstore hardware tokens](https://docs.sigstore.dev/cosign/key_management/hardware-based-tokens/)
- [`FiloSottile/yubikey-agent`](https://github.com/FiloSottile/yubikey-agent)
- [`str4d/age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey)
- [`artginzburg/sudo-touchid`](https://github.com/artginzburg/sudo-touchid) (EPL-2.0 - reference only)
- [Lennart Poettering on `systemd-cryptenroll` + TPM2/FIDO2](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html)
- [GitHub blog: SSH security keys](https://github.blog/changelog/2021-05-10-ssh-authentication-with-security-keys/)
- [Apple LAContext docs](https://developer.apple.com/documentation/localauthentication/lacontext)
- [Apple `evaluatePolicy(_:localizedReason:reply:)` docs](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:))
- [Beyond Identity AI Security Suite](https://www.beyondidentity.com/resource/beyond-identity-opens-early-access-for-the-ai-security-suite)
- [Der Flounder on macOS Sonoma sudo Touch ID](https://derflounder.wordpress.com/2023/10/14/enabling-touch-id-authentication-for-sudo-on-macos-sonoma/)
