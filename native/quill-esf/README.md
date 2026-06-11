# Quill Endpoint Security extension (`quill-esf`)

The always-on, kernel-layer counterpart to the Seatbelt floor (`quill shell`).

- **Seatbelt floor** (`quill shell`) is **opt-in per session**: you launch the
  agent under it and the kernel confines that process tree. It also seals
  network egress.
- **This ES extension** is **always-on, system-wide**: once installed it gates
  file-modifying syscalls for every process, so the gate-disable surface (the
  hook scripts, `~/.quill/config.toml`, the HMAC key) is protected even for an
  agent that was *not* launched under `quill shell`.

They are complementary defense-in-depth. Neither is a guarantee; the honest
claim is "no known bypass for a non-root agent without an OS-level 0-day."

## What it gates (and does not)

Gates these file AUTH events on the protected paths, failing closed:
`AUTH_OPEN(write)`, `AUTH_UNLINK`, `AUTH_RENAME`, `AUTH_TRUNCATE`.

It does **not** gate network egress: Endpoint Security emits no
network-connect AUTH event. Egress sealing is the Seatbelt floor's job
(`quill shell --seal`) or a future Network Extension. Stating this plainly
because an ESF tool that implies it blocks exfiltration would be overstating.

## Architecture

Mirrors Google Santa / Trail of Bits Sinter (the only serious open-source ES
*enforcers*; most ES projects are observe-only):

```
quill esf compile  ->  ~/.quill/esf-rules.json  ->  PolicyEngine.load (Foundation)
                                                          |
                                                          v
ES kernel event  ->  main.swift (es client)  ->  PolicyCore (Foundation-free, pure)
                                                          |
                                  O(1) verdict, respond inline -> es_respond_auth_result
```

- `PolicyCore.swift` - pure Swift stdlib verdict logic, zero deps on the
  deadline-critical path. Unit-tested with bare `swiftc`. The per-event
  decision is an O(1) set lookup, so the client responds inline within the
  kernel deadline; no async watchdog is needed for this workload.
- `Policy.swift` - thin Foundation shell: JSON decode + symlink canonicalize.
  Seam: NSString.resolvingSymlinksInPath and Python's realpath can diverge for
  paths whose final component does not exist; validate in the VM phase.
- `main.swift` - ES plumbing (`es_new_client` / `es_subscribe` / respond);
  AUTH_RENAME checks the destination path, not just the source.

The rules are the SAME source of truth as the Seatbelt floor
(`quill.sandbox.default_protected`), so the two layers cannot drift; the
Python suite asserts that parity.

## Build & test

Test the verdict core now (no Xcode, no entitlement, no SIP changes):

```sh
./build.sh test          # compiles PolicyCore + tests, runs them
```

Build the full system extension (requires **full Xcode** - the
EndpointSecurity framework is absent from the Command Line Tools SDK):

```sh
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
./build.sh sysext
```

## Running it (the SIP reality)

Running an ES client needs one of:

1. **Dev mode (free, no Apple grant):** a **SIP-disabled VM** (`csrutil disable`
   from Recovery, `systemextensionsctl developer on`), ad-hoc signed, run as
   root. Do this in a throwaway macOS VM, never on your daily driver - disabling
   SIP weakens the whole machine.
2. **Distribution (needs the entitlement):** Developer ID signing + notarization
   + Apple's granted `com.apple.developer.endpoint-security.client`. Then a
   normal user installs on a **SIP-enabled** machine and approves the extension
   in System Settings -> General -> Login Items & Extensions, plus grants Full
   Disk Access. No license on the user's side, just an approval click. See
   `apple-request/REQUEST.md`.

Open-sourcing this code is **not** "distribution" in Apple's sense - the
entitlement is only needed to ship a *signed binary* that runs without the user
disabling SIP. Anyone can clone and run it in dev mode for free.

## Status

- [x] verdict core, unit-tested with `swiftc`
- [x] ruleset compiler (`quill esf compile`) + Python parity tests
- [x] ES client (`main.swift`), entitlements, Info.plist
- [ ] Xcode project + host app bundle (build under full Xcode)
- [ ] validate end-to-end in a SIP-disabled VM
- [ ] Apple entitlement request (submit after VM validation; see REQUEST.md)
