# Apple Endpoint Security entitlement - request package

Status: **DRAFT - do not submit yet.** Submit only after the extension is
validated end-to-end in a SIP-disabled VM (see README "Status"). This is the
research-backed sequencing: Apple's own DTS guidance is to request distribution
only "once you've confirmed the ES capability will help you create a viable
product." Requesting with nothing built risks a terse denial with no appeal.

## The honest timeline (set expectations)

The grant itself **cannot be rushed**. The request is reviewed out-of-band by a
team you cannot contact; DTS has stated plainly there is no escalation path.
Reported waits run from ~5 months to over a year. So "ASAP" means: have a
validated prototype and a complete, compelling request ready to fire, then keep
building in dev mode (SIP-off VM) while it sits in the queue. Nothing we do
speeds Apple's review; the only levers we control are completeness and not
getting denied.

## Prerequisites (do these first)

- [ ] Active **Apple Developer Program** membership ($99/yr). Loomiq LLC is the
      business entity to register under (a real legal entity helps).
- [ ] A working prototype validated in a SIP-disabled VM (proof the ES capability
      is real, not aspirational).
- [ ] A short **screen-recording demo** of the extension blocking a tamper
      attempt, to attach to the request.
- [ ] Register an **explicit App ID** with the Endpoint Security capability. This
      capability is NOT in the normal Certificates/Identifiers UI - you switch
      to **manual signing** and add it to the App ID, then download the
      provisioning profile template Apple returns after approval.

## Where to submit

The System Extension request form (behind Apple ID auth):
<https://developer.apple.com/contact/request/system-extension/>

Select the Endpoint Security client entitlement. The decision arrives by email
to the requesting Apple ID.

## Draft justification (review before sending)

> Loomiq LLC builds Quill, a developer security tool that gates the actions of
> AI coding agents (Claude Code, Cursor) on a developer's machine. The Endpoint
> Security client entitlement is required for a system extension that gates
> file-modifying syscalls (AUTH_OPEN, AUTH_UNLINK, AUTH_RENAME, AUTH_TRUNCATE)
> to protect the integrity of the guardrail's own configuration and the user's
> credentials from a compromised or prompt-injected agent. The extension makes
> deterministic, local allow/deny decisions from a precompiled ruleset, with no
> data collection or network transmission. It is distributed via Developer ID
> with notarization, not the Mac App Store. A working prototype, validated in a
> test environment, is available to demonstrate on request.

Keep every sentence in the justification factually accurate to what the
extension actually does at submission time. Do not describe capabilities that
are not built yet.

## After approval

- Download the provisioning profile template, build under Xcode with the granted
  entitlement, Developer ID sign + notarize.
- Ship inside a host `.app` bundle (a bare executable does not appear in the Full
  Disk Access UI).
- The user approves in System Settings; MDM is only needed to pre-approve fleets.

## When NOT to bother

If Quill's strategy stays "Seatbelt floor for everyone + ESF as an opt-in,
open-source, dev-mode layer," the entitlement is **not needed**: open-sourcing
the code requires nothing from Apple, and researchers run it in dev mode. The
entitlement is only worth the multi-month queue once there is real demand to
ship a turnkey signed binary to non-technical users on SIP-enabled machines.
