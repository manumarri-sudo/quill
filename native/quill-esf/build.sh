#!/usr/bin/env bash
# Build / test the Quill Endpoint Security extension.
#
# Two targets:
#   test  - compile + run the Foundation-free verdict core with bare swiftc.
#           Works WITHOUT Xcode or the ES entitlement. This is the unit-test
#           gate that runs in CI and on any dev machine.
#   sysext - build the full system extension. Requires FULL XCODE (the
#           EndpointSecurity framework is not in the Command Line Tools SDK)
#           and, to actually RUN it, either Apple's granted entitlement on a
#           SIP-enabled machine, or a SIP-disabled VM with an ad-hoc signature
#           (see README.md and apple-request/REQUEST.md).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build

case "${1:-test}" in
  test)
    echo "==> compiling Foundation-free verdict core + tests"
    xcrun swiftc \
      QuillESF/PolicyCore.swift \
      tests/PolicyTests.swift \
      -o build/policytests
    echo "==> running"
    ./build/policytests
    ;;
  sysext)
    echo "==> building system extension (requires full Xcode)"
    if ! xcode-select -p | grep -q "Xcode.app"; then
      echo "ERROR: full Xcode required (EndpointSecurity.framework absent from CLT SDK)." >&2
      echo "Install Xcode, then: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer" >&2
      exit 1
    fi
    # The system extension is built and embedded in a host .app via an Xcode
    # project; this placeholder shows the codesign step once that exists.
    echo "Build the QuillESF target in Xcode, then sign with the ES entitlement:" >&2
    echo "  codesign --force --options runtime \\" >&2
    echo "    --entitlements QuillESF/QuillESF.entitlements \\" >&2
    echo "    --sign \"Developer ID Application: <YOUR TEAM>\" build/QuillESF.systemextension" >&2
    ;;
  *)
    echo "usage: $0 [test|sysext]" >&2
    exit 2
    ;;
esac
