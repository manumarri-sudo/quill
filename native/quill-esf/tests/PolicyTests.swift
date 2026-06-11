// PolicyTests.swift - runnable with bare swiftc (no Xcode, no Foundation):
//   swiftc QuillESF/PolicyCore.swift tests/PolicyTests.swift -o build/policytests
//   ./build/policytests
//
// Tests the Foundation-free verdict core. JSON decode and symlink
// canonicalization (Policy.swift) are exercised in the Xcode build;
// path-protection PARITY with the Python reference is covered by tests/test_esf.py.

@main
enum PolicyTests {
    static var failures = 0

    static func check(_ cond: Bool, _ msg: String) {
        if cond {
            print("ok   - \(msg)")
        } else {
            failures += 1
            print("FAIL - \(msg)")
        }
    }

    static func main() {
        let core = PolicyCore(
            protectedFiles: [
                "/Users/x/.quill/config.toml",
                "/Users/x/.quill/key",
                "/Users/x/.claude/settings.json",
            ],
            protectedPrefixes: ["/Users/x/.claude/hooks", "/Users/x/Library/LaunchAgents"]
        )

        check(core.decideFileWrite(canonicalPath: "/Users/x/.quill/config.toml") == .deny, "gate config write denied")
        check(core.decideFileWrite(canonicalPath: "/Users/x/.quill/key") == .deny, "hmac key write denied")
        check(core.decideFileWrite(canonicalPath: "/Users/x/.claude/settings.json") == .deny, "host settings write denied")
        check(core.decideFileWrite(canonicalPath: "/Users/x/.claude/hooks/pre-bash-firewall.sh") == .deny, "hook script write denied (A2)")
        check(core.decideFileWrite(canonicalPath: "/Users/x/Library/LaunchAgents/evil.plist") == .deny, "launch agent write denied (persistence)")
        check(core.decideFileWrite(canonicalPath: "/Users/x/project/main.py") == .allow, "project file write allowed")
        check(core.decideFileWrite(canonicalPath: "/Users/x/.quill/audit.log.jsonl") == .allow, "audit log write allowed (hook must log)")
        check(core.decideFileWrite(canonicalPath: "/Users/x/.claude/hooks-backup/x") == .allow, "prefix boundary respected")

        if failures == 0 {
            print("\nALL SWIFT POLICY TESTS PASSED")
        } else {
            print("\n\(failures) SWIFT TEST(S) FAILED")
        }
    }
}
