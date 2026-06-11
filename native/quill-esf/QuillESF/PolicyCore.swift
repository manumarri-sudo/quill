// PolicyCore.swift - the pure verdict logic for Quill's ES extension.
//
// DELIBERATELY Foundation-free (Swift stdlib only): the deadline-critical ES
// auth path must have zero framework or IPC dependencies, and keeping it pure
// also lets it compile and unit-test with bare `swiftc` on a machine without
// full Xcode. Policy.swift is the thin Foundation shell that decodes JSON and
// resolves symlinks, then hands canonical paths to this core.

enum Verdict: Equatable {
    case allow
    case deny
}

struct PolicyCore {
    let protectedFiles: Set<String>
    let protectedPrefixes: [String]
    let failClosed: Bool

    init(protectedFiles: [String], protectedPrefixes: [String], failClosed: Bool = true) {
        self.protectedFiles = Set(protectedFiles)
        self.protectedPrefixes = protectedPrefixes
        self.failClosed = failClosed
    }

    /// `c` must already be symlink-resolved by the caller (Policy.canonical).
    func isProtected(canonicalPath c: String) -> Bool {
        if protectedFiles.contains(c) { return true }
        for pre in protectedPrefixes {
            let prefix = pre.hasSuffix("/") ? pre : pre + "/"
            if c == pre || c.hasPrefix(prefix) { return true }
        }
        return false
    }

    /// Verdict for an AUTH_OPEN(write) / AUTH_UNLINK / AUTH_RENAME /
    /// AUTH_TRUNCATE event on the (already canonical) path.
    func decideFileWrite(canonicalPath c: String) -> Verdict {
        return isProtected(canonicalPath: c) ? .deny : .allow
    }
}
