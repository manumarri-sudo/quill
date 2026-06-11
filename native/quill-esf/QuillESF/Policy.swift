// Policy.swift - the Foundation shell around the pure PolicyCore.
//
// This file decodes the ruleset JSON (produced by `quill esf compile`) and
// resolves symlinks to canonical paths, then delegates every verdict to
// PolicyCore (Foundation-free). Foundation lives ONLY here, off the pure
// decision path. Builds under Xcode / a matched toolchain; the verdict logic
// it wraps is tested independently via PolicyCore + bare swiftc.

import Foundation

struct QuillRuleset: Decodable {
    var version: Int
    var failClosed: Bool
    var protectedFiles: [String]
    var protectedPrefixes: [String]

    enum CodingKeys: String, CodingKey {
        case version
        case failClosed = "fail_closed"
        case protectedFiles = "protected_files"
        case protectedPrefixes = "protected_prefixes"
    }
}

struct PolicyEngine {
    let core: PolicyCore

    init(ruleset: QuillRuleset) {
        self.core = PolicyCore(
            protectedFiles: ruleset.protectedFiles,
            protectedPrefixes: ruleset.protectedPrefixes,
            failClosed: ruleset.failClosed
        )
    }

    static func load(path: String) throws -> PolicyEngine {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let rs = try JSONDecoder().decode(QuillRuleset.self, from: data)
        return PolicyEngine(ruleset: rs)
    }

    /// Resolve symlinks so matching is on canonical paths, mirroring the Python
    /// renderer's os.path.realpath. SEAM: NSString.resolvingSymlinksInPath and
    /// realpath can diverge for paths whose final component does not exist
    /// (config.toml / key often don't exist yet); validate in the Xcode/VM phase.
    func canonical(_ path: String) -> String {
        return (path as NSString).resolvingSymlinksInPath
    }

    func decideFileWrite(_ path: String) -> Verdict {
        return core.decideFileWrite(canonicalPath: canonical(path))
    }
}
