// main.swift - Quill's Endpoint Security system-extension entry point.
//
// This is the ES plumbing. It imports EndpointSecurity, which ships only with
// full Xcode, so this file builds under Xcode (or a matched toolchain in a
// SIP-disabled VM), NOT with the bare Command Line Tools. The verdict logic it
// calls (PolicyCore) is Foundation-free and unit-tested separately, so the
// deadline-critical auth path carries zero framework or IPC dependencies.
//
// Architecture mirrors Santa / Sinter (from the research):
//   - one es_new_client subscribed to file AUTH events
//   - rules loaded out-of-band from ~/.quill/esf-rules.json (quill esf compile)
//   - the per-event verdict is an O(1) set lookup with no IO / IPC / signature
//     check, so the client responds INLINE well within the kernel deadline;
//     there is no slow path here that would need an async watchdog timer
//   - the client mutes its own binary to avoid auth re-entrancy
//
// Honest limits (see README): ES emits no network-connect AUTH event, so this
// does NOT gate egress (that is the Seatbelt floor's / a Network Extension's
// job). This layer's value is ALWAYS-ON protection of the gate-disable surface
// at the syscall, even for an agent not launched under `quill shell`.

import EndpointSecurity
import Foundation

let rulesPath = ("~/.quill/esf-rules.json" as NSString).expandingTildeInPath

guard let engine = try? PolicyEngine.load(path: rulesPath) else {
    FileHandle.standardError.write("quill-esf: cannot load ruleset at \(rulesPath); run `quill esf compile`\n".data(using: .utf8)!)
    exit(1)
}
let failClosed = engine.core.failClosed

// File AUTH events we gate. AUTH_OPEN is a flags-result event; the unlink /
// rename / truncate trio are bool-result events.
let subscriptions: [es_event_type_t] = [
    ES_EVENT_TYPE_AUTH_OPEN,
    ES_EVENT_TYPE_AUTH_UNLINK,
    ES_EVENT_TYPE_AUTH_RENAME,
    ES_EVENT_TYPE_AUTH_TRUNCATE,
]

func pathFromToken(_ t: es_string_token_t) -> String {
    return String(cString: t.data)
}

// Paths a file AUTH event would modify; deny if ANY is protected. For RENAME
// we must check the DESTINATION (the overwrite target), not just the source,
// or `mv evil.json ~/.claude/settings.json` would slip through on the
// unprotected source path.
func targetPaths(_ msg: UnsafePointer<es_message_t>) -> [String] {
    switch msg.pointee.event_type {
    case ES_EVENT_TYPE_AUTH_OPEN:
        return [pathFromToken(msg.pointee.event.open.file.pointee.path)]
    case ES_EVENT_TYPE_AUTH_UNLINK:
        return [pathFromToken(msg.pointee.event.unlink.target.pointee.path)]
    case ES_EVENT_TYPE_AUTH_TRUNCATE:
        return [pathFromToken(msg.pointee.event.truncate.target.pointee.path)]
    case ES_EVENT_TYPE_AUTH_RENAME:
        let rename = msg.pointee.event.rename
        var paths = [pathFromToken(rename.source.pointee.path)]
        if rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
            paths.append(pathFromToken(rename.destination.existing_file.pointee.path))
        } else {
            let dir = pathFromToken(rename.destination.new_path.dir.pointee.path)
            let name = pathFromToken(rename.destination.new_path.filename)
            paths.append(dir + "/" + name)
        }
        return paths
    default:
        return []
    }
}

var client: OpaquePointer?
let res = es_new_client(&client) { (clientPtr, msgPtr) in
    let msg = msgPtr

    // O(1) verdict: deny if ANY modified path is protected. No IO on this
    // path, so we respond inline well within the kernel deadline.
    let paths = targetPaths(msg)
    let allow = !paths.contains { engine.decideFileWrite($0) == .deny }

    switch msg.pointee.event_type {
    case ES_EVENT_TYPE_AUTH_OPEN:
        // Flags-result: full access mask if allowed, 0 to deny all access.
        let authorized: UInt32 = allow ? 0xffffffff : 0
        es_respond_flags_result(clientPtr, msg, authorized, false)
    default:
        let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        es_respond_auth_result(clientPtr, msg, result, false)
    }
}

guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client = client else {
    let why: String
    switch res {
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        why = "not entitled (need com.apple.developer.endpoint-security.client; dev: SIP off + ad-hoc sign)"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        why = "not permitted (grant Full Disk Access to this extension in System Settings)"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        why = "not privileged (must run as root)"
    default:
        why = "es_new_client failed: \(res)"
    }
    FileHandle.standardError.write("quill-esf: \(why)\n".data(using: .utf8)!)
    exit(1)
}

// Mute our own binary so reading the ruleset etc. cannot deadlock on our own
// AUTH_OPEN handler.
let selfPath = CommandLine.arguments[0]
selfPath.withCString { cstr in
    var token = es_string_token_t(length: strlen(cstr), data: cstr)
    es_mute_path(client, &token, ES_MUTE_PATH_TYPE_LITERAL)
}

guard es_subscribe(client, subscriptions, UInt32(subscriptions.count)) == ES_RETURN_SUCCESS else {
    FileHandle.standardError.write("quill-esf: es_subscribe failed\n".data(using: .utf8)!)
    exit(1)
}

FileHandle.standardError.write("quill-esf: online, gating \(subscriptions.count) file AUTH events (fail_closed=\(failClosed))\n".data(using: .utf8)!)
dispatchMain()
