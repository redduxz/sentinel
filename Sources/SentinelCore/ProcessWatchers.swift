import Foundation

// MARK: - Outbound connections per process (lsof diff)

public final class ConnectionWatcher: Watcher, @unchecked Sendable {
    public let name = "connections"
    public let interval: TimeInterval = 10

    private var seen = Set<Parse.Conn>()
    private var seeded = false

    public init() {}

    public func poll() async -> Poll {
        // established TCP + bound UDP - this machine's view of who's talking
        let out = Sh.run("/usr/sbin/lsof",
                         ["-nP", "-iTCP", "-sTCP:ESTABLISHED,SYN_SENT", "-iUDP"])
        let current = Set(Parse.conns(out).filter { $0.node.contains("->") || $0.node.contains("*:") })
        let new = current.subtracting(seen)

        var events: [Event] = []
        if seeded, !new.isEmpty {
            if new.count <= 4 {
                for c in new {
                    events.append(Event(kind: "proc.new_conn", severity: .info,
                                        title: "new connection",
                                        detail: "\(c.proc) -> \(c.node.replacingOccurrences(of: "->", with: " → "))"))
                }
            } else {
                let procs = new.map(\.proc)
                let counts = Dictionary(grouping: procs, by: { $0 }).mapValues(\.count)
                let summary = counts.sorted { $0.value > $1.value }
                    .prefix(4).map { "\($0.key) ×\($0.value)" }.joined(separator: ", ")
                events.append(Event(kind: "proc.conn_burst", severity: .notice,
                                    title: "\(new.count) new connections", detail: summary))
            }
        } else if !seeded {
            seeded = true
        }
        seen = current
        return Poll(events: events)
    }
}

// MARK: - New listening services

public final class ListenerWatcher: Watcher, @unchecked Sendable {
    public let name = "listeners"
    public let interval: TimeInterval = 15

    private var seen = Set<Parse.Conn>()
    private var seeded = false

    public init() {}

    public func poll() async -> Poll {
        let tcp = Sh.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"])
        let current = Set(Parse.conns(tcp))

        var snap = NetSnapshot()
        snap.listenerCount = current.count
        var events: [Event] = []

        let new = current.subtracting(seen)
        if seeded {
            for c in new {
                events.append(Event(kind: "proc.new_listener", severity: .warning,
                                    title: "new listening service",
                                    detail: "\(c.proc) is now listening on \(c.node)"))
            }
        } else {
            seeded = true
        }
        seen = current
        return Poll(events: events, snapshot: snap)
    }
}

// MARK: - Persistence locations (launchd dirs)

public final class PersistenceWatcher: Watcher, @unchecked Sendable {
    public let name = "persistence"
    public let interval: TimeInterval = 60

    private let dirs = [
        ("LaunchAgents", NSHomeDirectory() + "/Library/LaunchAgents"),
        ("LaunchAgents (system)", "/Library/LaunchAgents"),
        ("LaunchDaemons", "/Library/LaunchDaemons"),
        ("PrivilegedHelpers", "/Library/PrivilegedHelperTools"),
    ]
    private var state: [String: [String: Date]] = [:]
    private var seeded = false

    public init() {}

    public func poll() async -> Poll {
        var events: [Event] = []
        for (label, path) in dirs {
            let now = Parse.dirState(URL(fileURLWithPath: path))
            guard let prev = state[label] else {
                state[label] = now
                continue
            }
            for name in now.keys where prev[name] == nil && seeded {
                events.append(Event(kind: "persist.new_item", severity: .warning,
                                    title: "new \(label) item",
                                    detail: name))
            }
            for (name, mtime) in now where prev[name] != nil && prev[name]! < mtime && seeded {
                events.append(Event(kind: "persist.modified", severity: .notice,
                                    title: "modified \(label) item", detail: name))
            }
            state[label] = now
        }
        if !seeded { seeded = true }
        return Poll(events: events)
    }
}
