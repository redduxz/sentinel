import Foundation

/// Pure parsers for command output - kept side-effect free so tests can feed fixtures.
public enum Parse {

    public struct Conn: Hashable, Sendable {
        public let pid: Int
        public let proc: String
        public let node: String
    }

    /// `arp -an` -> [ip: mac]
    public static func arpTable(_ out: String) -> [String: String] {
        var table: [String: String] = [:]
        for line in out.split(separator: "\n") {
            let f = line.split(separator: " ")
            guard f.count >= 4,
                  let lparen = f.firstIndex(where: { $0.hasPrefix("(") }),
                  let at = f.firstIndex(of: "at") else { continue }
            let ip = f[lparen].trimmingCharacters(in: CharacterSet(charactersIn: "()"))
            let mac = String(f[at + 1])
            if mac != "(incomplete)" && mac.contains(":") { table[ip] = mac }
        }
        return table
    }

    /// `route -n get default` -> gateway address
    public static func defaultGateway(_ out: String) -> String? {
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("gateway:") {
                return t.dropFirst("gateway:".count).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// `scutil --dns` -> unique resolver addresses, first-seen order
    public static func resolvers(_ out: String) -> [String] {
        var seen = Set<String>()
        var list: [String] = []
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard t.hasPrefix("nameserver["), let colon = t.lastIndex(of: ":") else { continue }
            let ip = String(t[t.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if seen.insert(ip).inserted { list.append(ip) }
        }
        return list
    }

    /// `lsof -nP -iTCP -iUDP` -> established connections / bound sockets
    public static func conns(_ out: String) -> [Conn] {
        out.split(separator: "\n").compactMap { line in
            let f = line.split(separator: " ", omittingEmptySubsequences: true)
            // NAME is column 8 - a trailing "(STATE)" may follow it
            guard f.count >= 9, let pid = Int(f[1]) else { return nil }
            let node = String(f[8])
            return Conn(pid: pid, proc: String(f[0]), node: node)
        }
    }

    /// Snapshot of a directory: name -> mtime (cheap change detection).
    public static func dirState(_ url: URL) -> [String: Date] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: url.path) else {
            return [:]
        }
        var state: [String: Date] = [:]
        for name in names {
            let full = url.appendingPathComponent(name).path
            if let attr = try? FileManager.default.attributesOfItem(atPath: full),
               let mtime = attr[.modificationDate] as? Date {
                state[name] = mtime
            }
        }
        return state
    }
}
