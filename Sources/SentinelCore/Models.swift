import Foundation

public enum Severity: String, Sendable, Comparable, CaseIterable {
    case info, notice, warning, critical

    public static func < (a: Severity, b: Severity) -> Bool {
        a.rank < b.rank
    }

    private var rank: Int { Self.allCases.firstIndex(of: self)! }
}

public enum Status: String, Sendable {
    case ok = "protected"
    case watch = "attention"
    case alert = "alert"
}

public struct Event: Identifiable, Sendable {
    public let id = UUID()
    public let ts = Date()
    public let kind: String
    public let severity: Severity
    public let title: String
    public let detail: String

    public init(kind: String, severity: Severity, title: String, detail: String = "") {
        self.kind = kind
        self.severity = severity
        self.title = title
        self.detail = detail
    }
}

/// Rolling view of the network the Mac is attached to — what the header card shows.
public struct NetSnapshot: Sendable {
    public var ssid: String?
    public var bssid: String?
    public var wifiSecurity: String?
    public var gateway: String?
    public var gatewayMac: String?
    public var resolvers: [String] = []
    public var deviceCount = 0
    public var listenerCount = 0
    public var captivePortal = false

    public init() {}

    mutating func merge(_ other: NetSnapshot?) {
        guard let o = other else { return }
        if let v = o.ssid { ssid = v }
        if let v = o.bssid { bssid = v }
        if let v = o.wifiSecurity { wifiSecurity = v }
        if let v = o.gateway { gateway = v }
        if let v = o.gatewayMac { gatewayMac = v }
        if !o.resolvers.isEmpty { resolvers = o.resolvers }
        if o.deviceCount > 0 { deviceCount = o.deviceCount }
        if o.listenerCount > 0 { listenerCount = o.listenerCount }
        captivePortal = o.captivePortal
    }
}

/// One watch cycle's output: zero+ events plus an optional partial snapshot.
public struct Poll: Sendable {
    public var events: [Event]
    public var snapshot: NetSnapshot?

    public init(events: [Event] = [], snapshot: NetSnapshot? = nil) {
        self.events = events
        self.snapshot = snapshot
    }
}
