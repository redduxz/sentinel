import CoreWLAN
import Foundation

public protocol Watcher: Sendable {
    var name: String { get }
    var interval: TimeInterval { get }
    func poll() async -> Poll
}

/// Default watcher set - everything here works with zero root / zero entitlements.
public enum Watchers {
    public static func `default`() -> [any Watcher] {
        [WifiWatcher(), NetworkConfigWatcher(), ArpWatcher(), PortalWatcher(),
         ConnectionWatcher(), ListenerWatcher(), DeviceWatcher(), PersistenceWatcher()]
    }
}

// MARK: - Wi-Fi: SSID/BSSID tracking → evil twin + open-network warnings

public final class WifiWatcher: Watcher, @unchecked Sendable {
    public let name = "wifi"
    public let interval: TimeInterval = 15

    private var lastSsid: String?
    private var lastBssid: String?
    private var warnedOpen = false
    private var notedBssidGated = false

    public init() {}

    public func poll() async -> Poll {
        guard let iface = CWWiFiClient.shared().interface(),
              let ssid = iface.ssid() else { return Poll() }

        var snap = NetSnapshot()
        var events: [Event] = []
        snap.ssid = ssid
        snap.bssid = iface.bssid()
        snap.wifiSecurity = describe(iface.security())

        if let prev = lastSsid, prev != ssid {
            events.append(Event(kind: "wifi.network_change", severity: .notice,
                                title: "network change", detail: "\(prev) -> \(ssid)"))
        }
        if let prevBssid = lastBssid, let bssid = snap.bssid, prevBssid != bssid,
           lastSsid == ssid {
            events.append(Event(kind: "wifi.evil_twin", severity: .critical,
                                title: "possible evil twin",
                                detail: "AP radio changed on \"\(ssid)\" (\(prevBssid) -> \(bssid))"))
        }
        if iface.security() == .none && !warnedOpen {
            warnedOpen = true
            events.append(Event(kind: "wifi.open_network", severity: .warning,
                                title: "open network",
                                detail: "\"\(ssid)\" has no encryption - traffic is readable"))
        }
        if snap.bssid == nil && !notedBssidGated {
            notedBssidGated = true
            events.append(Event(kind: "wifi.bssid_gated", severity: .info,
                                title: "bssid unavailable",
                                detail: "grant location access for evil-twin detection"))
        }

        lastSsid = ssid
        lastBssid = snap.bssid
        return Poll(events: events, snapshot: snap)
    }

    private func describe(_ sec: CWSecurity) -> String {
        switch sec {
        case .none: "open"
        case .WEP: "wep"
        case .wpaPersonal, .wpaPersonalMixed: "wpa"
        case .wpa2Personal, .wpa2Enterprise, .wpaEnterprise, .wpaEnterpriseMixed: "wpa2"
        case .wpa3Personal, .wpa3Enterprise, .wpa3Transition: "wpa3"
        case .personal, .enterprise, .unknown: "secured"
        case .OWE, .oweTransition: "owe"
        case .dynamicWEP: "dynamic wep"
        @unknown default: "unknown"
        }
    }
}

// MARK: - Resolver + gateway config changes (DNS hijack surface)

public final class NetworkConfigWatcher: Watcher, @unchecked Sendable {
    public let name = "netconfig"
    public let interval: TimeInterval = 30

    private var lastResolvers: [String] = []
    private var lastGateway: String?

    public init() {}

    public func poll() async -> Poll {
        var snap = NetSnapshot()
        var events: [Event] = []

        let dnsOut = Sh.run("/usr/sbin/scutil", ["--dns"])
        let resolvers = Parse.resolvers(dnsOut)
        snap.resolvers = resolvers

        let routeOut = Sh.run("/sbin/route", ["-n", "get", "default"])
        snap.gateway = Parse.defaultGateway(routeOut)

        if !lastResolvers.isEmpty, resolvers != lastResolvers, !resolvers.isEmpty {
            events.append(Event(kind: "dns.resolver_change", severity: .warning,
                                title: "dns resolver changed",
                                detail: "\(lastResolvers.joined(separator: ", ")) -> \(resolvers.joined(separator: ", ")) - possible DNS hijack on hostile networks"))
        }
        if let gw = snap.gateway, let prev = lastGateway, gw != prev {
            events.append(Event(kind: "route.gateway_change", severity: .notice,
                                title: "default gateway changed", detail: "\(prev) -> \(gw)"))
        }

        lastResolvers = resolvers
        lastGateway = snap.gateway
        return Poll(events: events, snapshot: snap)
    }
}

// MARK: - ARP table: gateway MAC flip = ARP spoofing

public final class ArpWatcher: Watcher, @unchecked Sendable {
    public let name = "arp"
    public let interval: TimeInterval = 20

    private var lastGatewayMac: String?
    private var lastGateway: String?

    public init() {}

    public func poll() async -> Poll {
        let table = Parse.arpTable(Sh.run("/usr/sbin/arp", ["-an"]))
        let gateway = Parse.defaultGateway(Sh.run("/sbin/route", ["-n", "get", "default"]))

        var snap = NetSnapshot()
        var events: [Event] = []
        snap.gateway = gateway
        if let gw = gateway { snap.gatewayMac = table[gw] }

        if let gw = gateway, let mac = table[gw],
           let prevMac = lastGatewayMac, let prevGw = lastGateway {
            if gw == prevGw, mac != prevMac {
                events.append(Event(kind: "arp.gateway_flip", severity: .critical,
                                    title: "gateway mac changed - possible arp spoof",
                                    detail: "\(gw): \(prevMac) -> \(mac)"))
            }
        }

        lastGateway = gateway
        lastGatewayMac = snap.gatewayMac
        return Poll(events: events, snapshot: snap)
    }
}

// MARK: - Captive portal / content interception probe

public final class PortalWatcher: Watcher, @unchecked Sendable {
    public let name = "portal"
    public let interval: TimeInterval = 60

    private var wasCaptive = false

    public init() {}

    public func poll() async -> Poll {
        var snap = NetSnapshot()
        var events: [Event] = []

        var req = URLRequest(url: URL(string: "http://captive.apple.com/hotspot-detect.html")!,
                             cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                             timeoutInterval: 6)
        req.setValue("sentinel/0.1", forHTTPHeaderField: "User-Agent")

        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let body = String(data: data, encoding: .utf8) ?? ""
            let captive = !body.contains("Success")
            snap.captivePortal = captive
            if captive && !wasCaptive {
                events.append(Event(kind: "net.captive_portal", severity: .warning,
                                    title: "captive portal / interception",
                                    detail: "probe response was rewritten - login page or inline proxy ahead"))
            }
            wasCaptive = captive
        } catch {
            snap.captivePortal = false
        }
        return Poll(events: events, snapshot: snap)
    }
}

// MARK: - LAN device inventory from the ARP table

public final class DeviceWatcher: Watcher, @unchecked Sendable {
    public let name = "devices"
    public let interval: TimeInterval = 60

    private var knownMacs = Set<String>()
    private var seeded = false

    public init() {}

    public func poll() async -> Poll {
        let table = Parse.arpTable(Sh.run("/usr/sbin/arp", ["-an"]))
        let macs = Set(table.values.filter { $0 != "ff:ff:ff:ff:ff:ff" })
        let new = macs.subtracting(knownMacs)

        var snap = NetSnapshot()
        snap.deviceCount = macs.count
        var events: [Event] = []

        if seeded {
            if new.count == 1, let ip = table.first(where: { new.contains($0.value) })?.key {
                events.append(Event(kind: "lan.new_device", severity: .info,
                                    title: "new device on network",
                                    detail: "\(ip) (\(new.first!))"))
            } else if new.count > 1 {
                events.append(Event(kind: "lan.new_devices", severity: .notice,
                                    title: "\(new.count) new devices joined",
                                    detail: "busy segment - total \(macs.count) visible"))
            }
        } else {
            seeded = true
        }
        knownMacs = macs
        return Poll(events: events, snapshot: snap)
    }
}
