import AppKit
import SentinelCore
import SwiftUI

struct MenuBarView: View {
    @ObservedObject var monitor: Monitor
    @State private var tab = 0

    private static let rel: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            networkCard
            Picker("", selection: $tab) {
                Text("detections").tag(0)
                Text("activity").tag(1)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            if tab == 0 { detections } else { activity }
            footer
        }
        .padding(14)
        .frame(width: 380)
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: "shield.fill")
            Text("sentinel").font(.system(.headline, design: .monospaced))
            statusPill
            Spacer()
            Button { monitor.paused.toggle() } label: {
                Image(systemName: monitor.paused ? "play.fill" : "pause.fill")
            }
            .buttonStyle(.borderless)
            .help(monitor.paused ? "resume" : "pause monitoring")
            Button { NSApplication.shared.terminate(nil) } label: {
                Image(systemName: "power")
            }
            .buttonStyle(.borderless)
            .help("quit")
        }
    }

    private var statusPill: some View {
        Text(monitor.status.rawValue)
            .font(.system(size: 10, weight: .semibold, design: .monospaced))
            .textCase(.uppercase)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(pillColor.opacity(0.18), in: Capsule())
            .foregroundStyle(pillColor)
    }

    private var pillColor: Color {
        switch monitor.status {
        case .ok: .secondary
        case .watch: .yellow
        case .alert: .red
        }
    }

    // MARK: network card

    private var networkCard: some View {
        let s = monitor.snapshot
        return VStack(alignment: .leading, spacing: 6) {
            row("network", s.ssid.map { "\($0) · \(s.wifiSecurity ?? "")" } ?? "no wi-fi")
            row("gateway", [s.gateway, s.gatewayMac].compactMap { $0 }.joined(separator: "  "))
            row("dns", s.resolvers.isEmpty ? "—" : s.resolvers.joined(separator: ", "))
            row("devices", "\(s.deviceCount) seen · \(s.listenerCount) listeners")
            if s.captivePortal {
                Label("captive portal detected", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.yellow)
            }
        }
        .padding(10)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).font(.caption).foregroundStyle(.secondary)
                .frame(width: 56, alignment: .leading)
            Text(v.isEmpty ? "—" : v).font(.system(.caption, design: .monospaced))
                .lineLimit(1).truncationMode(.middle)
            Spacer()
        }
    }

    // MARK: detections / activity

    private var detections: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                if monitor.events.isEmpty {
                    Text("nothing flagged yet")
                        .font(.caption).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.vertical, 20)
                }
                ForEach(monitor.events.prefix(10)) { e in
                    HStack(alignment: .top, spacing: 8) {
                        Circle().fill(dotColor(e.severity))
                            .frame(width: 6, height: 6).padding(.top, 5)
                        VStack(alignment: .leading, spacing: 1) {
                            HStack {
                                Text(e.title).font(.caption.weight(.medium))
                                Spacer()
                                Text(Self.rel.localizedString(for: e.ts, relativeTo: Date()))
                                    .font(.caption2).foregroundStyle(.tertiary)
                            }
                            if !e.detail.isEmpty {
                                Text(e.detail).font(.caption2)
                                    .foregroundStyle(.secondary).lineLimit(2)
                            }
                        }
                    }
                }
            }
        }
        .frame(maxHeight: 220)
    }

    private var activity: some View {
        // most recent connection-type events, compact
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(monitor.events.filter { $0.kind.hasPrefix("proc.") }.prefix(12)) { e in
                    HStack {
                        Text(e.detail).font(.system(.caption2, design: .monospaced))
                            .lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text(Self.rel.localizedString(for: e.ts, relativeTo: Date()))
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                if monitor.events.allSatisfy({ !$0.kind.hasPrefix("proc.") }) {
                    Text("no connection activity yet")
                        .font(.caption).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity).padding(.vertical, 20)
                }
            }
        }
        .frame(maxHeight: 220)
    }

    private func dotColor(_ s: Severity) -> Color {
        switch s {
        case .info: .secondary.opacity(0.4)
        case .notice: .primary
        case .warning: .yellow
        case .critical: .red
        }
    }

    // MARK: footer

    private var footer: some View {
        HStack {
            Button("rescan") { monitor.rescan() }
                .buttonStyle(.borderless).font(.caption)
            Spacer()
            if monitor.paused {
                Text("paused").font(.caption2).foregroundStyle(.yellow)
            }
            Button("clear") { monitor.clearEvents() }
                .buttonStyle(.borderless).font(.caption)
        }
    }
}
