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
        VStack(alignment: .leading, spacing: 10) {
            header
            networkCard
            Picker("", selection: $tab) {
                Text("detections").tag(0)
                Text("activity").tag(1)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .controlSize(.small)

            if tab == 0 { detections } else { activity }
            footer
        }
        .padding(12)
        .frame(width: 340)
        .background(.ultraThinMaterial)
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 7) {
            Image(systemName: "shield.fill")
                .font(.system(size: 12))
            Text("sentinel")
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
            statusPill
            Spacer()
            Button { monitor.paused.toggle() } label: {
                Image(systemName: monitor.paused ? "play.fill" : "pause.fill")
                    .font(.system(size: 10))
            }
            .buttonStyle(.plain).foregroundStyle(.secondary)
            .help(monitor.paused ? "resume" : "pause monitoring")
            Button { NSApplication.shared.terminate(nil) } label: {
                Image(systemName: "power")
                    .font(.system(size: 10))
            }
            .buttonStyle(.plain).foregroundStyle(.secondary)
            .help("quit")
        }
    }

    private var statusPill: some View {
        Text(monitor.status.rawValue)
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .textCase(.uppercase)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(pillColor.opacity(0.16), in: Capsule())
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
        return VStack(alignment: .leading, spacing: 5) {
            row("network", s.ssid.map { "\($0) · \(s.wifiSecurity ?? "")" } ?? "no wi-fi")
            Divider().opacity(0.4)
            row("gateway", [s.gateway, s.gatewayMac].compactMap { $0 }.joined(separator: "  "))
            Divider().opacity(0.4)
            row("dns", s.resolvers.isEmpty ? "—" : s.resolvers.joined(separator: ", "))
            Divider().opacity(0.4)
            row("devices", "\(s.deviceCount) seen · \(s.listenerCount) listeners")
            if s.captivePortal {
                Divider().opacity(0.4)
                Label("captive portal detected", systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 10)).foregroundStyle(.yellow)
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack(spacing: 0) {
            Text(k)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .frame(width: 52, alignment: .leading)
            Text(v.isEmpty ? "—" : v)
                .font(.system(size: 10, design: .monospaced))
                .lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 0)
        }
    }

    // MARK: detections / activity

    private var detections: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 7) {
                if monitor.events.isEmpty {
                    Text("nothing flagged yet")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.vertical, 18)
                }
                ForEach(monitor.events.prefix(10)) { e in
                    HStack(alignment: .top, spacing: 7) {
                        Circle().fill(dotColor(e.severity))
                            .frame(width: 5, height: 5).padding(.top, 4)
                        VStack(alignment: .leading, spacing: 1) {
                            HStack {
                                Text(e.title)
                                    .font(.system(size: 10, weight: .medium))
                                Spacer(minLength: 4)
                                Text(Self.rel.localizedString(for: e.ts, relativeTo: Date()))
                                    .font(.system(size: 9))
                                    .foregroundStyle(.tertiary)
                            }
                            if !e.detail.isEmpty {
                                Text(e.detail)
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundStyle(.secondary).lineLimit(2)
                            }
                        }
                    }
                }
            }
        }
        .scrollIndicators(.hidden)
        .frame(maxHeight: 200)
    }

    private var activity: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 5) {
                if monitor.events.allSatisfy({ !$0.kind.hasPrefix("proc.") }) {
                    Text("no connection activity yet")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity).padding(.vertical, 18)
                }
                ForEach(monitor.events.filter { $0.kind.hasPrefix("proc.") }.prefix(14)) { e in
                    HStack {
                        Text(e.detail)
                            .font(.system(size: 9, design: .monospaced))
                            .lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 4)
                        Text(Self.rel.localizedString(for: e.ts, relativeTo: Date()))
                            .font(.system(size: 9)).foregroundStyle(.tertiary)
                    }
                }
            }
        }
        .scrollIndicators(.hidden)
        .frame(maxHeight: 200)
    }

    private func dotColor(_ s: Severity) -> Color {
        switch s {
        case .info: .secondary.opacity(0.35)
        case .notice: .primary
        case .warning: .yellow
        case .critical: .red
        }
    }

    // MARK: footer

    private var footer: some View {
        HStack {
            Button("rescan") { monitor.rescan() }
                .buttonStyle(.plain).font(.system(size: 10))
                .foregroundStyle(.secondary)
            Spacer()
            if monitor.paused {
                Text("paused").font(.system(size: 9)).foregroundStyle(.yellow)
            }
            Button("clear") { monitor.clearEvents() }
                .buttonStyle(.plain).font(.system(size: 10))
                .foregroundStyle(.secondary)
        }
    }
}
