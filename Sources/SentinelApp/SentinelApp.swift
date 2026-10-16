import AppKit
import SentinelCore
import SwiftUI

@main
struct SentinelApp: App {
    @StateObject private var monitor = Monitor()

    init() {
        NSApplication.shared.setActivationPolicy(.accessory)
        monitor.start()
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(monitor: monitor)
        } label: {
            Image(systemName: iconName)
        }
        .menuBarExtraStyle(.window)
    }

    private var iconName: String {
        switch monitor.status {
        case .ok: "shield.fill"
        case .watch: "shield.lefthalf.filled"
        case .alert: "exclamationmark.shield.fill"
        }
    }
}
