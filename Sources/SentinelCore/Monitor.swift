import Foundation

/// Aggregates all watchers: owns the event buffer, network snapshot, and the
/// rolled-up status that drives the menu bar icon.
@MainActor
public final class Monitor: ObservableObject {
    @Published public private(set) var events: [Event] = []
    @Published public private(set) var snapshot = NetSnapshot()
    @Published public private(set) var status: Status = .ok
    @Published public var paused = false

    private let watchers: [any Watcher]
    private var tasks: [Task<Void, Never>] = []
    private let maxEvents = 300

    /// How far back status looks - a critical event clears after this window.
    private let statusWindows: [Severity: TimeInterval] = [
        .critical: 300, .warning: 600,
    ]

    public init(watchers: [any Watcher] = Watchers.default()) {
        self.watchers = watchers
    }

    public func start() {
        stop()
        for w in watchers {
            tasks.append(Task.detached { [weak self] in
                while !Task.isCancelled {
                    if await self?.paused == true {
                        try? await Task.sleep(for: .seconds(2))
                        continue
                    }
                    let poll = await w.poll()
                    await self?.ingest(poll)
                    try? await Task.sleep(for: .seconds(w.interval))
                }
            })
        }
    }

    public func stop() {
        tasks.forEach { $0.cancel() }
        tasks.removeAll()
    }

    public func rescan() {
        for w in watchers {
            Task.detached { [weak self] in
                let poll = await w.poll()
                await self?.ingest(poll)
            }
        }
    }

    public func clearEvents() { events.removeAll() }

    private func ingest(_ poll: Poll) {
        if let snap = poll.snapshot { snapshot.merge(snap) }
        if !poll.events.isEmpty {
            events = Array((poll.events + events).prefix(maxEvents))
        }
        let now = Date()
        let recent = events.filter { now.timeIntervalSince($0.ts) < (statusWindows[$0.severity] ?? 0) }
        let worst = recent.max { $0.severity < $1.severity }?.severity ?? .info
        status = worst >= .critical ? .alert : worst >= .warning ? .watch : .ok
    }
}
