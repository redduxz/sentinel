import Foundation

/// Minimal shell-out helper - every watcher is just polling system tools.
public enum Sh {
    @discardableResult
    public static func run(_ cmd: String, _ args: [String] = [], timeout: TimeInterval = 8) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cmd)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return "" }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if p.isRunning {
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                if p.isRunning { p.terminate() }
            }
        }
        p.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
