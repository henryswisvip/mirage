import Foundation

/// Drives the bundled `mirage` binary as a local SOCKS5 proxy and (optionally)
/// toggles the macOS system SOCKS proxy.
@MainActor
final class ProxyController: ObservableObject {
    @Published var isConnected = false
    @Published var isBusy = false
    @Published var statusText = "Disconnected"
    @Published var log = ""
    @Published var listenPort: Int = 1080
    /// The network service the system-proxy toggle applies to (usually "Wi-Fi").
    @Published var networkService = "Wi-Fi"

    private var process: Process?
    private var pipe: Pipe?

    struct ParsedLink { let key, host: String; let port: Int }

    /// Validate a `mirage://KEY@HOST:PORT` link.
    static func parse(_ raw: String) -> ParsedLink? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.hasPrefix("mirage://") else { return nil }
        let rest = String(s.dropFirst("mirage://".count))
        guard let at = rest.firstIndex(of: "@") else { return nil }
        let key = String(rest[..<at])
        let hostPort = String(rest[rest.index(after: at)...])
        guard let colon = hostPort.lastIndex(of: ":") else { return nil }
        let host = String(hostPort[..<colon])
        let portStr = String(hostPort[hostPort.index(after: colon)...])
        guard !key.isEmpty, !host.isEmpty,
              let port = Int(portStr), (1...65535).contains(port) else { return nil }
        return ParsedLink(key: key, host: host, port: port)
    }

    // MARK: - Connection lifecycle

    func connect(link: String, setSystemProxy: Bool) {
        guard !isConnected, !isBusy else { return }
        guard ProxyController.parse(link) != nil else {
            statusText = "Invalid link"
            append("Error: link must look like mirage://KEY@HOST:PORT\n")
            return
        }
        isBusy = true
        statusText = "Connecting…"
        do {
            let bin = try stagedBinary()
            let proc = Process()
            proc.executableURL = bin
            proc.arguments = ["client",
                              "-listen", "127.0.0.1:\(listenPort)",
                              "-link", link.trimmingCharacters(in: .whitespacesAndNewlines)]
            let outPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = outPipe
            outPipe.fileHandleForReading.readabilityHandler = { [weak self] h in
                let data = h.availableData
                guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
                Task { @MainActor in self?.append(text) }
            }
            proc.terminationHandler = { [weak self] _ in
                Task { @MainActor in self?.onExit() }
            }
            try proc.run()
            process = proc
            pipe = outPipe
            isConnected = true
            isBusy = false
            statusText = "Connected · SOCKS5 at 127.0.0.1:\(listenPort)"
            append("mirage client started on 127.0.0.1:\(listenPort)\n")
            if setSystemProxy { setSystemProxyState(on: true) }
        } catch {
            isBusy = false
            statusText = "Failed to start"
            append("Error: \(error.localizedDescription)\n")
        }
    }

    func disconnect(unsetSystemProxy: Bool) {
        if unsetSystemProxy { setSystemProxyState(on: false) }
        process?.terminate()
        process = nil
        isConnected = false
        statusText = "Disconnected"
    }

    private func onExit() {
        pipe?.fileHandleForReading.readabilityHandler = nil
        process = nil
        if isConnected {
            isConnected = false
            statusText = "Disconnected (tunnel exited)"
            append("mirage client exited.\n")
        }
    }

    // MARK: - Binary staging

    /// Copy the bundled binary to Application Support and mark it executable.
    /// Running from a writable, chmod-ed copy avoids any bundle-permission or
    /// quarantine issues with executing a resource in place.
    private func stagedBinary() throws -> URL {
        guard let bundled = Bundle.main.url(forResource: "mirage", withExtension: nil) else {
            throw err("Bundled 'mirage' binary is missing from the app.")
        }
        let fm = FileManager.default
        let dir = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                             appropriateFor: nil, create: true)
            .appendingPathComponent("MirageGUI", isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let dest = dir.appendingPathComponent("mirage")
        if fm.fileExists(atPath: dest.path) { try? fm.removeItem(at: dest) }
        try fm.copyItem(at: bundled, to: dest)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dest.path)
        return dest
    }

    // MARK: - System proxy (needs admin; prompts via osascript)

    func setSystemProxyState(on: Bool) {
        let svc = networkService
        let cmd = on
            ? "networksetup -setsocksfirewallproxy \(shellQuote(svc)) 127.0.0.1 \(listenPort) && networksetup -setsocksfirewallproxystate \(shellQuote(svc)) on"
            : "networksetup -setsocksfirewallproxystate \(shellQuote(svc)) off"
        let script = "do shell script \"\(cmd.replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"
        var errInfo: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&errInfo)
        if let e = errInfo {
            append("System proxy \(on ? "enable" : "disable") failed: \(e[NSAppleScript.errorMessage] ?? "unknown")\n")
        } else {
            append("System proxy \(on ? "enabled" : "disabled") on \(svc).\n")
        }
    }

    // MARK: - Helpers

    private func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    private func err(_ m: String) -> NSError { NSError(domain: "Mirage", code: 1, userInfo: [NSLocalizedDescriptionKey: m]) }

    private func append(_ s: String) {
        log += s
        if log.count > 12000 { log = String(log.suffix(12000)) }
    }
}
