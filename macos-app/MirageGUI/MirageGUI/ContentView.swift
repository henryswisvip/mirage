import SwiftUI
import AppKit

struct ContentView: View {
    @StateObject private var proxy = ProxyController()
    @State private var link = ""
    @State private var setSystemProxy = false

    private var linkValid: Bool { ProxyController.parse(link) != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            linkField
            optionsRow
            connectButton
            statusRow
            Divider()
            logView
        }
        .padding(22)
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 30))
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text("Mirage").font(.title2).bold()
                Text("Censorship-resistant tunnel").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            HStack(spacing: 6) {
                Circle().fill(proxy.isConnected ? .green : .secondary).frame(width: 10, height: 10)
                Text(proxy.isConnected ? "Connected" : "Offline")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var linkField: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Connection link").font(.subheadline).bold()
            TextField("mirage://KEY@HOST:443", text: $link, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))
                .lineLimit(2...3)
                .disabled(proxy.isConnected)
            HStack {
                Button {
                    if let s = NSPasteboard.general.string(forType: .string) { link = s }
                } label: { Label("Paste", systemImage: "doc.on.clipboard") }
                    .buttonStyle(.link)
                    .disabled(proxy.isConnected)
                Spacer()
                if !link.isEmpty {
                    Label(linkValid ? "Looks valid" : "Invalid format",
                          systemImage: linkValid ? "checkmark.circle" : "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(linkValid ? .green : .red)
                }
            }
        }
    }

    private var optionsRow: some View {
        HStack(spacing: 16) {
            Toggle("Route all macOS traffic (system proxy)", isOn: $setSystemProxy)
                .disabled(proxy.isConnected)
            Spacer()
            HStack(spacing: 6) {
                Text("SOCKS port").font(.caption).foregroundStyle(.secondary)
                TextField("1080", value: $proxy.listenPort, format: .number.grouping(.never))
                    .frame(width: 64)
                    .textFieldStyle(.roundedBorder)
                    .disabled(proxy.isConnected)
            }
        }
    }

    private var connectButton: some View {
        Button {
            if proxy.isConnected {
                proxy.disconnect(unsetSystemProxy: setSystemProxy)
            } else {
                proxy.connect(link: link, setSystemProxy: setSystemProxy)
            }
        } label: {
            HStack {
                Spacer()
                if proxy.isBusy { ProgressView().controlSize(.small).padding(.trailing, 4) }
                Text(proxy.isConnected ? "Disconnect" : "Connect").bold()
                Spacer()
            }
            .padding(.vertical, 6)
        }
        .buttonStyle(.borderedProminent)
        .tint(proxy.isConnected ? .red : .accentColor)
        .disabled((!linkValid && !proxy.isConnected) || proxy.isBusy)
    }

    private var statusRow: some View {
        HStack(spacing: 8) {
            Image(systemName: proxy.isConnected ? "checkmark.circle.fill" : "circle.dashed")
                .foregroundStyle(proxy.isConnected ? .green : .secondary)
            Text(proxy.statusText).font(.callout)
            Spacer()
            if proxy.isConnected {
                Text("Point apps at 127.0.0.1:\(proxy.listenPort)")
                    .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
        }
    }

    private var logView: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Log").font(.subheadline).bold()
                Spacer()
                Button("Clear") { proxy.log = "" }.buttonStyle(.link).font(.caption)
            }
            ScrollView {
                Text(proxy.log.isEmpty ? "No output yet." : proxy.log)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(minHeight: 130, maxHeight: 190)
            .padding(8)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(.secondary.opacity(0.2)))
        }
    }
}

#Preview {
    ContentView().frame(width: 540, height: 520)
}
