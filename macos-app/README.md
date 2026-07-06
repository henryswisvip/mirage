# Mirage — macOS app

A native SwiftUI menu app that connects to your Mirage server from a
`mirage://KEY@HOST:PORT` link. It bundles the `mirage` client binary, runs it
as a local SOCKS5 proxy, and can flip the macOS system proxy for you.

![what it does](https://img.shields.io/badge/macOS-13%2B-blue)

## Open & run

```bash
open macos-app/MirageGUI/MirageGUI.xcodeproj
```

In Xcode: press **⌘R** (Run). The project is set to *Sign to Run Locally*
(ad-hoc), so it builds with no Apple Developer account. If you want to run it
outside Xcode, build once, then find `MirageGUI.app` under
**Product ▸ Show Build Folder in Finder** and drag it to `/Applications`.

## Use

1. Paste your link — e.g. `mirage://-xTsOrDRnR0qMgOk...@23.27.96.101:443` — into
   the **Connection link** field (the **Paste** button grabs the clipboard).
2. Optionally tick **Route all macOS traffic (system proxy)** — this sets the
   Wi-Fi SOCKS proxy and asks for your admin password.
3. Click **Connect**. The tunnel comes up as a SOCKS5 proxy on
   `127.0.0.1:1080`. If you didn't enable the system proxy, point individual
   apps there (Firefox, `curl --proxy socks5h://127.0.0.1:1080 …`, etc.).
4. **Disconnect** stops the tunnel and, if you enabled it, removes the system
   proxy.

## How it works

- `ProxyController.swift` stages the bundled binary to
  `~/Library/Application Support/MirageGUI/mirage` (chmod 755) and launches
  `mirage client -listen 127.0.0.1:<port> -link <link>` as a subprocess,
  streaming its output into the log view.
- The system-proxy toggle runs `networksetup` via an admin `osascript` prompt.
- The app is **not sandboxed** (it must launch a helper process and change
  network settings), so build it for yourself rather than distributing it.

## Updating the bundled binary

The client binary lives at `MirageGUI/mirage` (a universal arm64+x86_64 build,
ad-hoc signed). To refresh it after changing the Go source:

```bash
# from the repo root
GOOS=darwin GOARCH=arm64 go build -o /tmp/m-arm64 .
GOOS=darwin GOARCH=amd64 go build -o /tmp/m-amd64 .
lipo -create /tmp/m-arm64 /tmp/m-amd64 -output macos-app/MirageGUI/MirageGUI/mirage
codesign --force --sign - macos-app/MirageGUI/MirageGUI/mirage   # required on Apple Silicon
```

## Notes / limitations

- The system-proxy toggle targets the **Wi-Fi** service. On Ethernet, either
  set the SOCKS proxy manually in System Settings ▸ Network ▸ Proxies, or edit
  `networkService` in `ProxyController.swift`.
- SOCKS5 handles TCP (browsing and most apps). UDP/QUIC-only apps won't route.
- Everything else — the protocol, security properties, limitations — is in the
  [top-level README](../README.md).
