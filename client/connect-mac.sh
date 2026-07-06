#!/usr/bin/env bash
#
# connect-mac.sh — run the Mirage client on macOS and (optionally) flip the
# system SOCKS proxy on/off for you.
#
# Usage:
#   ./client/connect-mac.sh 'mirage://KEY@HOST:443'          # start the proxy
#   ./client/connect-mac.sh 'mirage://KEY@HOST:443' --system # + set macOS SOCKS
#   ./client/connect-mac.sh --unset-system                   # turn macOS SOCKS off
#
# The proxy listens on 127.0.0.1:1080. Leave this terminal open while browsing.
# ---------------------------------------------------------------------------
set -euo pipefail

LISTEN="127.0.0.1:1080"
PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# The Wi-Fi service name on most Macs is "Wi-Fi"; change if you use Ethernet.
NET_SERVICE="${NET_SERVICE:-Wi-Fi}"

enable_system_proxy() {
  local host="${LISTEN%%:*}" port="${LISTEN##*:}"
  echo "==> Enabling macOS SOCKS proxy on '$NET_SERVICE' -> $host:$port"
  sudo networksetup -setsocksfirewallproxy "$NET_SERVICE" "$host" "$port"
  sudo networksetup -setsocksfirewallproxystate "$NET_SERVICE" on
}
disable_system_proxy() {
  echo "==> Disabling macOS SOCKS proxy on '$NET_SERVICE'"
  sudo networksetup -setsocksfirewallproxystate "$NET_SERVICE" off
}

if [ "${1:-}" = "--unset-system" ]; then
  disable_system_proxy
  exit 0
fi

LINK="${1:-}"
[ -n "$LINK" ] || { echo "usage: $0 'mirage://KEY@HOST:PORT' [--system]"; exit 2; }

# Pick the right prebuilt binary for this Mac (Apple Silicon vs Intel).
case "$(uname -m)" in
  arm64) BIN="$PROJ_DIR/bin/mirage-macos-arm64" ;;
  x86_64) BIN="$PROJ_DIR/bin/mirage-macos-amd64" ;;
  *) BIN="" ;;
esac
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  if command -v go >/dev/null 2>&1; then
    echo "==> Building client from source…"
    ( cd "$PROJ_DIR" && go build -o "$PROJ_DIR/bin/mirage-local" . )
    BIN="$PROJ_DIR/bin/mirage-local"
  else
    echo "No usable binary and Go not installed." >&2; exit 1
  fi
fi
# macOS quarantines downloaded binaries; clear it so it will run.
xattr -d com.apple.quarantine "$BIN" 2>/dev/null || true

if [ "${2:-}" = "--system" ]; then
  enable_system_proxy
  trap disable_system_proxy EXIT INT TERM
fi

echo "==> Mirage client running. SOCKS5 at $LISTEN  (Ctrl-C to stop)"
echo "    Test in another terminal:"
echo "      curl --proxy socks5h://$LISTEN https://ifconfig.me"
exec "$BIN" client -listen "$LISTEN" -link "$LINK"
