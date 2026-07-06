#!/usr/bin/env bash
#
# install-server.sh — install the Mirage tunnel server on your VM.
#
# Copy this whole project folder to your VM (outside China), then run:
#     sudo bash server/install-server.sh
#
# It installs a prebuilt static binary (no Go toolchain needed), generates a
# key if you don't supply one, writes a systemd service, opens the firewall
# and prints the mirage:// link + client command for your Mac.
#
# Optional environment overrides:
#     PORT=443                 # port clients connect to
#     PSK=<base64 key>         # reuse an existing key instead of generating
#     FALLBACK=host:port       # decoy for unauthenticated probes (recommended)
#     LABEL=my-server          # a friendly name
# ---------------------------------------------------------------------------
set -euo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLD=$'\e[1m'; RST=$'\e[0m'
say()  { printf '%s\n' "${GRN}==>${RST} $*"; }
warn() { printf '%s\n' "${YEL}!! ${RST} $*"; }
die()  { printf '%s\n' "${RED}xx ${RST} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash server/install-server.sh"

PORT="${PORT:-443}"
FALLBACK="${FALLBACK:-www.microsoft.com:443}"   # decoy site probes get relayed to
LABEL="${LABEL:-mirage}"
PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ------------------------- pick / build the binary -------------------------
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  BIN_SRC="$PROJ_DIR/bin/mirage-linux-amd64" ;;
  aarch64|arm64) BIN_SRC="$PROJ_DIR/bin/mirage-linux-arm64" ;;
  *) BIN_SRC="" ;;
esac

if [ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ]; then
  say "Using prebuilt binary for $ARCH"
elif command -v go >/dev/null 2>&1; then
  say "No prebuilt binary for $ARCH; building from source with Go…"
  ( cd "$PROJ_DIR" && go build -trimpath -ldflags="-s -w" -o "$PROJ_DIR/bin/mirage-local" . )
  BIN_SRC="$PROJ_DIR/bin/mirage-local"
else
  die "No prebuilt binary for '$ARCH' and Go is not installed. Install Go, or build a matching binary and place it in bin/."
fi

install -m 0755 "$BIN_SRC" /usr/local/bin/mirage
say "Installed /usr/local/bin/mirage"

# ------------------------- key ---------------------------------------------
if [ -z "${PSK:-}" ]; then
  PSK="$(/usr/local/bin/mirage keygen)"
  say "Generated a new pre-shared key."
else
  say "Using the PSK provided via environment."
fi

# ------------------------- systemd service ---------------------------------
say "Writing systemd unit (mirage.service)…"
cat > /etc/systemd/system/mirage.service <<UNIT
[Unit]
Description=Mirage tunnel server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mirage server -listen :${PORT} -psk ${PSK} -fallback ${FALLBACK}
Restart=on-failure
RestartSec=2
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable mirage >/dev/null 2>&1 || true
systemctl restart mirage
sleep 1
systemctl is-active --quiet mirage || { journalctl -u mirage --no-pager -n 20; die "mirage failed to start"; }
say "Service is running."

# ------------------------- firewall ----------------------------------------
if command -v ufw >/dev/null 2>&1; then ufw allow "${PORT}"/tcp >/dev/null 2>&1 || true; fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${PORT}"/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

# BBR congestion control noticeably improves long-haul throughput.
if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
  { echo 'net.core.default_qdisc=fq'; echo 'net.ipv4.tcp_congestion_control=bbr'; } >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
fi

# ------------------------- output ------------------------------------------
IP="$(curl -s4 https://api.ipify.org 2>/dev/null || echo YOUR_SERVER_IP)"
LINK="$(/usr/local/bin/mirage link -server "${IP}:${PORT}" -psk "${PSK}")"

printf '\n%s\n' "${GRN}${BLD}================  Mirage server is up  ================${RST}"
cat <<INFO
Server address : ${IP}:${PORT}
Pre-shared key : ${PSK}
Decoy fallback : ${FALLBACK}

Import link for your Mac:
  ${BLD}${LINK}${RST}

On your Mac, run the local proxy with either:
  ./mirage client -listen 127.0.0.1:1080 -link "${LINK}"
  ./mirage client -listen 127.0.0.1:1080 -server ${IP}:${PORT} -psk ${PSK}

Then set your Mac SOCKS proxy to 127.0.0.1:1080  (see client/connect-mac.sh).

Manage the server:  systemctl {status|restart|stop} mirage
                    journalctl -u mirage -f
INFO
printf '%s\n' "Save the key somewhere safe — anyone with it can use your server."
