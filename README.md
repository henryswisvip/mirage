# Mirage

A small, from-scratch, censorship-resistant tunnel — my own protocol, not a
wrapper around Xray / V2Ray / Shadowsocks. One ~2.5 MB static binary is both
the **server** (on your VM, abroad) and the **client** (on your Mac). Your Mac
apps talk to a local SOCKS5 proxy; everything to the server is encrypted and
looks like random bytes on the wire.

```
  Mac apps ──SOCKS5──> mirage client ══ Mirage tunnel (AEAD) ══> mirage server ──> the open internet
  (127.0.0.1:1080)        (your Mac)      looks like random bytes      (your VM abroad)
```

## Why it resists the Great Firewall

- **No fingerprint.** After the TCP connect, the only things on the wire are a
  32-byte random salt and AES-256-GCM ciphertext. There are no plaintext
  headers, magic bytes, or fixed-length handshake for DPI to match on.
- **Survives active probing.** The GFW connects to suspected proxy servers to
  see how they answer. A Mirage server never answers as a proxy: without the
  key you cannot forge a valid auth tag, so the server either silently drains
  the connection or **transparently relays it to a decoy site** (`-fallback`),
  so a prober sees an ordinary web server.
- **Replay-proof.** Each session uses a fresh random salt plus a signed
  timestamp; the server rejects reused salts and stale timestamps.
- **Sound crypto.** Custom *wire format*, standard *primitives*: HKDF-SHA256 for
  key derivation, AES-256-GCM AEAD, `crypto/rand` for all randomness. No
  home-made ciphers. Pure Go standard library, zero dependencies.

---

## Quick start

### 1. Server (your VM, e.g. Ubuntu/Debian abroad)

SSH into the VM, clone the repo, and run the installer:

```bash
ssh you@YOUR_VM_IP
git clone https://github.com/henryswisvip/mirage.git
sudo bash mirage/server/install-server.sh
```

(No Go toolchain needed — prebuilt static binaries ship in `bin/`.)

It installs the binary, generates a key, starts a `systemd` service on port
443, sets `www.microsoft.com:443` as the decoy, opens the firewall, and prints:

```
Import link for your Mac:
  mirage://<KEY>@YOUR_VM_IP:443
```

Copy that `mirage://…` link. (Re-print it any time with
`mirage link -server YOUR_VM_IP:443 -psk <KEY>`.)

> **Port 443 tip:** it blends in with HTTPS. If your VM already runs a web
> server on 443, either use a different port (`PORT=8443 sudo bash …`) or point
> `-fallback` at that local web server so real probes land on real content.

### 2. Client (your Mac)

Clone the repo on your Mac and run the client helper:

```bash
git clone https://github.com/henryswisvip/mirage.git
cd mirage
./client/connect-mac.sh 'mirage://<KEY>@YOUR_VM_IP:443'
```

Leave it running. It starts a SOCKS5 proxy at **127.0.0.1:1080**. Test it:

```bash
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me   # should show your VM's IP
```

### 3. Point your Mac at the proxy

**Per-app:** set the app's SOCKS5 proxy to `127.0.0.1:1080` (Firefox, many
tools, and anything honoring `ALL_PROXY=socks5h://127.0.0.1:1080`).

**Whole system:** let the script flip macOS's SOCKS proxy for you (it turns it
back off when you Ctrl-C):

```bash
./client/connect-mac.sh 'mirage://<KEY>@YOUR_VM_IP:443' --system
# turn it off manually if needed:
./client/connect-mac.sh --unset-system
```

Or do it by hand in **System Settings → Network → (your interface) → Details →
Proxies → SOCKS5** = `127.0.0.1` port `1080`.

---

## Command reference

```
mirage keygen
      Print a fresh pre-shared key (base64).

mirage server -listen :443 -psk <KEY> [-fallback host:port]
      Run the server. -fallback is a decoy that unauthenticated connections are
      relayed to (strongly recommended; omit to silently drain instead).

mirage client -listen 127.0.0.1:1080 -server HOST:443 -psk <KEY>
mirage client -listen 127.0.0.1:1080 -link mirage://KEY@HOST:443
      Run the local SOCKS5 proxy.

mirage link -server HOST:443 -psk <KEY>
      Print an importable mirage://KEY@HOST:443 link.
```

Prebuilt binaries are in `bin/` (`linux-amd64`, `linux-arm64`, `macos-arm64`,
`macos-amd64`). Rebuild from source anytime with `go build -o mirage .`.

---

## Protocol spec (v1)

Same AEAD framing in both directions; each direction is keyed independently.

```
On connect, each side sends once:
    [ 32 bytes: random salt ]
Then a stream of frames:
    frame = seal(uint16 payload_len)      # 2 + 16 bytes
            seal(payload)                 # payload_len + 16 bytes

    subkey = HKDF-SHA256(ikm=PSK, salt=salt, info="mirage-v1")   -> 32 bytes
    AEAD   = AES-256-GCM
    nonce  = 12-byte little-endian counter, starts at 0, +1 after every seal
    max payload per frame = 16 KiB
```

The client's first frame is the request header:

```
[1B  version = 0x01]
[8B  unix timestamp, big-endian]      # server requires |now - ts| <= 45s
[1B  address type: 0x01 v4 / 0x03 domain / 0x04 v6]
[    address: 4B | (1B len + N) | 16B]
[2B  port, big-endian]
[2B  padding length P]
[P B random padding]                  # 0..255 B, hides the first frame's size
```

The server checks the version, timestamp window, and that the salt hasn't been
seen recently (replay guard). Any failure → the connection is handed to the
decoy / drained, revealing nothing.

---

## Security properties & honest limitations

**What it gives you**

- Confidentiality + integrity of all tunneled traffic (AES-256-GCM).
- No static, matchable byte pattern; salts and ciphertext are random-looking.
- Active-probing resistance via authenticate-or-look-like-a-decoy.
- Replay and coarse clock-skew protection.

**What it does *not* do (know these before relying on it)**

- **No forward secrecy.** Security rests on the pre-shared key. If the PSK
  leaks, past captured traffic can be decrypted. (A future v2 could add an
  X25519 ephemeral handshake.) Keep the key secret; use one key per person.
- **Fully-random traffic is itself a signal.** Sophisticated censors sometimes
  flag flows with uniformly high entropy and no TLS. Mirage does not (yet)
  mimic a real TLS handshake the way REALITY does. Running on port 443 with a
  good decoy helps, but this is the main theoretical weakness versus
  state-of-the-art tools.
- **UDP isn't tunneled.** SOCKS5 CONNECT (TCP) only — fine for web browsing and
  most apps; QUIC/UDP-only apps won't route through it.
- **Not independently audited.** This is a clean, correct, from-scratch
  implementation, but it hasn't had adversarial review. For high-risk use,
  mature tools (Xray VLESS-REALITY, sing-box) have had far more scrutiny.
- **Use it lawfully.** Intended for privacy and reaching the open internet.

**Operational tips**

- Use a VM whose IP isn't already known-blocked; residential/cloud IPs vary.
- Set `-fallback` to a site that's reachable and TLS-capable (the default
  `www.microsoft.com:443` is a reasonable choice), or to a real local web
  server on the VM.
- Rotate the key if you suspect exposure: `mirage keygen`, update the service
  (`/etc/systemd/system/mirage.service`), `systemctl restart mirage`, and
  re-share the new link.

---

## Files

```
main.go                     the whole protocol + server + client (one file)
go.mod
bin/                        prebuilt static binaries (linux/macos, amd64/arm64)
server/install-server.sh    installs & runs the server as a systemd service
client/connect-mac.sh       runs the Mac client, optional system-proxy toggle
```
