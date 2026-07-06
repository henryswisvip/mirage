// Mirage — a from-scratch, censorship-resistant TCP tunnel protocol.
//
// One binary, two roles:
//
//	mirage server -listen :443 -psk <KEY> [-fallback host:port]
//	mirage client -listen 127.0.0.1:1080 -server HOST:443 -psk <KEY>
//	mirage keygen                 # print a fresh pre-shared key
//	mirage link   -server HOST:443 -psk <KEY>   # print an importable mirage:// link
//
// Wire protocol (v1), identical framing in both directions:
//
//	[ 32 bytes random salt ]                         <- sent once, first thing
//	then a stream of AEAD frames:
//	   frame = seal(uint16 len) [2+16 B] || seal(payload) [len+16 B]
//
//	subkey = HKDF-SHA256(ikm=PSK, salt=salt, info="mirage-v1")   (32 bytes)
//	AEAD   = AES-256-GCM, 12-byte little-endian counter nonce, +1 per seal.
//
// The client's very first frame carries the request header:
//
//	[1B version=1][8B unix-ts][1B atyp][addr][2B port][2B padlen][padlen B rand]
//
// Everything on the wire is either a 32-byte random salt or GCM ciphertext, so
// a passive observer sees only high-entropy bytes with no recognizable pattern.
// A server that can't authenticate a connection reveals nothing: it drains the
// bytes silently, or splices them to a decoy (-fallback) so an active prober
// sees a perfectly ordinary server. Pure Go stdlib; no external dependencies.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ------------------------------- constants ---------------------------------

const (
	version    = 0x01
	saltSize   = 32
	keySize    = 32 // AES-256
	nonceSize  = 12 // GCM standard nonce
	tagSize    = 16 // GCM tag
	lenHdrSize = 2  // uint16 payload length prefix (plaintext, before sealing)
	maxPayload = 16 * 1024

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	maxSkew     = 45 * time.Second // reject headers with |now-ts| beyond this
	handshakeTO = 15 * time.Second // read deadline while authenticating a client
	dialTO      = 10 * time.Second
)

var hkdfInfo = []byte("mirage-v1")

// ------------------------------- key schedule ------------------------------

// hkdf implements HKDF-SHA256 (RFC 5869) using only the standard library.
func hkdf(ikm, salt, info []byte, n int) []byte {
	// Extract
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)
	// Expand
	var out, t []byte
	for counter := byte(1); len(out) < n; counter++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func deriveAEAD(psk, salt []byte) (cipher.AEAD, error) {
	key := hkdf(psk, salt, hkdfInfo, keySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func incNonce(n *[nonceSize]byte) {
	for i := 0; i < nonceSize; i++ {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

// ------------------------------- secure channel ----------------------------

// secureConn wraps a raw net.Conn and turns every Read/Write into the Mirage
// AEAD frame stream. Read and Write sides are independent: each direction has
// its own salt (chosen by whoever writes first in that direction), derived key
// and nonce counter.
type secureConn struct {
	net.Conn
	psk []byte

	// write side
	wAEAD  cipher.AEAD
	wNonce [nonceSize]byte
	wInit  bool

	// read side
	rAEAD  cipher.AEAD
	rNonce [nonceSize]byte
	rInit  bool
	rBuf   []byte // decrypted payload not yet consumed by Read

	clientSalt []byte // the peer's salt (set on first read; used for replay check)
}

func newSecureConn(c net.Conn, psk []byte) *secureConn {
	return &secureConn{Conn: c, psk: psk}
}

func (c *secureConn) initWriter() error {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := deriveAEAD(c.psk, salt)
	if err != nil {
		return err
	}
	if _, err := c.Conn.Write(salt); err != nil {
		return err
	}
	c.wAEAD = aead
	c.wInit = true
	return nil
}

func (c *secureConn) initReader() error {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, err := deriveAEAD(c.psk, salt)
	if err != nil {
		return err
	}
	c.clientSalt = salt
	c.rAEAD = aead
	c.rInit = true
	return nil
}

func (c *secureConn) writeFrame(p []byte) error {
	var lenbuf [lenHdrSize]byte
	binary.BigEndian.PutUint16(lenbuf[:], uint16(len(p)))

	out := make([]byte, 0, lenHdrSize+tagSize+len(p)+tagSize)
	out = c.wAEAD.Seal(out, c.wNonce[:], lenbuf[:], nil)
	incNonce(&c.wNonce)
	out = c.wAEAD.Seal(out, c.wNonce[:], p, nil)
	incNonce(&c.wNonce)

	_, err := c.Conn.Write(out)
	return err
}

func (c *secureConn) Write(p []byte) (int, error) {
	if !c.wInit {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPayload {
			n = maxPayload
		}
		if err := c.writeFrame(p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (c *secureConn) readFrame() ([]byte, error) {
	if !c.rInit {
		if err := c.initReader(); err != nil {
			return nil, err
		}
	}
	sealedLen := make([]byte, lenHdrSize+tagSize)
	if _, err := io.ReadFull(c.Conn, sealedLen); err != nil {
		return nil, err
	}
	lenbuf, err := c.rAEAD.Open(sealedLen[:0], c.rNonce[:], sealedLen, nil)
	if err != nil {
		return nil, errAuth // authentication failure — caller may fall back
	}
	incNonce(&c.rNonce)
	plen := int(binary.BigEndian.Uint16(lenbuf))
	if plen == 0 || plen > maxPayload {
		return nil, errors.New("mirage: bad frame length")
	}
	sealed := make([]byte, plen+tagSize)
	if _, err := io.ReadFull(c.Conn, sealed); err != nil {
		return nil, err
	}
	payload, err := c.rAEAD.Open(sealed[:0], c.rNonce[:], sealed, nil)
	if err != nil {
		return nil, errAuth
	}
	incNonce(&c.rNonce)
	return payload, nil
}

func (c *secureConn) Read(p []byte) (int, error) {
	if len(c.rBuf) > 0 {
		n := copy(p, c.rBuf)
		c.rBuf = c.rBuf[n:]
		return n, nil
	}
	payload, err := c.readFrame()
	if err != nil {
		return 0, err
	}
	n := copy(p, payload)
	if n < len(payload) {
		c.rBuf = payload[n:]
	}
	return n, nil
}

var errAuth = errors.New("mirage: authentication failed")

// ------------------------------- request header ----------------------------

func encodeHeader(host string, port int) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(version)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
	buf.Write(ts[:])

	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf.WriteByte(atypIPv4)
			buf.Write(v4)
		} else {
			buf.WriteByte(atypIPv6)
			buf.Write(ip.To16())
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("mirage: invalid domain length")
		}
		buf.WriteByte(atypDomain)
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	buf.Write(pb[:])

	// Random padding (0..255 B) so the first frame's size carries no signal.
	var pad [1]byte
	rand.Read(pad[:])
	padLen := int(pad[0])
	var pl [2]byte
	binary.BigEndian.PutUint16(pl[:], uint16(padLen))
	buf.Write(pl[:])
	if padLen > 0 {
		p := make([]byte, padLen)
		rand.Read(p)
		buf.Write(p)
	}
	return buf.Bytes(), nil
}

// decodeHeader parses a request header and returns "host:port". It validates
// the version byte and the timestamp skew (replay/clock-drift defense).
func decodeHeader(b []byte) (string, error) {
	r := bytes.NewReader(b)
	v, err := r.ReadByte()
	if err != nil || v != version {
		return "", errors.New("mirage: bad version")
	}
	var ts [8]byte
	if _, err := io.ReadFull(r, ts[:]); err != nil {
		return "", err
	}
	t := time.Unix(int64(binary.BigEndian.Uint64(ts[:])), 0)
	if d := time.Since(t); d > maxSkew || d < -maxSkew {
		return "", errors.New("mirage: timestamp out of window")
	}
	atyp, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	var host string
	switch atyp {
	case atypIPv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return "", err
		}
		host = net.IP(a[:]).String()
	case atypIPv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return "", err
		}
		host = net.IP(a[:]).String()
	case atypDomain:
		l, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		d := make([]byte, int(l))
		if _, err := io.ReadFull(r, d); err != nil {
			return "", err
		}
		host = string(d)
	default:
		return "", errors.New("mirage: bad address type")
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(pb[:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// ------------------------------- replay guard ------------------------------

type replayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayGuard() *replayGuard { return &replayGuard{seen: make(map[string]time.Time)} }

// fresh returns true the first time a salt is seen and false on replay. Entries
// expire after twice the skew window, which is all a replay could exploit.
func (g *replayGuard) fresh(salt []byte) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, t := range g.seen {
		if now.Sub(t) > 2*maxSkew {
			delete(g.seen, k)
		}
	}
	k := string(salt)
	if _, ok := g.seen[k]; ok {
		return false
	}
	g.seen[k] = now
	return true
}

// ------------------------------- plumbing ----------------------------------

// recordingConn tees every byte read from the underlying conn into rec (while
// rec != nil) so the server can replay a failed handshake to the fallback.
type recordingConn struct {
	net.Conn
	rec *bytes.Buffer
}

func (rc *recordingConn) Read(p []byte) (int, error) {
	n, err := rc.Conn.Read(p)
	if n > 0 && rc.rec != nil {
		rc.rec.Write(p[:n])
	}
	return n, err
}

// splice copies bidirectionally and closes both ends when either direction ends.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}

// ------------------------------- server ------------------------------------

func runServer(listen string, psk []byte, fallback string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("mirage server listening on %s (fallback=%q)", listen, fallback)
	guard := newReplayGuard()
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleServerConn(c, psk, fallback, guard)
	}
}

func handleServerConn(raw net.Conn, psk []byte, fallback string, guard *replayGuard) {
	rc := &recordingConn{Conn: raw, rec: new(bytes.Buffer)}
	sc := newSecureConn(rc, psk)

	raw.SetReadDeadline(time.Now().Add(handshakeTO))
	hdr, err := sc.readFrame()
	if err == nil && !guard.fresh(sc.clientSalt) {
		err = errAuth // replayed salt: treat exactly like an auth failure
	}
	var target string
	if err == nil {
		target, err = decodeHeader(hdr)
	}
	if err != nil {
		// Unauthenticated / malformed / replayed: reveal nothing.
		serveFallback(rc, fallback)
		return
	}
	raw.SetReadDeadline(time.Time{}) // clear; authenticated from here on
	rc.rec = nil                     // stop recording — we won't fall back now

	remote, err := net.DialTimeout("tcp", target, dialTO)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		raw.Close()
		return
	}
	log.Printf("tunnel -> %s", target)
	splice(sc, remote)
}

// serveFallback makes an unauthenticated connection look like an ordinary
// server. With -fallback set, the raw bytes (including everything already read)
// are replayed to the decoy and the two are spliced, so a prober sees exactly
// the decoy's behavior. Without it, we silently drain and hang up.
func serveFallback(rc *recordingConn, fallback string) {
	if fallback == "" {
		io.Copy(io.Discard, rc.Conn)
		rc.Conn.Close()
		return
	}
	up, err := net.DialTimeout("tcp", fallback, dialTO)
	if err != nil {
		rc.Conn.Close()
		return
	}
	rc.Conn.SetReadDeadline(time.Time{})
	if rc.rec != nil {
		up.Write(rc.rec.Bytes())
		rc.rec = nil
	}
	splice(rc.Conn, up)
}

// ------------------------------- client (SOCKS5) ---------------------------

func runClient(listen, server string, psk []byte) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("mirage client: SOCKS5 on %s -> server %s", listen, server)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleClientConn(c, server, psk)
	}
}

func handleClientConn(local net.Conn, server string, psk []byte) {
	defer local.Close()
	host, port, err := socks5Handshake(local)
	if err != nil {
		return
	}
	raw, err := net.DialTimeout("tcp", server, dialTO)
	if err != nil {
		socks5Reply(local, 0x01) // general failure
		return
	}
	sc := newSecureConn(raw, psk)
	hdr, err := encodeHeader(host, port)
	if err != nil {
		socks5Reply(local, 0x01)
		raw.Close()
		return
	}
	if _, err := sc.Write(hdr); err != nil { // first Write sends salt + header frame
		socks5Reply(local, 0x01)
		raw.Close()
		return
	}
	if err := socks5Reply(local, 0x00); err != nil { // success
		raw.Close()
		return
	}
	splice(sc, local)
}

// socks5Handshake performs the minimal SOCKS5 no-auth CONNECT negotiation and
// returns the requested destination host and port.
func socks5Handshake(c net.Conn) (string, int, error) {
	br := make([]byte, 2)
	if _, err := io.ReadFull(c, br); err != nil {
		return "", 0, err
	}
	if br[0] != 0x05 {
		return "", 0, errors.New("not socks5")
	}
	methods := make([]byte, int(br[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", 0, err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return "", 0, err
	}
	hd := make([]byte, 4)
	if _, err := io.ReadFull(c, hd); err != nil {
		return "", 0, err
	}
	if hd[0] != 0x05 || hd[1] != 0x01 { // only CONNECT
		socks5Reply(c, 0x07)
		return "", 0, errors.New("unsupported socks command")
	}
	var host string
	switch hd[3] {
	case atypIPv4:
		a := make([]byte, 4)
		io.ReadFull(c, a)
		host = net.IP(a).String()
	case atypIPv6:
		a := make([]byte, 16)
		io.ReadFull(c, a)
		host = net.IP(a).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", 0, err
		}
		d := make([]byte, int(l[0]))
		io.ReadFull(c, d)
		host = string(d)
	default:
		socks5Reply(c, 0x08)
		return "", 0, errors.New("bad atyp")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(pb)), nil
}

func socks5Reply(c net.Conn, code byte) error {
	// VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
	_, err := c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// ------------------------------- links / keys ------------------------------

// A mirage:// link bundles everything a client needs:  mirage://<pskB64URL>@host:port
func makeLink(server string, psk []byte) string {
	return "mirage://" + base64.RawURLEncoding.EncodeToString(psk) + "@" + server
}

func parseLink(link string) (server string, psk []byte, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	if u.Scheme != "mirage" {
		return "", nil, errors.New("not a mirage:// link")
	}
	psk, err = base64.RawURLEncoding.DecodeString(u.User.Username())
	if err != nil {
		return "", nil, fmt.Errorf("bad key in link: %w", err)
	}
	if len(psk) != keySize {
		return "", nil, fmt.Errorf("key must be %d bytes, got %d", keySize, len(psk))
	}
	return u.Host, psk, nil
}

func decodePSK(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Accept both base64url and standard base64 for convenience.
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil && len(b) == keySize {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == keySize {
		return b, nil
	}
	return nil, fmt.Errorf("PSK must be a base64-encoded %d-byte key", keySize)
}

func genPSK() []byte {
	k := make([]byte, keySize)
	if _, err := rand.Read(k); err != nil {
		log.Fatalf("rand: %v", err)
	}
	return k
}

// ------------------------------- main --------------------------------------

func usage() {
	fmt.Fprint(os.Stderr, `Mirage — a censorship-resistant tunnel.

Usage:
  mirage keygen
        Print a fresh pre-shared key (base64).

  mirage server -listen :443 -psk <KEY> [-fallback host:port]
        Run the server on your VM. -fallback is a decoy (e.g. a real web
        server or www.microsoft.com:443) that unauthenticated probes are
        transparently relayed to. Strongly recommended.

  mirage client -listen 127.0.0.1:1080 -server HOST:443 -psk <KEY>
  mirage client -listen 127.0.0.1:1080 -link mirage://KEY@HOST:443
        Run the local SOCKS5 proxy on your Mac. Point apps at 127.0.0.1:1080.

  mirage link -server HOST:443 -psk <KEY>
        Print an importable mirage://KEY@HOST:443 link.
`)
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {

	case "keygen":
		fmt.Println(base64.StdEncoding.EncodeToString(genPSK()))

	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		listen := fs.String("listen", ":443", "address to listen on")
		pskStr := fs.String("psk", "", "pre-shared key (base64)")
		fallback := fs.String("fallback", "", "decoy host:port for unauthenticated connections")
		fs.Parse(os.Args[2:])
		psk, err := decodePSK(*pskStr)
		if err != nil {
			log.Fatalf("-psk: %v", err)
		}
		log.Fatal(runServer(*listen, psk, *fallback))

	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 address")
		server := fs.String("server", "", "server HOST:port")
		pskStr := fs.String("psk", "", "pre-shared key (base64)")
		link := fs.String("link", "", "mirage:// link (overrides -server/-psk)")
		fs.Parse(os.Args[2:])
		var psk []byte
		var err error
		if *link != "" {
			*server, psk, err = parseLink(*link)
		} else {
			psk, err = decodePSK(*pskStr)
		}
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		if *server == "" {
			log.Fatal("need -server HOST:port or -link")
		}
		log.Fatal(runClient(*listen, *server, psk))

	case "link":
		fs := flag.NewFlagSet("link", flag.ExitOnError)
		server := fs.String("server", "", "server HOST:port")
		pskStr := fs.String("psk", "", "pre-shared key (base64)")
		fs.Parse(os.Args[2:])
		psk, err := decodePSK(*pskStr)
		if err != nil {
			log.Fatalf("-psk: %v", err)
		}
		if *server == "" {
			log.Fatal("need -server HOST:port")
		}
		fmt.Println(makeLink(*server, psk))

	default:
		usage()
		os.Exit(2)
	}
}
