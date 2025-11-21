package main

import (
	"crypto/ed25519"
	"net"
	"time"

	"github.com/HeadLikeAHole/vpn/tai64n"
)

type Peer struct {
	publicKey ed25519.PublicKey
	// Derived from own static private and other side's static public.
	// Precomputed when peer is added "manually" to the server.
	staticSharedSecret []byte
	allowedIPs         []net.IP
	session            Session
}

type Session struct {
	hash        [32]byte
	chainingKey [32]byte
	// sender from HandshakeInit
	remoteIndex     [4]byte
	remoteEphemeral [32]byte
	// prevents replay attacks by tracking the latest timestamp seen from the peer
	latestTimestamp tai64n.Timestamp
	// Enforces the HandshakeInitRate limit.
	// Prevents processing too many handshakes too quickly (DoS protection).
	latestHandshakeInit time.Time
}
