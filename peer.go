package main

import (
	"net"
	"time"

	"github.com/HeadLikeAHole/vpn/tai64n"
	"golang.org/x/crypto/blake2s"
)

type Peer struct {
	allowedIPs []net.IP
	session    Session
}

type Session struct {
	remoteStaticPublic publicKeyType
	// Derived from own static private and other side's static public.
	// Precomputed when peer is added "manually" to the server.
	staticSharedSecret [publicKeySize]byte
	// Randomly generated pre-shared symmetric key or PSK.
	// This key is generated on the server and shared
	// with peer beforehand like peer's key pair.
	presharedKey          presharedKeyType
	localEphemeralPrivate privateKeyType
	remoteEphemeralPublic publicKeyType
	// sender from handshake initiation
	remoteIndex [4]byte
	hash        [blake2s.Size]byte
	chainingKey [blake2s.Size]byte
	// prevents replay attacks by tracking the latest timestamp seen from the peer
	latestTimestamp tai64n.Timestamp
	// prevents processing too many handshakes too quickly (DoS protection)
	latestHandshakeInit time.Time
}
