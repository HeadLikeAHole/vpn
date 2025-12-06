// noise protocol implementation
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"time"

	"github.com/HeadLikeAHole/vpn/tai64n"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	identifier   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

var (
	initialChainingKey [blake2s.Size]byte
	initialHash        [blake2s.Size]byte
	zeroNonce          [chacha20poly1305.NonceSize]byte
)

func init() {
	// responder.chaining_key = HASH(CONSTRUCTION)
	initialChainingKey = [blake2s.Size]byte(HASH([]byte(construction)))
	// responder.hash = HASH(responder.chaining_key || IDENTIFIER)
	initialHash = [blake2s.Size]byte(HASH(initialChainingKey[:], []byte(identifier)))
}

const (
	privateKeySize   = 32
	publicKeySize    = 32
	presharedKeySize = 32
)

type (
	privateKeyType   [privateKeySize]byte
	publicKeyType    [publicKeySize]byte
	presharedKeyType [presharedKeySize]byte
)

func processHandshakeInit(d *device, r io.Reader) (*peer, error) {
	h, err := parseHandshakeInit(r)
	if err != nil {
		return nil, err
	}
	var (
		hash [blake2s.Size]byte
		chainingKey [blake2s.Size]byte
	)
	hash = HASH(initialHash[:], d.publicKey[:])
	hash = HASH(hash[:], h.ephemeral[:])
	chainingKey = HMAC(initialChainingKey[:], h.ephemeral[:])
	chainingKey = HMAC(chainingKey[:], []byte{1})
	// initiatorSharedSecret = curve25519.X25519(initiatorEphemeralPrivateKey, serverStaticPublicKey)
	// serverSharedSecret = curve25519.X25519(serverStaticPrivateKey, initiatorEphemeralPublicKey)
	// initiatorSharedSecret == serverSharedSecret
	ephemeralSharedSecret, err := curve25519.X25519(d.privateKey[:], h.ephemeral[:])
	if err != nil {
		return nil, err
	}
	temp := HMAC(chainingKey[:], ephemeralSharedSecret)
	chainingKey = HMAC(temp[:], []byte{1})
	var key [chacha20poly1305.KeySize]byte
	key = HMAC(temp[:], chainingKey[:], []byte{2})
	aead, _ := chacha20poly1305.New(key[:])
	var initiatorStaticPublic publicKeyType
	_, err = aead.Open(initiatorStaticPublic[:0], zeroNonce[:], h.static[:], hash[:])
	if err != nil {
		return nil, err
	}	
	hash = HASH(hash[:], h.static[:])
	peer, ok := d.peers[initiatorStaticPublic]
	if !ok {
		return nil, errors.New("peer not found")
	}
	sess := &peer.session	
	if isZero(sess.staticSharedSecret[:]) {
		return nil, errors.New("peer's static shared secret is zero'")
	}
	temp = HMAC(chainingKey[:], sess.staticSharedSecret[:])
	chainingKey = HMAC(temp[:], []byte{1})
	key = HMAC(temp[:], chainingKey[:], []byte{2})
	aead, _ = chacha20poly1305.New(key[:])
	var timestamp tai64n.Timestamp
	_, err = aead.Open(timestamp[:0], zeroNonce[:], h.timestamp[:], hash[:])
	if err != nil {
		return nil, err
	}	
	hash = HASH(hash[:], h.timestamp[:])
	isReplay := !timestamp.After(sess.latestTimestamp)
	if isReplay {
		return nil, errors.New("replay attempt")
	}
	isDoS := time.Since(sess.latestHandshakeInit) <= handshakeInitRate
	if isDoS {
		return nil, errors.New("DoS attempt")
	}	
	sess.remoteEphemeralPublic = h.ephemeral
	sess.remoteIndex = h.sender
	sess.hash = hash
	sess.chainingKey = chainingKey
	if timestamp.After(sess.latestTimestamp) {
		sess.latestTimestamp = timestamp
	}
	now := time.Now()
	if now.After(sess.latestHandshakeInit) {
		sess.latestHandshakeInit = now
	}
	return &peer, nil
}

// https://www.wireguard.com/protocol/
func createHandshakeResp(sess *session) (*handshakeResp, error) {
	var resp = new(handshakeResp)
	resp.typ = 2
	// TODO: probably should be generated earlier
	sender := make([]byte, 4)
	_, err := rand.Read(sender)
	if err != nil {
		return nil, err
	}
	resp.sender = [4]byte(sender)
	resp.receiver = sess.remoteIndex
	ephemeralPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sess.localEphemeralPrivate = [32]byte(ephemeralPrivate.Bytes())
	resp.ephemeral = [32]byte(ephemeralPrivate.PublicKey().Bytes())
	sess.hash = HASH(sess.hash[:], resp.ephemeral[:])
	sess.chainingKey = HMAC(sess.chainingKey[:], resp.ephemeral[:])
	sess.chainingKey = HMAC(sess.chainingKey[:], []byte{0x1})
	ephemeralSharedSecret, err := curve25519.X25519(sess.localEphemeralPrivate[:], sess.remoteEphemeralPublic[:])
	if err != nil {
		return nil, err
	}
	sess.chainingKey = HMAC(sess.chainingKey[:], ephemeralSharedSecret[:])
	sess.chainingKey = HMAC(sess.chainingKey[:], []byte{0x1})
	ephemeralSharedSecret, err = curve25519.X25519(sess.localEphemeralPrivate[:], sess.remoteStaticPublic[:])
	if err != nil {
		return nil, err
	}
	sess.chainingKey = HMAC(sess.chainingKey[:], ephemeralSharedSecret[:])
	sess.chainingKey = HMAC(sess.chainingKey[:], []byte{0x1})
	temp := HMAC(sess.chainingKey[:], sess.presharedKey[:])
	sess.chainingKey = HMAC(temp[:], []byte{0x1})
	temp2 := HMAC(temp[:], sess.chainingKey[:], []byte{0x2})
	key := HMAC(temp[:], temp2[:], []byte{0x3})
	sess.hash = HASH(sess.hash[:], temp2[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(resp.empty[:0], zeroNonce[:], nil, sess.hash[:])
	sess.hash = HASH(sess.hash[:], temp2[:])
	return resp, nil
}

func deriveDataKeys(sess *session) {
	temp := HMAC(sess.chainingKey[:])
	receivingKey := HMAC(temp[:], []byte{1})
	sendingKey := HMAC(temp[:], receivingKey[:], []byte{2})
	zeroOut(sess.localEphemeralPrivate[:])
	zeroOut(sess.remoteEphemeralPublic[:])
	zeroOut(sess.hash[:])
	zeroOut(sess.chainingKey[:])
	sess.sendingKey, _ = chacha20poly1305.New(sendingKey[:])
	sess.receivingKey, _ = chacha20poly1305.New(receivingKey[:])
}

// func processTransportData(peer *peer) (*handshakeResp, error) {
	
// }