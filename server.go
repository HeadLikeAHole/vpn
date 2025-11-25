package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/HeadLikeAHole/vpn/tai64n"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type Server struct {
	privateKey privateKeyType
	publicKey  publicKeyType
	conn       *net.UDPConn
	peers      map[publicKeyType]Peer
}

func NewServer() (*Server, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Server{
		privateKey: [32]byte(privateKey.Bytes()),
		publicKey:  [32]byte(privateKey.PublicKey().Bytes()),
		peers:      make(map[publicKeyType]Peer),
	}, nil
}

func (s *Server) Start(port int) error {
	addr := &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: port,
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	fmt.Println("Server is listening on port:", port)
	return nil
}

func (s *Server) readLoop() {
	for {
		// First byte is message type:
		// 	1 - handshake initiation
		//  2 - handshake response
		//  3 - cookie reply
		//  4 - data message
		// Next three bytes are always three zeros. They serve as
		// padding for 32-bit alignment and future protocol extensions.
		buf := make([]byte, 4)
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}
		data := buf[:n]
		if len(data) < 4 {
			continue
		}
		typ := MessageType(data[0])
		switch typ {
		case handshakeInitType:
			peer, err := s.processHandshakeInit(s.conn, addr)
		case transportDataType:
			err = s.handleTransportData(data, addr)
		default:
			fmt.Println("Unknown message type:", typ)
		}
		if err != nil {
			fmt.Println("Error processing message:", err)
		}
	}
}

func (s *Server) processHandshakeInit(r io.Reader, addr *net.UDPAddr) (*Peer, error) {
	h, err := ParseHandshakeInit(r)
	if err != nil {
		return nil, err
	}
	var (
		hash [blake2s.Size]byte
		chainingKey [blake2s.Size]byte
	)
	hash = HASH(initialHash[:], s.publicKey[:])
	hash = HASH(hash[:], h.ephemeral[:])
	chainingKey = HMAC(initialChainingKey[:], h.ephemeral[:])
	chainingKey = HMAC(chainingKey[:], []byte{1})
	// initiatorSharedSecret = curve25519.X25519(initiatorEphemeralPrivateKey, serverStaticPublicKey)
	// serverSharedSecret = curve25519.X25519(serverStaticPrivateKey, initiatorEphemeralPublicKey)
	// initiatorSharedSecret == serverSharedSecret
	ephemeralSharedSecret, err := curve25519.X25519(s.privateKey[:], h.ephemeral[:])
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
	peer, ok := s.peers[initiatorStaticPublic]
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
func (s *Server) sendHandshakeResp(peer *Peer) (*HandshakeResp, error) {
	sess := &peer.session
	var resp = new(HandshakeResp)
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
