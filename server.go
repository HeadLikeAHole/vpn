package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type Server struct {
	privKey *ecdh.PrivateKey
	pubKey  *ecdh.PublicKey
	conn    *net.UDPConn
	peers   map[[32]byte]Peer
}

func NewServer() (*Server, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Server{
		privKey: privKey,
		pubKey:  privKey.PublicKey(),
		peers:   make(map[[32]byte]Peer),
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
			err = s.handleHandshakeInit(s.conn, addr)
		case handshakeRespType:
			err = s.handleHandshakeResponse(data, addr)
		case dataMessageType:
			err = s.handleDataMessage(data, addr)
		default:
			fmt.Println("Unknown message type:", typ)
		}
		if err != nil {
			fmt.Println("Error processing message:", err)
		}
	}
}

func (s *Server) handleHandshakeInit(r io.Reader, addr *net.UDPAddr) error {
	h, err := NewHandshakeInit(r)
	if err != nil {
		return err
	}
	hash := HASH(initialChainingKey, s.privKey.PublicKey().Bytes())
	hash = HASH(hash, h.ephemeral[:])
	chainingKey := HMAC(initialChainingKey, h.ephemeral[:])
	chainingKey = HMAC(chainingKey, []byte{1})
	// initiatorSharedSecret = curve25519.X25519(initiatorEphemeralPrivateKey, serverStaticPublicKey)
	// serverSharedSecret = curve25519.X25519(serverStaticPrivateKey, initiatorEphemeralPublicKey)
	// initiatorSharedSecret == serverSharedSecret
	sharedSecret, err := curve25519.X25519(s.privKey.Bytes(), ephemeral[:])
	if err != nil {
		return err
	}
	temp := HMAC(chainingKey, sharedSecret)
	chainingKey = HMAC(temp, []byte(1))
	key := HMAC(temp, chainingKey, []byte(2))
	var initiatorStaticPublic []byte
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(initiatorStaticPublic, []byte(0), h.static[:], hash[:])
	if err != nil {
		return nil
	}
	hash = HASH(hash, h.static[:])
	
	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()
	if replay {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake flood", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer

}

// https://www.wireguard.com/protocol/
func (s *Server) sendHandshakeResp(receiver [4]byte, initiatorStaticPublic) error {
	var resp = new(HandshakeResp)
	// responder.ephemeral_private = DH_GENERATE()
	ephemeralPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// msg.message_type = 2
	// msg.reserved_zero = { 0, 0, 0 } - encoded later with
	// message_type as little_endian(uint32(msg.message_type))
	resp.typ = 2
	// msg.sender_index = little_endian(responder.sender_index)
	sender := make([]byte, 4)
	_, err := rand.Read(sender)
	if err != nil {
		return err
	}
	// A 32-bit index that locally represents the other peer,
	// analogous to IPsec’s “SPI”.
	resp.sender = [4]byte(sender)
	// msg.receiver_index = little_endian(initiator.sender_index)
	resp.receiver = receiver
	// msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
	resp.ephemeral = [32]byte(ephemeralPrivate.PublicKey().Bytes())
	hasher, err := blake2s.New256(nil)
	if err != nil {
		return err
	}
	// responder.chaining_key = HASH(CONSTRUCTION)
	_, err = hasher.Write([]byte(construction))
	if err != nil {
		return err
	}
	chainingKey := hasher.Sum(nil)
	hasher.Reset()
	// responder.hash = HASH(HASH(responder.chaining_key || IDENTIFIER) || initiator.static_public)
	_, err = hasher.Write(chainingKey)
	if err != nil {
		return err
	}
	_, err = hasher.Write([]byte(identifier))
	if err != nil {
		return err
	}
	chainingKey2 := hasher.Sum(nil)
	hasher.Reset()
	_, err = hasher.Write(chainingKey2)
	if err != nil {
		return err
	}
	_, err = hasher.Write(initiatorStaticPublic)
	if err != nil {
		return err
	}
	hash := hasher.Sum(nil)
	hasher.Reset()
	// responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
	_, err = hasher.Write(hash)
	if err != nil {
		return err
	}
	_, err = hasher.Write(resp.ephemeral[:])
	if err != nil {
		return err
	}
	hash = hasher.Sum(nil)
	// temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
	temp := HMAC(chainingKey, resp.ephemeral[:])
	// responder.chaining_key = HMAC(temp, 0x1)
	chainingKey = HMAC(temp, []byte{1})
	// temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
	temp2, err := curve25519.X25519(ephemeralPrivate, initiatorEphemeralPublic)
	if err != nil {
		return err
	}
	temp = HMAC(chainingKey, temp2)
	// responder.chaining_key = HMAC(temp, 0x1)
	chainingKey = HMAC(temp, []byte{1})
	// temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
	temp2, err = curve25519.X25519(ephemeralPrivate, initiatorStaticPublic)
	if err != nil {
		return err
	}
	temp = HMAC(chainingKey, temp2)
	// responder.chaining_key = HMAC(temp, 0x1)
	chainingKey = HMAC(temp, []byte{1})
	// temp = HMAC(responder.chaining_key, preshared_key)
	// TODO: what is preshared_key?


	key := HMAC(temp, chainingKey, []byte{2})
	// msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
	// aead, _ := chacha20poly1305.New(key[:])
	// aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
	aead, err :=  chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	resp := aead.Seal()
	return nil
}











// responder.chaining_key = HMAC(temp, 0x1)
// temp2 = HMAC(temp, responder.chaining_key || 0x2)
// key = HMAC(temp, temp2 || 0x3)
// responder.hash = HASH(responder.hash || temp2)

// msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
// responder.hash = HASH(responder.hash || msg.encrypted_nothing)

// msg.mac1 = MAC(HASH(LABEL_MAC1 || initiator.static_public), msg[0:offsetof(msg.mac1)])
// if (responder.last_received_cookie is empty or expired)
//     msg.mac2 = [zeros]
// else
//     msg.mac2 = MAC(responder.last_received_cookie, msg[0:offsetof(msg.mac2)])

type Peer struct {
	// 32 bytes
	publicKey  ed25519.PublicKey
	allowedIPs []net.IP
}
