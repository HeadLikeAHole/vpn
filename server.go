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
	// Random 32-bit number chosen by initiator.
	// Identifies this specific handshake.
	// Prevents replay attacks.
	// Used in handshake response as `receiver` field, so initiator can
	// identify to which handshake initiation this response belongs.
	var sender [4]byte
	if err := binary.Read(r, binary.LittleEndian, &sender); err != nil {
		return err
	}
	// TODO: rewrite it because it's incorrect
	// 1. Initiator gets server's static public key from configuration before handshake.
	// 2. Initiator derives from its static private key and server's static public key shared secret.
	// 3. Initiator encrypts with server's static public key its static public key and sends it to the server.
	// 4. Server derives from its static private key and initiator's ephemeral public key shared secret.
	// 5. Server decrypts initiator's static public key with its static private key.
	//
	// Initiator's ephemeral Curve25519 public key.
	// Generated for each handshake and sent unencrypted.
	var ephemeral [32]byte
	if err := binary.Read(r, binary.LittleEndian, &ephemeral); err != nil {
		return err
	}
	// initiatorSharedSecret = curve25519.X25519(initiatorStaticPrivateKey, serverStaticPublicKey)
	// serverSharedSecret = curve25519.X25519(serverStaticPrivateKey, initiatorEphemeralPublicKey)
	// initiatorSharedSecret == serverSharedSecret
	sharedSecret, err := curve25519.X25519(s.privKey.Bytes(), ephemeral[:])
	if err != nil {
		return err
	}
	// Initiator's long-term static public key.
	// Derived from ephemeral keys. Encrypted to protect
	// initiator's identity and to provide authentication.
	var static [32]byte
	if err := binary.Read(r, binary.LittleEndian, &static); err != nil {
		return err
	}
	// decrypt initiator's static public key

	// Encrypted timestamp for replay protection.
	var timestamp [12]byte
	if err := binary.Read(r, binary.LittleEndian, &timestamp); err != nil {
		return err
	}
	// Message authentication code.
	// Verifies message integrity.
	var mac1 [16]byte
	if err := binary.Read(r, binary.LittleEndian, &mac1); err != nil {
		return err
	}
	// TODO: use a condition here
	// DoS protection using cookie challenge.
	// Mitigates DoS attacks by requiring computational work.
	// Only included if responder previously sent a cookie.
	var mac2 [16]byte
	if err := binary.Read(r, binary.LittleEndian, &mac2); err != nil {
		return err
	}
	if err := s.sendHandshakeResp(sender); err != nil {
		return err
	}
	return nil
}

// https://www.wireguard.com/protocol/
func (s *Server) sendHandshakeResp(receiver [4]byte) error {
	var resp = new(HandshakeResp)
	resp.typ = 2
	sender := make([]byte, 4)
	_, err := rand.Read(sender)
	if err != nil {
		return err
	}
	resp.sender = [4]byte(sender)
	resp.receiver = receiver
	ephemeralPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	resp.ephemeral = [32]byte(ephemeralPrivate.PublicKey().Bytes())
	hasher, err := blake2s.New256(nil)
	if err != nil {
		return err
	}
	_, err = hasher.Write([]byte(construction))
	if err != nil {
		return err
	}
	chainingKey := hasher.Sum(nil)
	hasher.Reset()
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
	_, err = hasher.Write(s.pubKey.Bytes())
	if err != nil {
		return err
	}
	hash := hasher.Sum(nil)
	temp := HMAC(chainingKey, resp.ephemeral[:])
	chainingKey = HMAC(temp, []byte{1})
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

type Peer struct {
	// 32 bytes
	publicKey  ed25519.PublicKey
	allowedIPs []net.IP
}
