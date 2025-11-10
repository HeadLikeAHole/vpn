package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"golang.org/x/crypto/curve25519"
)

type Server struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
	conn    *net.UDPConn
	peers   map[[32]byte]Peer
}

func NewServer() (*Server, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Server{
		pubKey:  pubKey,
		privKey: privKey,
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
		//  4 - data message
		// Next three bytes are always three zeros. Serve as padding
		// for 32-bit alignment and future protocol extensions.
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
	// Used in handshake response as `receiver` field, so peer can identify
	// to which handshake initiation this response belongs.
	var sender [4]byte
	if err := binary.Read(r, binary.LittleEndian, &sender); err != nil {
		return err
	}
	// 1. Initiator gets access to server's static public key from configuration before handshake.
	// 2. Initiator derives from its static private key and server's static public key shared secret.
	// 3. Initiator encrypts with shared secret its static public key and sends it to the server.
	// 4. Server derives from its static private key and initiator's ephemeral public key shared secret.
	// 5. Server decrypts initiator's static public key with shared secret.
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
	sharedSecret, err := curve25519.X25519(s.privKey, ephemeral[:])
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

func (s *Server) sendHandshakeResp(receiver [4]byte) error {
	return nil
}

type Peer struct {
	// 32 bytes
	publicKey  ed25519.PublicKey
	allowedIPs []net.IP
}
