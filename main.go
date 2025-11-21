package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// WireGuard constants
const (
	WG_PORT                  = 51820
	WG_MTU                   = 1420
	WG_KEY_LEN               = 32
	WG_COOKIE_LEN            = 16
	WG_MAC1_LEN              = 16
	WG_MAC2_LEN              = 16
	WG_TIMESTAMP_LEN         = 12
	WG_COUNTER_LEN           = 8
	WG_TYPE_HANDSHAKE_INIT   = 1
	WG_TYPE_HANDSHAKE_RESP   = 2
	WG_TYPE_HANDSHAKE_COOKIE = 3
	WG_TYPE_DATA             = 4
)

// Packet structures
type MessageHeader struct {
	Type     uint32
	Reserved uint32
}

type HandshakeInit_ struct {
	Header               MessageHeader
	SenderIndex          uint32
	UnencryptedEphemeral [32]byte
	EncryptedStatic      [48]byte
	EncryptedTimestamp   [28]byte
	MAC1                 [16]byte
	MAC2                 [16]byte
}

type HandshakeResponse struct {
	Header               MessageHeader
	SenderIndex          uint32
	ReceiverIndex        uint32
	UnencryptedEphemeral [32]byte
	EncryptedNothing     [48]byte
	MAC1                 [16]byte
	MAC2                 [16]byte
}

type DataPacket struct {
	Header        MessageHeader
	ReceiverIndex uint32
	Counter       uint64
	EncryptedData []byte
}

// Cryptographic primitives
type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

type Session_ struct {
	LocalIndex      uint32
	RemoteIndex     uint32
	LocalEphemeral  KeyPair
	RemoteEphemeral [32]byte
	SendingKey      [32]byte
	ReceivingKey    [32]byte
	LastSent        time.Time
	LastReceived    time.Time
}

// WireGuard peer
type Peer_ struct {
	PublicKey  [32]byte
	Endpoint   *net.UDPAddr
	Session    *Session
	AllowedIPs []*net.IPNet
	mu         sync.RWMutex
}

// WireGuard device
type Device struct {
	PrivateKey   KeyPair
	PublicKey    [32]byte
	Peers        map[[32]byte]*Peer
	ListenPort   int
	Conn         *net.UDPConn
	mu           sync.RWMutex
	CookieSecret [32]byte
	LastCookie   [16]byte
}

// Utility functions
func generateKeypair() (KeyPair, error) {
	var kp KeyPair
	_, err := rand.Read(kp.Private[:])
	if err != nil {
		return kp, err
	}

	// In real implementation, this would use Curve25519
	// For simplicity, we'll use a hash-based approach
	hash := sha256.Sum256(kp.Private[:])
	copy(kp.Public[:], hash[:])

	return kp, nil
}

func computeMAC(key []byte, data []byte) [16]byte {
	// Simplified MAC computation (in real WG this uses Poly1305)
	var mac [16]byte
	h := sha256.New()
	h.Write(key)
	h.Write(data)
	hash := h.Sum(nil)
	copy(mac[:], hash[:16])
	return mac
}

func (d *Device) generateCookie(senderPubKey [32]byte) [16]byte {
	var cookie [16]byte
	h := sha256.New()
	h.Write(d.CookieSecret[:])
	h.Write(senderPubKey[:])
	hash := h.Sum(nil)
	copy(cookie[:], hash[:16])
	return cookie
}

// Core WireGuard protocol implementation
func (d *Device) createHandshakeInit(peer *Peer) (*HandshakeInit, error) {
	// Generate ephemeral keypair
	ephemeral, err := generateKeypair()
	if err != nil {
		return nil, err
	}

	// Create session
	session := &Session{
		LocalIndex:     binary.LittleEndian.Uint32([]byte{1, 0, 0, 0}), // Simple index
		LocalEphemeral: ephemeral,
		LastSent:       time.Now(),
	}

	peer.Session = session

	msg := &HandshakeInit{
		Header: MessageHeader{
			Type: WG_TYPE_HANDSHAKE_INIT,
		},
		SenderIndex: session.LocalIndex,
	}

	// Copy ephemeral public key
	copy(msg.UnencryptedEphemeral[:], ephemeral.Public[:])

	// In real implementation, we'd encrypt static key and timestamp
	// For this example, we'll use placeholder values
	rand.Read(msg.EncryptedStatic[:])
	rand.Read(msg.EncryptedTimestamp[:])

	// Compute MACs (simplified)
	msg.MAC1 = computeMAC(d.CookieSecret[:], msg.UnencryptedEphemeral[:])

	return msg, nil
}

func (d *Device) processHandshakeInit(data []byte, remoteAddr *net.UDPAddr) error {
	if len(data) < binary.Size(HandshakeInit{}) {
		return errors.New("handshake init too short")
	}

	var msg HandshakeInit
	// Parse message (simplified - real implementation would use binary.Read)
	copy(msg.UnencryptedEphemeral[:], data[8:40])
	copy(msg.EncryptedStatic[:], data[40:88])
	copy(msg.EncryptedTimestamp[:], data[88:116])
	copy(msg.MAC1[:], data[116:132])

	// Look up peer by public key or create new one
	var peerPubKey [32]byte
	// In real implementation, we'd derive this from the encrypted static
	copy(peerPubKey[:], msg.UnencryptedEphemeral[:32])

	peer, exists := d.Peers[peerPubKey]
	if !exists {
		peer = &Peer{
			PublicKey: peerPubKey,
			Endpoint:  remoteAddr,
		}
		d.Peers[peerPubKey] = peer
	}

	// Create handshake response
	return d.createHandshakeResponse(peer)
}

func (d *Device) createHandshakeResponse(peer *Peer) error {
	ephemeral, err := generateKeypair()
	if err != nil {
		return err
	}

	if peer.Session == nil {
		peer.Session = &Session{}
	}

	peer.Session.RemoteEphemeral = peer.PublicKey // Simplified
	peer.Session.LocalEphemeral = ephemeral

	msg := &HandshakeResponse{
		Header: MessageHeader{
			Type: WG_TYPE_HANDSHAKE_RESP,
		},
		SenderIndex:   peer.Session.LocalIndex,
		ReceiverIndex: peer.Session.RemoteIndex,
	}

	copy(msg.UnencryptedEphemeral[:], ephemeral.Public[:])
	rand.Read(msg.EncryptedNothing[:])
	msg.MAC1 = computeMAC(d.CookieSecret[:], msg.UnencryptedEphemeral[:])

	// Send response
	return d.sendHandshakeResponse(msg, peer.Endpoint)
}

func (d *Device) sendHandshakeResponse(msg *HandshakeResponse, addr *net.UDPAddr) error {
	data := make([]byte, binary.Size(msg))
	binary.LittleEndian.PutUint32(data[0:4], msg.Header.Type)
	binary.LittleEndian.PutUint32(data[4:8], msg.Header.Reserved)
	binary.LittleEndian.PutUint32(data[8:12], msg.SenderIndex)
	binary.LittleEndian.PutUint32(data[12:16], msg.ReceiverIndex)
	copy(data[16:48], msg.UnencryptedEphemeral[:])
	copy(data[48:96], msg.EncryptedNothing[:])
	copy(data[96:112], msg.MAC1[:])

	_, err := d.Conn.WriteToUDP(data, addr)
	return err
}

func (d *Device) processHandshakeResponse(data []byte, remoteAddr *net.UDPAddr) error {
	if len(data) < binary.Size(HandshakeResponse{}) {
		return errors.New("handshake response too short")
	}

	// Find peer by endpoint (simplified)
	var peer *Peer
	for _, p := range d.Peers {
		if p.Endpoint.String() == remoteAddr.String() {
			peer = p
			break
		}
	}

	if peer == nil {
		return errors.New("peer not found")
	}

	// Derive session keys (simplified)
	if peer.Session != nil {
		// In real implementation, we'd use key derivation from handshake
		hash := sha256.Sum256(append(peer.Session.LocalEphemeral.Public[:], peer.PublicKey[:]...))
		copy(peer.Session.SendingKey[:], hash[:16])
		copy(peer.Session.ReceivingKey[:], hash[16:])
		peer.Session.LastReceived = time.Now()
	}

	return nil
}

// Data packet handling
func (d *Device) encryptDataPacket(peer *Peer, plaintext []byte) (*DataPacket, error) {
	if peer.Session == nil {
		return nil, errors.New("no active session")
	}

	packet := &DataPacket{
		Header: MessageHeader{
			Type: WG_TYPE_DATA,
		},
		ReceiverIndex: peer.Session.RemoteIndex,
		Counter:       uint64(time.Now().UnixNano()),
	}

	// Simple XOR encryption (in real WG this uses ChaCha20)
	encrypted := make([]byte, len(plaintext))
	for i := range plaintext {
		encrypted[i] = plaintext[i] ^ peer.Session.SendingKey[i%len(peer.Session.SendingKey)]
	}
	packet.EncryptedData = encrypted

	return packet, nil
}

func (d *Device) decryptDataPacket(peer *Peer, packet *DataPacket) ([]byte, error) {
	if peer.Session == nil {
		return nil, errors.New("no active session")
	}

	// Simple XOR decryption
	plaintext := make([]byte, len(packet.EncryptedData))
	for i := range packet.EncryptedData {
		plaintext[i] = packet.EncryptedData[i] ^ peer.Session.ReceivingKey[i%len(peer.Session.ReceivingKey)]
	}

	return plaintext, nil
}

func (d *Device) SendData(peerPubKey [32]byte, data []byte) error {
	d.mu.RLock()
	peer, exists := d.Peers[peerPubKey]
	d.mu.RUnlock()

	if !exists || peer.Session == nil {
		return errors.New("peer not found or no session")
	}

	packet, err := d.encryptDataPacket(peer, data)
	if err != nil {
		return err
	}

	// Serialize and send packet
	packetData := make([]byte, 16+len(packet.EncryptedData))
	binary.LittleEndian.PutUint32(packetData[0:4], packet.Header.Type)
	binary.LittleEndian.PutUint32(packetData[4:8], packet.Header.Reserved)
	binary.LittleEndian.PutUint32(packetData[8:12], packet.ReceiverIndex)
	binary.LittleEndian.PutUint64(packetData[12:20], packet.Counter)
	copy(packetData[20:], packet.EncryptedData)

	_, err = d.Conn.WriteToUDP(packetData, peer.Endpoint)
	return err
}

// Main packet processing loop
func (d *Device) readLoop() {
	buffer := make([]byte, 65535)

	for {
		n, addr, err := d.Conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("Read error: %v\n", err)
			continue
		}

		data := buffer[:n]

		if len(data) < 4 {
			continue
		}

		msgType := binary.LittleEndian.Uint32(data[0:4])

		switch msgType {
		case WG_TYPE_HANDSHAKE_INIT:
			err = d.processHandshakeInit(data, addr)
		case WG_TYPE_HANDSHAKE_RESP:
			err = d.processHandshakeResponse(data, addr)
		case WG_TYPE_DATA:
			err = d.processDataPacket(data, addr)
		default:
			fmt.Printf("Unknown message type: %d\n", msgType)
		}

		if err != nil {
			fmt.Printf("Error processing packet: %v\n", err)
		}
	}
}

func (d *Device) processDataPacket(data []byte, remoteAddr *net.UDPAddr) error {
	if len(data) < 20 {
		return errors.New("data packet too short")
	}

	// Find peer by endpoint
	var peer *Peer
	for _, p := range d.Peers {
		if p.Endpoint.String() == remoteAddr.String() {
			peer = p
			break
		}
	}

	if peer == nil {
		return errors.New("peer not found for data packet")
	}

	packet := &DataPacket{
		Header: MessageHeader{
			Type: binary.LittleEndian.Uint32(data[0:4]),
		},
		ReceiverIndex: binary.LittleEndian.Uint32(data[8:12]),
		Counter:       binary.LittleEndian.Uint64(data[12:20]),
		EncryptedData: data[20:],
	}

	plaintext, err := d.decryptDataPacket(peer, packet)
	if err != nil {
		return err
	}

	fmt.Printf("Received data from %s: %s\n", remoteAddr, string(plaintext))
	return nil
}

// Device management
func NewDevice() (*Device, error) {
	privateKey, err := generateKeypair()
	if err != nil {
		return nil, err
	}

	device := &Device{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public,
		Peers:      make(map[[32]byte]*Peer),
		ListenPort: WG_PORT,
	}

	rand.Read(device.CookieSecret[:])
	return device, nil
}

func (d *Device) Listen() error {
	addr := &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: d.ListenPort,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	d.Conn = conn
	go d.readLoop()
	return nil
}

func (d *Device) AddPeer(publicKey [32]byte, endpoint string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return err
	}

	peer := &Peer{
		PublicKey: publicKey,
		Endpoint:  udpAddr,
	}

	d.mu.Lock()
	d.Peers[publicKey] = peer
	d.mu.Unlock()

	// Initiate handshake
	_, err = d.createHandshakeInit(peer)
	return err
}

// Example usage
func main() {
	// Create device
	device, err := NewDevice()
	if err != nil {
		panic(err)
	}

	// Start listening
	err = device.Listen()
	if err != nil {
		panic(err)
	}

	fmt.Printf("WireGuard device listening on port %d\n", WG_PORT)

	// Example: Add a peer (in real usage, you'd get this from configuration)
	// peerPubKey := [32]byte{...}
	// device.AddPeer(peerPubKey, "192.168.1.100:51820")

	// Keep the program running
	select {}
}

// Sending:

//     Your OS has an IP packet to send to a peer in the VPN (e.g., 10.0.0.2).

//     The WireGuard interface encapsulates this packet.

//     WireGuard looks up the peer associated with 10.0.0.2 and finds their current session keys and index.

//     It constructs the packet_data header: sets message_type=4, reserved_zero=0, the peer's receiver_index, and increments the counter.

//     It encrypts the original IP packet using ChaCha20Poly1305 with the session key, producing the encrypted_encapsulated_packet.

//     The full message is sent over the network (UDP) to the peer.

// Receiving:

//     The peer receives a UDP packet. The first byte is 4, so it's a data message.

//     It uses the receiver_index to find the correct decryption key for this session.

//     It checks the counter to ensure this isn't a replayed packet.

//     It verifies the integrity and decrypts the encrypted_encapsulated_packet using Poly1305 and ChaCha20.

//     If successful, the decrypted original IP packet is injected into the peer's local network stack as if it was received directly.
