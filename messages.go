package main

type MessageType uint8

const (
	handshakeInitType MessageType = 1
	handshakeRespType MessageType = 2
	dataMessageType   MessageType = 4
)

// Handshake establishes symmetric keys to be used for data transfer.
// This handshake occurs every few minutes, in order to provide
// rotating keys for forward secrecy.
type HandshakeInit struct {
	// Type of message. Always set to 1 for handshake initiation.
	typ MessageType
	// Always three zeros.
	// Padding for 32-bit alignment and future protocol extensions.
	reserved [3]byte
	// Random 32-bit number chosen by initiator.
	// Identifies this specific handshake.
	// Prevents replay attacks.
	// Used in response messages to match initiation.
	sender [4]byte
	// Initiator's ephemeral Curve25519 public key for key exchange.
	// Generated for each handshake and sent unencrypted.
	ephemeral [32]byte
	// Initiator's long-term static public key.
	// Derived from ephemeral keys.
	// Encrypted to protect initiator's identity and to provide authentication.
	static [32]byte
	// Encrypted timestamp for replay protection.
	timestamp [12]byte
	// Message authentication code.
	// Verifies message integrity.
	mac1 [16]byte
	// DoS protection using cookie challenge.
	// Mitigates DoS attacks by requiring computational work.
	// Only included if responder previously sent a cookie.
	mac2 [16]byte
}

type HandshakeResp struct {
	// Type of message. Always set to 2 for handshake response.
	typ uint8
	// Always three zeros.
	// Padding for 32-bit alignment and future protocol extensions.
	reserved [3]byte
	// Random 32-bit number chosen by responder (server).
	// Identifies this specific handshake.
	sender [4]byte
	// Copied directly from `sender` of the handshake initiation.
	// Allows initiator to match response with their request to
	// prevent confusion when multiple handshakes are in progress.
	receiver [4]byte
	// Responder's ephemeral Curve25519 public key for key exchange.
	// Generated for each handshake and sent unencrypted.
	ephemeral [32]byte
	// Cryptographic authentication without payload.
	// Provides cryptographic proof that responder has the correct keys.
	empty [0]byte
	// Message authentication code.
	// Verifies message integrity and authenticates the responder.
	mac1 [16]byte
	// DoS protection.
	// Mitigates amplification attacks by requiring computational work.
	mac2 [16]byte
}

type DataMessage struct {
	// Type of message. Always set to 4 for data message.
	typ uint8
	// Always three zeros.
	// Padding for 32-bit alignment and future protocol extensions.
	reserved [3]byte
	// Identifies which cryptographic session this packet belongs to.
	// It contains the index of the recipient's current sending key.
	// It tells the receiver: "Use the private key associated
	// with this index to decrypt the payload of this message."
	// During the handshake, peers exchange and store
	// each other's public keys and assign them an index.
	// This index is a much smaller and more efficient way
	// to reference the correct key for a session than sending
	// the full public key with every data packet.
	receiver [4]byte
	// Number used for replay protection.
	// Each peer keeps a counter for the packets they send.
	// This value is incremented for every new data message.
	// The receiver remembers the highest counter value
	// it has seen for a given session.
	// If it receives a packet with a counter value
	// that is less than or equal to the one
	// it has already seen, it discards the packet.
	// This prevents an attacker from capturing a valid
	// packet and replaying it later to disrupt
	// the connection or perform other attacks.
	counter [8]byte
	// The actual data being sent through the tunnel, but in a processed form.
	// The original plaintext IP packet (e.g., a TCP segment from browser)
	// that needs to be sent through the tunnel is encrypted and authenticated
	// using the symmetric keys derived during the handshake.
	// The encryption algorithm is ChaCha20, and the authentication
	// is provided by Poly1305 (together, "ChaCha20Poly1305").
	// A 16-byte authentication tag (MAC) is appended
	// to the encrypted data to ensure integrity.
	// TODO: check later if the algorithm above is correct
	packet []byte
}
