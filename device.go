package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/songgao/water"
)

type device struct {
	tun        *water.Interface
	privateKey privateKeyType
	publicKey  publicKeyType
	conn       *net.UDPConn
	peers      map[publicKeyType]peer
}

func newDevice() (*device, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	tun, err := water.New(config)
	if err != nil {
		return nil, err
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &device{
		tun: tun,
		privateKey: privateKeyType(privateKey.Bytes()),
		publicKey:  publicKeyType(privateKey.PublicKey().Bytes()),
		peers:      make(map[publicKeyType]peer),
	}, nil
}

func (d *device) start(port int) error {
	addr := &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: port,
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	d.conn = conn
	fmt.Println("Device is listening on port:", port)
	return nil
}

func (d *device) readLoop() {
	for {
		// First byte is message type:
		// 	1 - handshake initiation
		//  2 - handshake response
		//  3 - cookie reply
		//  4 - data message
		// Next three bytes are always three zeros. They serve as
		// padding for 32-bit alignment and future protocol extensions.
		buf := make([]byte, 4)
		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}
		data := buf[:n]
		if len(data) < 4 {
			continue
		}
		typ := messageType(data[0])
		switch typ {
		case handshakeInitType:
		case transportDataType:
		default:
			fmt.Println("Unknown message type:", typ)
		}
		if err != nil {
			fmt.Println("Error processing message:", err)
		}
	}
}
