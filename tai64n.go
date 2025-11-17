package main

import (
	"bytes"
	"encoding/binary"
	"time"
)

const (
	// By adding this large base value, WireGuard guarantees
	// that all TAI64N timestamps are positive 64-bit integers,
	// avoiding issues with signed/unsigned integer handling
	// across different systems.
	base = uint64(0x400000000000000a)
	whitenerMask = uint32(0xffffff)
)


// [ 0 1 2 3 4 5 6 7 ] [ 8 9 10 11 ]
//       8 bytes          4 bytes  
//       Seconds        Nanoseconds
//     (big-endian)     (big-endian)
type TAI64N [12]byte

func newTAI64N(t time.Time) TAI64N {
	secs := base + uint64(t.Unix())
	// "&^" bit clear (AND NOT).
	// If the second operand has 1 in that position, sets result to 0.
	// If the second operand has 0 in that position, keeps the first operand's bit.
	//
	// 0xffffff = 16,777,215
	// Before whitening: 1ns precision (1,000,000,000 values/second).
	// After whitening: ~16.7ms precision (16,777,216 values/second).
	// Prevents timing attacks: high-precision timestamps can leak information about system state and help attackers correlate events.
    // Reduces fingerprinting: unique microsecond/nanosecond patterns can identify specific devices or handshakes.
    // Hides system characteristics: different systems have different clock behaviors at high precision.
    // Still sufficient for protocol: handshakes happen every few seconds, so millisecond precision is plenty.
	//
	// Clears lower 24 bits (3 bytes).
	nano := uint32(t.Nanosecond()) &^ whitenerMask
	var tai64n TAI64N
	binary.BigEndian.PutUint64(tai64n[:], secs)
	binary.BigEndian.PutUint32(tai64n[8:], nano)
	return tai64n
}

func Now() TAI64N {
	return newTAI64N(time.Now())
}

// After calculates if t is later than t2.
func (t TAI64N) After(t2 TAI64N) bool {
	return bytes.Compare(t[:], t2[:]) > 0
}

func (t TAI64N) String() string {
	secs := int64(binary.BigEndian.Uint64(t[:8])-base)
	nano := int64(binary.BigEndian.Uint32(t[8:12]))
	return time.Unix(secs, nano).String()
}