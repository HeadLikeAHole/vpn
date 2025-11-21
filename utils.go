package main

import (
	"crypto/hmac"
	"crypto/subtle"
	"hash"

	"golang.org/x/crypto/blake2s"
)

// HASH hashes inputs using BLAKE2s hash algorithm
func HASH(inputs ...[]byte) []byte {
	hasher, _ := blake2s.New256(nil)
	for _, input := range inputs {
		hasher.Write(input)
	}
	return hasher.Sum(nil)
}

func HMAC(key []byte, inputs ...[]byte) []byte {
	hasher := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	for _, input := range inputs {
		hasher.Write(input)
	}
	return hasher.Sum(nil)
}

// func isZeroNaive(val []byte) bool {
// 	  for _, b := range val {
// 		  if b != 0 {  // EARLY EXIT - TIMING LEAK!
// 			  return false
// 		  }
// 	  }
// 	  return true
// }
//
// The Security Problem: Timing Attacks
// Vulnerability:
//   The naive version exits early when it finds the first non-zero byte.
//   An attacker can measure how long the function takes to return.
//   Longer time = more leading zero bytes were found.
//   This leaks information about the secret data.
//
// Example Attack Scenario
// Attacker probes with different inputs:
// secret := []byte{0x12, 0x34, 0x56, 0x78}
// Attacker probes with different guesses
// guess1 := []byte{0x11, 0x00, 0x00, 0x00}  // wrong first byte
// Function returns after 1 iteration → FAST
// guess2 := []byte{0x12, 0x33, 0x00, 0x00}  // correct first byte, wrong second  
// Function returns after 2 iterations → SLIGHTLY SLOWER
// guess3 := []byte{0x12, 0x34, 0x55, 0x00}  // correct first two bytes
// Function returns after 3 iterations → SLOWER
// guess4 := []byte{0x12, 0x34, 0x56, 0x78}  // all correct
// Function runs all 4 iterations → SLOWEST
// By measuring timing differences, the attacker can gradually learn the secret.
func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}
