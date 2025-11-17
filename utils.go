package main

import (
	"crypto/hmac"
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
