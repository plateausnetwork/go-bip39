package bip39

import (
	"crypto/rand"
)

// NewEntropy will create random entropy bytes.
func NewEntropy(bitSize int) ([]byte, error) {
	err := validateEntropyBitSize(bitSize)
	if err != nil {
		return nil, err
	}

	entropy := make([]byte, bitSize/8)
	_, err = rand.Read(entropy)
	return entropy, err
}

// NewSeed creates a hashed seed output given the mnemonic and a password.
func NewSeed(mnemonic string, password string) ([]byte, error) {
	return DefaultEncoder.NewSeed(mnemonic, password)
}

// MarshalEntropy will return a string consisting of the mnemonic words for the
// given entropy.
func MarshalEntropy(entropy []byte) (string, error) {
	return DefaultEncoder.MarshalEntropy(entropy)
}

// UnmarshalEntropy takes a mnemonic string and turns it into a byte array.
func UnmarshalEntropy(mnemonic string) ([]byte, error) {
	return DefaultEncoder.UnmarshalEntropy(mnemonic)
}

// validateEntropyBitSize ensures that entropy is the correct size for being a
// mnemonic.
func validateEntropyBitSize(bitSize int) error {
	if (bitSize%32) != 0 || bitSize < 128 || bitSize > 256 {
		return ErrEntropyLengthInvalid
	}
	return nil
}
