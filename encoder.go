package bip39

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"strings"

	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/pbkdf2"
)

var (
	// DefaultEncoder is the endoder used by package-root level functions.
	DefaultEncoder = English

	// ChineseSimplified is an Encoder initialized with the Chinese Simplified
	// wordlist
	ChineseSimplified = NewEncoder(wordlists.ChineseSimplified)

	// ChineseTraditional is an Encoder initialized with the Chinese Traditional
	// wordlist
	ChineseTraditional = NewEncoder(wordlists.ChineseTraditional)

	// English is an Encoder initialized with the English wordlist
	English = NewEncoder(wordlists.English)

	// Italian is an Encoder initialized with the Italian wordlist
	Italian = NewEncoder(wordlists.Italian)

	// Japanese is an Encoder initialized with the Japanese wordlist
	Japanese = NewEncoder(wordlists.Japanese)

	// Korean is an Encoder initialized with the Korean wordlist
	Korean = NewEncoder(wordlists.Korean)

	// Spanish is an Encoder initialized with the Spanish wordlist
	Spanish = NewEncoder(wordlists.Spanish)

	// Some bitwise operands for working with big.Ints
	bigOne                  = big.NewInt(1)
	bigTwo                  = big.NewInt(2)
	last11BitsMask          = big.NewInt(2047)
	rightShift11BitsDivider = big.NewInt(2048)
)

// Encoder allows marshalling and unmarshaling of random entropy as defined by
// the BIP39 spec.
type Encoder struct {
	wordList []string
	wordMap  map[string]int
}

// NewEncoder returns a new Encoder for the given wordlist.
func NewEncoder(wordList []string) *Encoder {
	e := &Encoder{
		wordList: wordList,
		wordMap:  make(map[string]int, len(wordList)),
	}

	for i, v := range wordList {
		e.wordMap[v] = i
	}

	return e
}

// MarshalEntropy encodes entropy as a mnemonic phrase.
func (e *Encoder) MarshalEntropy(entropy []byte) (string, error) {
	// Compute some lengths for convenience
	entropyBitLength := len(entropy) * 8
	checksumBitLength := entropyBitLength / 32
	sentenceLength := (entropyBitLength + checksumBitLength) / 11

	err := validateEntropyBitSize(entropyBitLength)
	if err != nil {
		return "", err
	}

	// Add checksum to entropy
	entropy = addChecksum(entropy)

	// Break entropy up into sentenceLength chunks of 11 bits
	// For each word AND mask the rightmost 11 bits and find the word at that index
	// Then bitshift entropy 11 bits right and repeat
	// Add to the last empty slot so we can work with LSBs instead of MSB

	// Entropy as an int so we can bitmask without worrying about bytes slices
	entropyInt := new(big.Int).SetBytes(entropy)

	// Slice to hold words in
	words := make([]string, sentenceLength)

	// Throw away big int for AND masking
	word := big.NewInt(0)

	for i := sentenceLength - 1; i >= 0; i-- {
		// Get 11 right most bits and bitshift 11 to the right for next time
		word.And(entropyInt, last11BitsMask)
		entropyInt.Div(entropyInt, rightShift11BitsDivider)

		// Get the bytes representing the 11 bits as a 2 byte slice
		wordBytes := padByteSlice(word.Bytes(), 2)

		// Convert bytes to an index and add that word to the list
		words[i] = e.wordList[binary.BigEndian.Uint16(wordBytes)]
	}

	return strings.Join(words, " "), nil
}

// UnmarshalEntropy decodes a mnemonic phrase into raw entropy.
func (e *Encoder) UnmarshalEntropy(mnemonic string) ([]byte, error) {
	var (
		mnemonicSlice    = strings.Fields(mnemonic)
		wordCount        = len(mnemonicSlice)
		entropyBitSize   = wordCount * 11
		checksumBitSize  = entropyBitSize % 32
		fullByteSize     = (entropyBitSize-checksumBitSize)/8 + 1
		checksumByteSize = fullByteSize - (fullByteSize % 4)
	)

	// The number of words should be 12, 15, 18, 21 or 24
	if wordCount%3 != 0 || wordCount < 12 || wordCount > 24 {
		return nil, ErrMnemonicLengthInvalid
	}

	// Convert word indices to a `big.Int` representing the entropy
	checksummedEntropy := big.NewInt(0)
	for _, v := range mnemonicSlice {
		index, ok := e.wordMap[v]
		if !ok {
			return nil, ErrMnemonicWordInvalid
		}
		checksummedEntropy.Mul(checksummedEntropy, rightShift11BitsDivider)
		checksummedEntropy.Add(checksummedEntropy, big.NewInt(int64(index)))
	}

	// Calculate the unchecksummed entropy so we can validate that the checksum is
	// correct
	checksumModulo := big.NewInt(0).Exp(bigTwo, big.NewInt(int64(checksumBitSize)), nil)
	rawEntropy := big.NewInt(0).Div(checksummedEntropy, checksumModulo)

	// Convert `big.Int`s to byte padded byte slices
	rawEntropyBytes := padByteSlice(rawEntropy.Bytes(), checksumByteSize)
	checksummedEntropyBytes := padByteSlice(checksummedEntropy.Bytes(), fullByteSize)

	// Validate that the checksum is correct
	newChecksummedEntropyBytes := padByteSlice(addChecksum(rawEntropyBytes), fullByteSize)
	if !compareByteSlices(checksummedEntropyBytes, newChecksummedEntropyBytes) {
		return nil, ErrChecksumIncorrect
	}

	return checksummedEntropyBytes, nil
}

// NewSeed creates a hashed seed from given the mnemonic and a password.
// The mnemonic is checked for validity.
func (e *Encoder) NewSeed(mnemonic string, password string) ([]byte, error) {
	_, err := e.UnmarshalEntropy(mnemonic)
	if err != nil {
		return nil, err
	}
	return createSeedHash(mnemonic, password), nil
}

// createSeedHash calculates a seed hash from an arbitrary string.
func createSeedHash(mnemonic string, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}

// addChecksum appends to data the first (len(data) / 32)bits of the result of
// sha256(data). Currently only supports data up to 32 bytes.
func addChecksum(data []byte) []byte {
	// Get first byte of sha256
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	firstChecksumByte := hash[0]

	// len() is in bytes so we divide by 4
	checksumBitLength := uint(len(data) / 4)

	// For each bit of checksum we want we shift the data one the left
	// and then set the (new) right most bit equal to checksum bit at that index
	// staring from the left
	dataBigInt := new(big.Int).SetBytes(data)
	for i := uint(0); i < checksumBitLength; i++ {
		// Bitshift 1 left
		dataBigInt.Mul(dataBigInt, bigTwo)

		// Set rightmost bit if leftmost checksum bit is set
		if uint8(firstChecksumByte&(1<<(7-i))) > 0 {
			dataBigInt.Or(dataBigInt, bigOne)
		}
	}

	return dataBigInt.Bytes()
}

// padByteSlice returns a byte slice of the given size with contents of the
// given slice left padded and any empty spaces filled with 0's.
func padByteSlice(slice []byte, length int) []byte {
	if len(slice) >= length {
		return slice
	}
	newSlice := make([]byte, length-len(slice))
	return append(newSlice, slice...)
}

// compareByteSlices returns true of the byte slices have equal contents and
// returns false otherwise.
func compareByteSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
