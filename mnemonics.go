package mnemonics

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"strconv"
	"golang.org/x/crypto/pbkdf2"
)

type Bits []byte

// CheckSum takes the first ENT/32 bits of sha256 hash of entropy and appends this to entropy as per BIP39 spec
func CheckSummed(ent []byte) Bits {
	h := sha256.New()
	h.Write(ent)
	cs := h.Sum(nil)
	hashBits := bytesToBits(cs)
	num := len(ent) * 8 / 32
	cs = hashBits[:num] 
	bits := bytesToBits(ent)
	return append(bits, cs...)
}

func bytesToBits(bytes []byte) Bits {
	length := len(bytes)
	bits := make([]byte, length*8)
	for i := 0; i < length; i++ {
		b := bytes[i]
		for j := 0; j < 8; j++ {
			mask := byte(1 << uint8(j))
			bit := b & mask
			if bit == 0 {
				bits[(i*8)+8-(j+1)] = '0'
			} else {
				bits[(i*8)+8-(j+1)] = '1'
			}
		}
	}
	return bits
}

func GenEntropy(length int) ([]byte, error) {
	if length < 128 {
		return nil, errors.New("length must be at least 128 bits")
	}
	b := make([]byte, length/8)
	_, err := rand.Read(b)
	return b, err
}

func NewMnemonic(ent []byte) ([]string, error) {
	const size = 11
	bits := CheckSummed(ent)
	length := len(bits)
	words := make([]string, length/11)
	for i := 0; i < length; i += size {
		stringVal := string(bits[i : size+i])
		intVal, err := strconv.ParseInt(stringVal, 2, 64)
		if err != nil {
			return nil, errors.New("Could not convert" +stringVal +" to word index")
		}
		word := ReturnWord(intVal)
		words[(size+i)/11-1] = word
	}
	return words, nil
}

func NewSeed(mnemonic string, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}