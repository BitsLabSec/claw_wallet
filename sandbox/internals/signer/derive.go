package signer

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tyler-smith/go-bip32"
)

const (
	FirstHardenedIndex = uint32(0x80000000)
)

// ParsePath parses a BIP32 derivation path like "m/44'/60'/0'/0/0"
func ParsePath(path string) ([]uint32, error) {
	if !strings.HasPrefix(path, "m/") {
		return nil, errors.New("invalid derivation path: must start with m/")
	}

	segments := strings.Split(path[2:], "/")
	var indices []uint32

	for _, seg := range segments {
		if seg == "" {
			continue
		}
		hardened := strings.HasSuffix(seg, "'")
		if hardened {
			seg = seg[:len(seg)-1] // remove quote
		}

		val, err := strconv.ParseUint(seg, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path segment: %s", seg)
		}

		index := uint32(val)
		if hardened {
			index += FirstHardenedIndex
		}
		indices = append(indices, index)
	}

	return indices, nil
}

// DeriveSecp256k1 derives a secp256k1 private key using standard BIP32
func DeriveSecp256k1(seed []byte, path string) ([]byte, error) {
	if path == "" {
		// Just parse from seed if no path provided, assuming root key derivation or simple key usage
		return seed, nil
	}
	if path == "m" || path == "m/" {
		masterKey, err := bip32.NewMasterKey(seed)
		if err != nil {
			return nil, err
		}
		return masterKey.Key, nil
	}

	indices, err := ParsePath(path)
	if err != nil {
		return nil, err
	}

	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	for _, idx := range indices {
		key, err = key.NewChildKey(idx)
		if err != nil {
			return nil, err
		}
	}

	return key.Key, nil
}

// DeriveEd25519 derives an Ed25519 private key using SLIP-0010
// Ed25519 requires all derivation path indices to be hardened.
func DeriveEd25519(seed []byte, path string) ([]byte, error) {
	if path == "" || path == "m" {
		return seed, nil
	}

	indices, err := ParsePath(path)
	if err != nil {
		return nil, err
	}

	// 1. Calculate Master Key
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(seed)
	I := mac.Sum(nil)
	kL := I[:32]
	kR := I[32:]

	for _, idx := range indices {
		if idx < FirstHardenedIndex {
			return nil, errors.New("SLIP-0010 for ed25519 only supports hardened derivation paths")
		}

		mac := hmac.New(sha512.New, kR)
		// data = 0x00 || kL || idx
		data := make([]byte, 1+32+4)
		data[0] = 0x00
		copy(data[1:33], kL)
		binary.BigEndian.PutUint32(data[33:], idx)

		mac.Write(data)
		I := mac.Sum(nil)
		kL = I[:32]
		kR = I[32:]
	}

	return kL, nil
}
