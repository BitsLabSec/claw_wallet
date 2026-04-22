// sandbox/internals/crypto/aes.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const DefaultPBKDF2Iterations = 600000

// DeriveKeyFromPassword mirrors the TS PBKDF2 implementation.
func DeriveKeyFromPassword(password []byte, salt []byte) []byte {
	return DeriveKeyFromPasswordWithIterations(password, salt, DefaultPBKDF2Iterations)
}

// DeriveKeyFromPasswordWithIterations allows legacy share decryption to opt into older KDF work factors.
func DeriveKeyFromPasswordWithIterations(password []byte, salt []byte, iterations int) []byte {
	if iterations <= 0 {
		iterations = DefaultPBKDF2Iterations
	}
	return pbkdf2.Key(password, salt, iterations, 32, sha256.New)
}

// DecryptData mirrors the TS AES-GCM decryption
func DecryptData(key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(iv) != aesgcm.NonceSize() {
		return nil, errors.New("AES-GCM decryption failed: incorrect nonce length")
	}

	// In WebCrypto AES-GCM, the auth tag (16 bytes) is appended to the ciphertext
	// Go's Open also expects this format.
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, errors.New("AES-GCM decryption failed (wrong PIN or corrupted data)")
	}

	return plaintext, nil
}

// EncryptData mirrors the TS AES-GCM encryption
func EncryptData(key []byte, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)
	return ciphertext, iv, nil
}
