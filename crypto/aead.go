package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD algorithm identifiers.
const (
	AlgXChaCha20Poly1305 uint8 = 1
	AlgAES256GCM         uint8 = 2

	// DefaultAlgorithm is the default AEAD for new vaults/items.
	DefaultAlgorithm uint8 = AlgXChaCha20Poly1305

	tagSize = 16
)

func nonceSize(alg uint8) (int, error) {
	switch alg {
	case AlgXChaCha20Poly1305:
		return chacha20poly1305.NonceSizeX, nil
	case AlgAES256GCM:
		return 12, nil
	default:
		return 0, ErrUnsupportedAlgorithm
	}
}

func newAEAD(alg uint8, key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}
	switch alg {
	case AlgXChaCha20Poly1305:
		return chacha20poly1305.NewX(key)
	case AlgAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// aeadSeal seals plaintext with an explicit nonce.
func aeadSeal(alg uint8, key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(alg, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrInvalidEnvelope
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// aeadOpen opens ciphertext with an explicit nonce.
func aeadOpen(alg uint8, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(alg, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
