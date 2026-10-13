package crypto

import "crypto/rand"

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomKey returns a fresh 32-byte key.
func RandomKey() ([32]byte, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	return k, nil
}

// RandomNonce returns a fresh nonce of the size required by alg.
func RandomNonce(alg uint8) ([]byte, error) {
	n, err := nonceSize(alg)
	if err != nil {
		return nil, err
	}
	return RandomBytes(n)
}
