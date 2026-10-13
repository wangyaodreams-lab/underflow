package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// domain-separation info strings. These MUST NOT change without a format bump.
const (
	infoAuth = "underflow/v1/auth"
	infoEnc  = "underflow/v1/enc"
	infoItem = "underflow/v1/item/"
)

func hkdfSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeriveAuthKey derives the authentication key from the master key.
func DeriveAuthKey(mk [32]byte, salt []byte) ([32]byte, error) {
	var out [32]byte
	b, err := hkdfSHA256(mk[:], salt, []byte(infoAuth), 32)
	if err != nil {
		return out, err
	}
	defer Zero(b)
	copy(out[:], b)
	return out, nil
}

// DeriveKEK derives the key-encryption key from the master key.
func DeriveKEK(mk [32]byte, salt []byte) ([32]byte, error) {
	var out [32]byte
	b, err := hkdfSHA256(mk[:], salt, []byte(infoEnc), 32)
	if err != nil {
		return out, err
	}
	defer Zero(b)
	copy(out[:], b)
	return out, nil
}

// ComputeVerifier returns HMAC-SHA256(pepper, authKey).
func ComputeVerifier(pepper []byte, authKey [32]byte) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write(authKey[:])
	return m.Sum(nil)
}

// Verify reports whether verifier == HMAC-SHA256(pepper, authKey) in constant
// time.
func Verify(authKey [32]byte, pepper, verifier []byte) bool {
	want := ComputeVerifier(pepper, authKey)
	return hmac.Equal(want, verifier)
}
