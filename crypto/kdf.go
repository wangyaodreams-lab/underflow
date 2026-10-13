package crypto

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// NormalizePassword applies NFKD normalization and returns UTF-8 bytes.
//
// The returned slice should be zeroed by the caller when no longer needed.
func NormalizePassword(password string) []byte {
	return []byte(norm.NFKD.String(password))
}

// DeriveMasterKey derives the 32-byte master key from a normalized password.
func DeriveMasterKey(password []byte, p KDFParams) ([32]byte, error) {
	var mk [32]byte
	if len(password) == 0 {
		return mk, ErrInvalidPassword
	}
	if err := p.Validate(); err != nil {
		return mk, err
	}
	switch p.ID {
	case KDFArgon2id:
		out := argon2.IDKey(password, p.Salt[:], p.T, p.M, p.P, 32)
		copy(mk[:], out)
		Zero(out)
	default:
		return mk, ErrUnsupportedKDF
	}
	return mk, nil
}

// DeriveMasterKeyFromString normalizes then derives.
func DeriveMasterKeyFromString(password string, p KDFParams) ([32]byte, error) {
	norm := NormalizePassword(password)
	defer Zero(norm)
	return DeriveMasterKey(norm, p)
}
