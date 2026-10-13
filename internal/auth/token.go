// Package auth provides session tokens, verifier helpers and rate limiting.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// TokenBytes is the entropy of a session token.
const TokenBytes = 32

// NewToken returns a fresh opaque token and the SHA-256 hash to persist.
func NewToken() (token string, hash []byte, err error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken returns SHA-256 of the token string.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NewCSRF returns a random CSRF double-submit token.
func NewCSRF() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
