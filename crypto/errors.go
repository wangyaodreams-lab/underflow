// Package crypto implements the Underflow zero-knowledge cryptography core.
//
// The package is intentionally dependency-light and platform-neutral so that it
// can be compiled both natively (CLI) and to js/wasm (Web) from a single source
// of truth. See docs/CRYPTO.md for the normative specification.
package crypto

import "errors"

var (
	// ErrInvalidEnvelope indicates a malformed or truncated envelope.
	ErrInvalidEnvelope = errors.New("underflow/crypto: invalid envelope")
	// ErrUnsupportedVersion indicates an unknown envelope format version.
	ErrUnsupportedVersion = errors.New("underflow/crypto: unsupported format version")
	// ErrUnsupportedAlgorithm indicates an unknown AEAD algorithm id.
	ErrUnsupportedAlgorithm = errors.New("underflow/crypto: unsupported algorithm")
	// ErrUnsupportedKDF indicates an unknown KDF id.
	ErrUnsupportedKDF = errors.New("underflow/crypto: unsupported kdf")
	// ErrDecrypt is returned for every decryption failure without disclosing
	// whether the cause was a tag, AAD, or length mismatch.
	ErrDecrypt = errors.New("underflow/crypto: decryption failed")
	// ErrInvalidKeySize indicates a key whose length does not match the algorithm.
	ErrInvalidKeySize = errors.New("underflow/crypto: invalid key size")
	// ErrInvalidParams indicates invalid KDF parameters.
	ErrInvalidParams = errors.New("underflow/crypto: invalid kdf parameters")
	// ErrInvalidPassword indicates an invalid/empty master password input.
	ErrInvalidPassword = errors.New("underflow/crypto: invalid password")
)
