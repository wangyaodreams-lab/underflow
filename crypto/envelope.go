package crypto

import (
	"encoding/binary"
	"math"
)

const (
	magic0        byte  = 'U'
	magic1        byte  = 'F'
	formatVersion uint8 = 1
)

// SealBlob encrypts plaintext and returns a versioned BlobEnvelope.
//
// The caller supplies the algorithm and a 32-byte key. A random nonce is
// generated internally. aad binds the ciphertext to its scope.
func SealBlob(alg uint8, key, plaintext, aad []byte) ([]byte, error) {
	nonce, err := RandomNonce(alg)
	if err != nil {
		return nil, err
	}
	return sealBlobWithNonce(alg, key, nonce, plaintext, aad)
}

func sealBlobWithNonce(alg uint8, key, nonce, plaintext, aad []byte) ([]byte, error) {
	ct, err := aeadSeal(alg, key, nonce, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return encodeBlob(alg, nonce, ct), nil
}

// OpenBlob decrypts a BlobEnvelope produced by SealBlob.
func OpenBlob(key, envelope, aad []byte) ([]byte, error) {
	h, err := decodeBlob(envelope)
	if err != nil {
		return nil, err
	}
	return aeadOpen(h.alg, key, h.nonce, h.ct, aad)
}

// SealKeyEnvelope encrypts plaintext (typically a 32-byte vault key) and embeds
// the KDF parameters in a KeyEnvelope.
func SealKeyEnvelope(alg uint8, kek [32]byte, kdf KDFParams, plaintext, aad []byte) ([]byte, error) {
	nonce, err := RandomNonce(alg)
	if err != nil {
		return nil, err
	}
	bound := keyEnvelopeAAD(aad, kdf)
	ct, err := aeadSeal(alg, kek[:], nonce, plaintext, bound)
	if err != nil {
		return nil, err
	}
	return encodeKeyEnvelope(alg, kdf, nonce, ct), nil
}

// OpenKeyEnvelope decrypts a KeyEnvelope and returns the plaintext together
// with the embedded KDF parameters.
func OpenKeyEnvelope(kek [32]byte, envelope, aad []byte) ([]byte, KDFParams, error) {
	h, err := decodeKeyEnvelope(envelope)
	if err != nil {
		return nil, KDFParams{}, err
	}
	bound := keyEnvelopeAAD(aad, h.kdf)
	pt, err := aeadOpen(h.alg, kek[:], h.nonce, h.ct, bound)
	if err != nil {
		return nil, KDFParams{}, err
	}
	return pt, h.kdf, nil
}

// keyEnvelopeAAD binds the embedded KDF parameters into the authentication tag
// so that tampering with them is detected.
func keyEnvelopeAAD(base []byte, kdf KDFParams) []byte {
	var tmp [binary.MaxVarintLen32]byte
	out := make([]byte, 0, len(base)+8+len(kdf.Salt))
	out = append(out, base...)
	out = append(out, 0x00, kdf.ID)
	n := binary.PutUvarint(tmp[:], uint64(kdf.M))
	out = append(out, tmp[:n]...)
	n = binary.PutUvarint(tmp[:], uint64(kdf.T))
	out = append(out, tmp[:n]...)
	n = binary.PutUvarint(tmp[:], uint64(kdf.P))
	out = append(out, tmp[:n]...)
	out = append(out, kdf.Salt[:]...)
	return out
}

// --- BlobEnvelope wire format ---
//
//	"UF" | version(1) | alg(1) | nonceLen(1) | nonce | ciphertext||tag

type blobHeader struct {
	version uint8
	alg     uint8
	nonce   []byte
	ct      []byte
}

func encodeBlob(alg uint8, nonce, ct []byte) []byte {
	out := make([]byte, 0, 5+len(nonce)+len(ct))
	// #nosec G115 -- nonce length is fixed by the algorithm (<= 24 bytes).
	out = append(out, magic0, magic1, formatVersion, alg, byte(len(nonce)))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}

func decodeBlob(env []byte) (blobHeader, error) {
	var h blobHeader
	if len(env) < 5 {
		return h, ErrInvalidEnvelope
	}
	if env[0] != magic0 || env[1] != magic1 {
		return h, ErrInvalidEnvelope
	}
	h.version = env[2]
	if h.version != formatVersion {
		return h, ErrUnsupportedVersion
	}
	h.alg = env[3]
	n, err := nonceSize(h.alg)
	if err != nil {
		return h, err
	}
	nlen := int(env[4])
	if nlen != n {
		return h, ErrInvalidEnvelope
	}
	if len(env) < 5+nlen {
		return h, ErrInvalidEnvelope
	}
	ct := env[5+nlen:]
	if len(ct) < tagSize {
		return h, ErrInvalidEnvelope
	}
	h.nonce = env[5 : 5+nlen]
	h.ct = ct
	return h, nil
}

// --- KeyEnvelope wire format ---
//
//	"UF" | version(1) | alg(1) | kdfId(1)
//	   | m(uvarint) | t(uvarint) | p(uvarint)
//	   | saltLen(1) | salt
//	   | nonceLen(1) | nonce | ciphertext||tag

type keyHeader struct {
	version uint8
	alg     uint8
	kdf     KDFParams
	nonce   []byte
	ct      []byte
}

func encodeKeyEnvelope(alg uint8, kdf KDFParams, nonce, ct []byte) []byte {
	var tmp [binary.MaxVarintLen32]byte
	out := make([]byte, 0, 64+len(nonce)+len(ct))
	out = append(out, magic0, magic1, formatVersion, alg, kdf.ID)
	n := binary.PutUvarint(tmp[:], uint64(kdf.M))
	out = append(out, tmp[:n]...)
	n = binary.PutUvarint(tmp[:], uint64(kdf.T))
	out = append(out, tmp[:n]...)
	n = binary.PutUvarint(tmp[:], uint64(kdf.P))
	out = append(out, tmp[:n]...)
	out = append(out, byte(len(kdf.Salt))) // #nosec G115 -- salt is a fixed 16-byte array.
	out = append(out, kdf.Salt[:]...)
	out = append(out, byte(len(nonce))) // #nosec G115 -- nonce length is fixed by the algorithm.
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}

func decodeKeyEnvelope(env []byte) (keyHeader, error) {
	var h keyHeader
	if len(env) < 5 {
		return h, ErrInvalidEnvelope
	}
	if env[0] != magic0 || env[1] != magic1 {
		return h, ErrInvalidEnvelope
	}
	h.version = env[2]
	if h.version != formatVersion {
		return h, ErrUnsupportedVersion
	}
	h.alg = env[3]
	h.kdf.ID = env[4]
	if h.kdf.ID != KDFArgon2id {
		return h, ErrUnsupportedKDF
	}
	p := 5
	m, n := binary.Uvarint(env[p:])
	if n <= 0 {
		return h, ErrInvalidEnvelope
	}
	p += n
	t, n := binary.Uvarint(env[p:])
	if n <= 0 {
		return h, ErrInvalidEnvelope
	}
	p += n
	par, n := binary.Uvarint(env[p:])
	if n <= 0 {
		return h, ErrInvalidEnvelope
	}
	p += n
	// Validate before narrowing so a crafted value cannot truncate into a
	// valid-looking parameter set.
	if m > math.MaxUint32 || t > math.MaxUint32 || par > math.MaxUint8 {
		return h, ErrInvalidEnvelope
	}
	h.kdf.M = uint32(m)
	h.kdf.T = uint32(t)
	h.kdf.P = uint8(par)

	if p >= len(env) {
		return h, ErrInvalidEnvelope
	}
	slen := int(env[p])
	p++
	if slen != len(h.kdf.Salt) || len(env) < p+slen {
		return h, ErrInvalidEnvelope
	}
	copy(h.kdf.Salt[:], env[p:p+slen])
	p += slen

	if p >= len(env) {
		return h, ErrInvalidEnvelope
	}
	nlen := int(env[p])
	p++
	want, err := nonceSize(h.alg)
	if err != nil {
		return h, err
	}
	if nlen != want || len(env) < p+nlen {
		return h, ErrInvalidEnvelope
	}
	h.nonce = env[p : p+nlen]
	p += nlen

	ct := env[p:]
	if len(ct) < tagSize {
		return h, ErrInvalidEnvelope
	}
	h.ct = ct

	if err := h.kdf.Validate(); err != nil {
		return h, err
	}
	return h, nil
}
