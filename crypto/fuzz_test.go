package crypto

import (
	"bytes"
	"testing"
)

func FuzzEnvelopeDecode(f *testing.F) {
	seed, _ := SealBlob(DefaultAlgorithm, make([]byte, 32), []byte("seed"), nil)
	f.Add(seed)
	kdf, _ := ParamsForProfile(ProfileInteractive, [16]byte{})
	kenv, _ := SealKeyEnvelope(DefaultAlgorithm, [32]byte{}, kdf, make([]byte, 32), nil)
	f.Add(kenv)
	f.Add([]byte("UF\x01\x01\x18"))
	f.Add([]byte("UF\x01\x01\x01\x10"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Decoders must never panic and must fail closed on bad input.
		if h, err := decodeBlob(data); err == nil {
			if len(h.nonce) == 0 || len(h.ct) < tagSize {
				t.Fatalf("decoder accepted structurally invalid blob: %+v", h)
			}
		}
		if h, err := decodeKeyEnvelope(data); err == nil {
			if len(h.nonce) == 0 || len(h.ct) < tagSize {
				t.Fatalf("decoder accepted structurally invalid key envelope: %+v", h)
			}
		}
	})
}

func FuzzBlobRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), []byte("aad"))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, pt, aad []byte) {
		var key [32]byte
		copy(key[:], "0123456789abcdef0123456789abcdef")
		env, err := SealBlob(DefaultAlgorithm, key[:], pt, aad)
		if err != nil {
			t.Skip()
		}
		got, err := OpenBlob(key[:], env, aad)
		if err != nil {
			t.Fatalf("round trip failed: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip mismatch")
		}
	})
}
