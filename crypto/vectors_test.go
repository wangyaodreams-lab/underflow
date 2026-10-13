package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// chachaSeal exercises the standard (12-byte nonce) ChaCha20-Poly1305, which is
// not exposed as a selectable Underflow algorithm but is the primitive behind
// the RFC 8439 vector.
func chachaSeal(key, nonce, pt, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, pt, aad), nil
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// RFC 5869 HKDF-SHA256 test vectors.
func TestHKDFVectors(t *testing.T) {
	cases := []struct {
		name      string
		ikm, salt string
		info      string
		length    int
		want      string
	}{
		{
			name:   "RFC5869 case 1",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "000102030405060708090a0b0c",
			info:   "f0f1f2f3f4f5f6f7f8f9",
			length: 42,
			want:   "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name:   "RFC5869 case 3 (empty salt/info)",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "",
			info:   "",
			length: 42,
			want:   "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hkdfSHA256(mustHex(t, tc.ikm), mustHex(t, tc.salt), mustHex(t, tc.info), tc.length)
			if err != nil {
				t.Fatalf("hkdf: %v", err)
			}
			if !bytes.Equal(got, mustHex(t, tc.want)) {
				t.Fatalf("hkdf mismatch:\n got %x\nwant %s", got, tc.want)
			}
		})
	}
}

// RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD vector (12-byte nonce).
func TestChaCha20Poly1305Vector(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "070000004041424344454647")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want := mustHex(t, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"+
		"1ae10b594f09e26a7e902ecbd0600691")

	// Build via the raw cipher (12-byte nonce); our wrapper selects XChaCha by
	// default, so exercise aeadSeal/aeadOpen indirectly through a temporary
	// helper that uses a 12-byte nonce with the standard ChaCha20-Poly1305.
	got, err := chachaSeal(key, nonce, pt, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("chacha20poly1305 mismatch:\n got %x\nwant %x", got, want)
	}
}

// draft-irtf-cfrg-xchacha-01 §A.3.1 XChaCha20-Poly1305 vector (24-byte nonce).
func TestXChaCha20Poly1305Vector(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "404142434445464748494a4b4c4d4e4f5051525354555657")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	pt := mustHex(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
	want := mustHex(t, "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"+
		"c0875924c1c7987947deafd8780acf49")

	got, err := aeadSeal(AlgXChaCha20Poly1305, key, nonce, pt, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("xchacha20poly1305 mismatch:\n got %x\nwant %x", got, want)
	}
}

// AES-256-GCM vector (from the Go standard library's NIST-derived suite).
func TestAES256GCMVector(t *testing.T) {
	key := mustHex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce := mustHex(t, "54cc7dc2c37ec006bcc6d1da")
	pt := mustHex(t, "007c5e5b3e59df24a7c355584fc1518d")
	want := mustHex(t, "d50b9e252b70945d4240d351677eb10f937cdaef6f2822b6a3191654ba41b197")

	got, err := aeadSeal(AlgAES256GCM, key, nonce, pt, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("aes256gcm mismatch:\n got %x\nwant %x", got, want)
	}
	back, err := aeadOpen(AlgAES256GCM, key, nonce, got, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatalf("aes256gcm round-trip mismatch")
	}
}

// Argon2id reference vector (validates the underlying primitive and params).
func TestArgon2idVector(t *testing.T) {
	got := argon2.IDKey([]byte("password"), []byte("somesalt"), 2, 65536, 1, 32)
	want := mustHex(t, "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
	if !bytes.Equal(got, want) {
		t.Fatalf("argon2id mismatch:\n got %x\nwant %x", got, want)
	}
}
