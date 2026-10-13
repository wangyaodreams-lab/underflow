package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(t *testing.T) [32]byte {
	t.Helper()
	k, err := RandomKey()
	if err != nil {
		t.Fatalf("random key: %v", err)
	}
	return k
}

func algs() []uint8 { return []uint8{AlgXChaCha20Poly1305, AlgAES256GCM} }

func TestBlobRoundTripAllAlgs(t *testing.T) {
	for _, alg := range algs() {
		t.Run(string(rune('0'+alg)), func(t *testing.T) {
			key := testKey(t)
			pt := []byte("hello underflow")
			aad := []byte("scope/a")
			env, err := SealBlob(alg, key[:], pt, aad)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			got, err := OpenBlob(key[:], env, aad)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("round trip: got %q want %q", got, pt)
			}
		})
	}
}

func TestBlobSamePlaintextProducesDifferentCiphertext(t *testing.T) {
	key := testKey(t)
	pt := []byte("deterministic? no")
	aad := []byte("scope")
	a, err := SealBlob(DefaultAlgorithm, key[:], pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealBlob(DefaultAlgorithm, key[:], pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("ciphertext is deterministic; random nonce is not working")
	}
}

func TestBlobTamperFails(t *testing.T) {
	key := testKey(t)
	env, err := SealBlob(DefaultAlgorithm, key[:], []byte("payload"), []byte("scope"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(env); i++ {
		bad := bytes.Clone(env)
		bad[i] ^= 0x01
		if _, err := OpenBlob(key[:], bad, []byte("scope")); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
}

func TestBlobAADMismatchFails(t *testing.T) {
	key := testKey(t)
	env, err := SealBlob(DefaultAlgorithm, key[:], []byte("payload"), []byte("scope/1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBlob(key[:], env, []byte("scope/2")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("AAD mismatch: got %v want ErrDecrypt", err)
	}
}

func TestBlobWrongKeyFails(t *testing.T) {
	k1, k2 := testKey(t), testKey(t)
	env, err := SealBlob(DefaultAlgorithm, k1[:], []byte("payload"), []byte("scope"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBlob(k2[:], env, []byte("scope")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: got %v want ErrDecrypt", err)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	seedKey := testKey(t)
	valid, err := SealBlob(DefaultAlgorithm, seedKey[:], []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	openKey := testKey(t)
	cases := map[string][]byte{
		"empty":     {},
		"short":     []byte("UF"),
		"badMagic":  append([]byte("XX"), valid[2:]...),
		"version":   append(append([]byte{}, valid[:2]...), append([]byte{99}, valid[3:]...)...),
		"alg":       append(append([]byte{}, valid[:3]...), append([]byte{99}, valid[4:]...)...),
		"truncated": valid[:len(valid)-1],
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenBlob(openKey[:], env, nil); err == nil {
				t.Fatalf("malformed envelope %q accepted", name)
			}
		})
	}
}

func TestKeyEnvelopeRoundTrip(t *testing.T) {
	kek := testKey(t)
	vk := testKey(t)
	kdf, err := ParamsForProfile(ProfileInteractive, [16]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("scope")
	env, err := SealKeyEnvelope(DefaultAlgorithm, kek, kdf, vk[:], aad)
	if err != nil {
		t.Fatal(err)
	}
	pt, gotKDF, err := OpenKeyEnvelope(kek, env, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, vk[:]) {
		t.Fatal("vault key mismatch")
	}
	if gotKDF != kdf {
		t.Fatalf("kdf params mismatch: got %+v want %+v", gotKDF, kdf)
	}
}

func TestKeyEnvelopeTamperFails(t *testing.T) {
	kek := testKey(t)
	kdf, _ := ParamsForProfile(ProfileInteractive, [16]byte{})
	vk := testKey(t)
	env, err := SealKeyEnvelope(DefaultAlgorithm, kek, kdf, vk[:], []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(env); i++ {
		bad := bytes.Clone(env)
		bad[i] ^= 0x80
		if _, _, err := OpenKeyEnvelope(kek, bad, []byte("aad")); err == nil {
			t.Fatalf("tampered key envelope byte %d accepted", i)
		}
	}
}

func TestVaultKeyWrapUnwrap(t *testing.T) {
	kek := testKey(t)
	vk := testKey(t)
	kdf, _ := ParamsForProfile(ProfileModerate, [16]byte{9})
	env, err := WrapVaultKey(kek, DefaultAlgorithm, kdf, "vault-1", vk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapVaultKey(kek, "vault-1", env)
	if err != nil {
		t.Fatal(err)
	}
	if got != vk {
		t.Fatal("unwrapped vault key mismatch")
	}
	if _, err := UnwrapVaultKey(kek, "vault-2", env); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("cross-vault unwrap: got %v want ErrDecrypt", err)
	}
}

func TestVaultNameSealOpen(t *testing.T) {
	vk := testKey(t)
	env, err := SealVaultName(DefaultAlgorithm, vk, "v1", "Personal")
	if err != nil {
		t.Fatal(err)
	}
	name, err := OpenVaultName(vk, "v1", env)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Personal" {
		t.Fatalf("got %q", name)
	}
	if _, err := OpenVaultName(vk, "v2", env); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("cross-vault name: got %v want ErrDecrypt", err)
	}
}

func TestItemSealOpen(t *testing.T) {
	vk := testKey(t)
	pt := []byte(`{"name":"example.com","password":"hunter2"}`)
	env, err := SealItemWithVaultKey(DefaultAlgorithm, vk, "vault-1", "item-1", pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenItemWithVaultKey(vk, "vault-1", "item-1", env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("item round trip mismatch")
	}
}

func TestItemCrossScopeFails(t *testing.T) {
	vk := testKey(t)
	env, err := SealItemWithVaultKey(DefaultAlgorithm, vk, "vault-1", "item-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenItemWithVaultKey(vk, "vault-1", "item-2", env); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("cross-item: got %v want ErrDecrypt", err)
	}
	if _, err := OpenItemWithVaultKey(vk, "vault-2", "item-1", env); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("cross-vault: got %v want ErrDecrypt", err)
	}
}

func TestDeriveItemKeyDeterministic(t *testing.T) {
	vk := testKey(t)
	a, err := DeriveItemKey(vk, "v", "i")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveItemKey(vk, "v", "i")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("item key derivation is not deterministic")
	}
	c, _ := DeriveItemKey(vk, "v", "j")
	if a == c {
		t.Fatal("item keys for different items must differ")
	}
}

func TestVerifier(t *testing.T) {
	auth := testKey(t)
	pepper := []byte("0123456789abcdef0123456789abcdef")
	v := ComputeVerifier(pepper, auth)
	if !Verify(auth, pepper, v) {
		t.Fatal("verifier did not validate")
	}
	if Verify(auth, []byte("wrong-pepper"), v) {
		t.Fatal("verifier validated with wrong pepper")
	}
	other := testKey(t)
	if Verify(other, pepper, v) {
		t.Fatal("verifier validated with wrong auth key")
	}
}

func TestKDFDeterminismAndNormalization(t *testing.T) {
	salt := [16]byte{7, 7, 7}
	p, err := ParamsForProfile(ProfileInteractive, salt)
	if err != nil {
		t.Fatal(err)
	}
	// Keep cost low for the test while staying within validation bounds.
	p.M, p.T, p.P = minMemory, 1, 1

	// NFKD: composed "é" (U+00E9) and decomposed "e"+combining acute.
	composed := "caf\u00e9"
	decomposed := "cafe\u0301"
	mk1, err := DeriveMasterKeyFromString(composed, p)
	if err != nil {
		t.Fatal(err)
	}
	mk2, err := DeriveMasterKeyFromString(decomposed, p)
	if err != nil {
		t.Fatal(err)
	}
	if mk1 != mk2 {
		t.Fatal("NFKD normalization not applied")
	}

	// Determinism.
	mk3, _ := DeriveMasterKeyFromString(composed, p)
	if mk1 != mk3 {
		t.Fatal("master key derivation is not deterministic")
	}

	// Salt sensitivity.
	p2 := p
	p2.Salt[0] ^= 0xff
	mk4, _ := DeriveMasterKeyFromString(composed, p2)
	if mk1 == mk4 {
		t.Fatal("different salts must produce different master keys")
	}
}

func TestDeriveMasterKeyRejectsEmpty(t *testing.T) {
	p, _ := ParamsForProfile(ProfileInteractive, [16]byte{})
	p.M, p.T, p.P = minMemory, 1, 1
	if _, err := DeriveMasterKey(nil, p); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("got %v want ErrInvalidPassword", err)
	}
}

func TestKDFParamsValidate(t *testing.T) {
	good, _ := ParamsForProfile(ProfileInteractive, [16]byte{})
	if err := good.Validate(); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	bad := good
	bad.M = 1
	if !errors.Is(bad.Validate(), ErrInvalidParams) {
		t.Fatal("small memory accepted")
	}
	bad = good
	bad.T = 0
	if !errors.Is(bad.Validate(), ErrInvalidParams) {
		t.Fatal("zero time accepted")
	}
	bad = good
	bad.P = 0
	if !errors.Is(bad.Validate(), ErrInvalidParams) {
		t.Fatal("zero parallelism accepted")
	}
}
