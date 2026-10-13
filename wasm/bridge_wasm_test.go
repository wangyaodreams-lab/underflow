//go:build js && wasm

package main

import (
	"encoding/base64"
	"encoding/json"
	"syscall/js"
	"testing"

	"github.com/wangyaodreams-lab/underflow/crypto"
)

// kdf returns a low-cost KDF descriptor as JSON for tests.
func testKDF(t *testing.T) (string, [16]byte) {
	t.Helper()
	var salt [16]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	k := crypto.KDFParams{ID: crypto.KDFArgon2id, M: 8192, T: 1, P: 1, Salt: salt}
	b, err := json.Marshal(kdfJSON{ID: k.ID, M: k.M, T: k.T, P: k.P, Salt: base64.StdEncoding.EncodeToString(k.Salt[:])})
	if err != nil {
		t.Fatal(err)
	}
	return string(b), salt
}

func TestBridgeDeriveMatchesGo(t *testing.T) {
	kdfStr, salt := testKDF(t)
	mkB64 := fnDeriveMasterKey(js.Undefined(), []js.Value{js.ValueOf("Password123!"), js.ValueOf(kdfStr)}).(string)

	wantMK, err := crypto.DeriveMasterKeyFromString("Password123!", crypto.KDFParams{ID: crypto.KDFArgon2id, M: 8192, T: 1, P: 1, Salt: salt})
	if err != nil {
		t.Fatal(err)
	}
	if mkB64 != base64.StdEncoding.EncodeToString(wantMK[:]) {
		t.Fatal("bridge master key differs from native")
	}

	saltB64 := base64.StdEncoding.EncodeToString(salt[:])
	authB64 := fnDeriveAuthKey(js.Undefined(), []js.Value{js.ValueOf(mkB64), js.ValueOf(saltB64)}).(string)
	kekB64 := fnDeriveKEK(js.Undefined(), []js.Value{js.ValueOf(mkB64), js.ValueOf(saltB64)}).(string)

	wantAuth, _ := crypto.DeriveAuthKey(wantMK, salt[:])
	wantKEK, _ := crypto.DeriveKEK(wantMK, salt[:])
	if authB64 != base64.StdEncoding.EncodeToString(wantAuth[:]) {
		t.Fatal("bridge auth key differs from native")
	}
	if kekB64 != base64.StdEncoding.EncodeToString(wantKEK[:]) {
		t.Fatal("bridge kek differs from native")
	}
}

func TestBridgeItemRoundTrip(t *testing.T) {
	kdfStr, _ := testKDF(t)
	vaultID := "vault-1"
	itemID := "item-1"

	vkB64 := fnRandomBytes(js.Undefined(), []js.Value{js.ValueOf(32)}).(string)
	plaintext := `{"name":"example.com","password":"hunter2"}`

	blob := fnSealItem(js.Undefined(), []js.Value{
		js.ValueOf(crypto.AlgXChaCha20Poly1305), js.ValueOf(vkB64), js.ValueOf(vaultID), js.ValueOf(itemID), js.ValueOf(plaintext),
	}).(string)

	got := fnOpenItem(js.Undefined(), []js.Value{js.ValueOf(vkB64), js.ValueOf(vaultID), js.ValueOf(itemID), js.ValueOf(blob)}).(string)
	if got != plaintext {
		t.Fatalf("bridge item round trip mismatch: %s", got)
	}

	// Vault key wrap/unwrap via the bridge.
	kekB64 := fnDeriveKEK(js.Undefined(), []js.Value{
		js.ValueOf(fnDeriveMasterKey(js.Undefined(), []js.Value{js.ValueOf("Password123!"), js.ValueOf(kdfStr)}).(string)),
		js.ValueOf(base64.StdEncoding.EncodeToString(mustSalt(t, kdfStr))),
	}).(string)
	prot := fnWrapVaultKey(js.Undefined(), []js.Value{
		js.ValueOf(kekB64), js.ValueOf(float64(crypto.AlgXChaCha20Poly1305)), js.ValueOf(kdfStr), js.ValueOf(vaultID), js.ValueOf(vkB64),
	}).(string)
	unwrapped := fnUnwrapVaultKey(js.Undefined(), []js.Value{js.ValueOf(kekB64), js.ValueOf(vaultID), js.ValueOf(prot)}).(string)
	if unwrapped != vkB64 {
		t.Fatal("bridge vault key wrap/unwrap mismatch")
	}
}

func mustSalt(t *testing.T, kdfStr string) []byte {
	t.Helper()
	var k kdfJSON
	if err := json.Unmarshal([]byte(kdfStr), &k); err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(k.Salt)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
