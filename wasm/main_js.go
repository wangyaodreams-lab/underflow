//go:build js && wasm

// Command wasm exposes the Underflow crypto core to the browser as a
// JavaScript global `underflow`. All binary values cross the boundary as
// base64 strings so the JS side never has to manage Go memory.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/pwgen"
)

type kdfJSON struct {
	ID   uint8  `json:"id"`
	M    uint32 `json:"m"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
	Salt string `json:"salt"`
}

func (k kdfJSON) toParams() (crypto.KDFParams, error) {
	var p crypto.KDFParams
	if k.ID == 0 {
		k.ID = crypto.KDFArgon2id
	}
	salt, err := base64.StdEncoding.DecodeString(k.Salt)
	if err != nil {
		return p, fmt.Errorf("invalid salt encoding")
	}
	if len(salt) != 16 {
		return p, fmt.Errorf("salt must be 16 bytes")
	}
	p.ID, p.M, p.T, p.P = k.ID, k.M, k.T, k.P
	copy(p.Salt[:], salt)
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func main() {
	api := map[string]any{
		"deriveMasterKey":  js.FuncOf(fnDeriveMasterKey),
		"deriveAuthKey":    js.FuncOf(fnDeriveAuthKey),
		"deriveKEK":        js.FuncOf(fnDeriveKEK),
		"wrapVaultKey":     js.FuncOf(fnWrapVaultKey),
		"unwrapVaultKey":   js.FuncOf(fnUnwrapVaultKey),
		"sealVaultName":    js.FuncOf(fnSealVaultName),
		"openVaultName":    js.FuncOf(fnOpenVaultName),
		"sealItem":         js.FuncOf(fnSealItem),
		"openItem":         js.FuncOf(fnOpenItem),
		"randomBytes":      js.FuncOf(fnRandomBytes),
		"generatePassword": js.FuncOf(fnGeneratePassword),
	}
	js.Global().Set("underflow", js.ValueOf(api))
	select {}
}

func fail(format string, args ...any) {
	panic(js.Global().Get("Error").New(fmt.Sprintf(format, args...)))
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fail("invalid base64 input")
	}
	return b
}

func mustKey32(s string) [32]byte {
	var k [32]byte
	b := mustB64(s)
	if len(b) != 32 {
		fail("expected a 32-byte key")
	}
	copy(k[:], b)
	return k
}

func parseKDF(s string) crypto.KDFParams {
	var k kdfJSON
	if err := json.Unmarshal([]byte(s), &k); err != nil {
		fail("invalid kdf parameters: %v", err)
	}
	p, err := k.toParams()
	if err != nil {
		fail("invalid kdf parameters: %v", err)
	}
	return p
}

func fnDeriveMasterKey(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		fail("deriveMasterKey(password, kdfJson)")
	}
	mk, err := crypto.DeriveMasterKeyFromString(args[0].String(), parseKDF(args[1].String()))
	if err != nil {
		fail("derive master key: %v", err)
	}
	return b64(mk[:])
}

func fnDeriveAuthKey(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		fail("deriveAuthKey(masterKeyB64, saltB64)")
	}
	ak, err := crypto.DeriveAuthKey(mustKey32(args[0].String()), mustB64(args[1].String()))
	if err != nil {
		fail("derive auth key: %v", err)
	}
	return b64(ak[:])
}

func fnDeriveKEK(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		fail("deriveKEK(masterKeyB64, saltB64)")
	}
	kek, err := crypto.DeriveKEK(mustKey32(args[0].String()), mustB64(args[1].String()))
	if err != nil {
		fail("derive kek: %v", err)
	}
	return b64(kek[:])
}

func fnWrapVaultKey(_ js.Value, args []js.Value) any {
	if len(args) < 5 {
		fail("wrapVaultKey(kekB64, alg, kdfJson, vaultId, vaultKeyB64)")
	}
	kek := mustKey32(args[0].String())
	alg := uint8(args[1].Int())
	kdf := parseKDF(args[2].String())
	vaultID := args[3].String()
	vk := mustKey32(args[4].String())
	out, err := crypto.WrapVaultKey(kek, alg, kdf, vaultID, vk)
	if err != nil {
		fail("wrap vault key: %v", err)
	}
	return b64(out)
}

func fnUnwrapVaultKey(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		fail("unwrapVaultKey(kekB64, vaultId, protectedB64)")
	}
	vk, err := crypto.UnwrapVaultKey(mustKey32(args[0].String()), args[1].String(), mustB64(args[2].String()))
	if err != nil {
		fail("unwrap vault key (wrong master password?): %v", err)
	}
	return b64(vk[:])
}

func fnSealVaultName(_ js.Value, args []js.Value) any {
	if len(args) < 4 {
		fail("sealVaultName(alg, vaultKeyB64, vaultId, name)")
	}
	out, err := crypto.SealVaultName(uint8(args[0].Int()), mustKey32(args[1].String()), args[2].String(), args[3].String())
	if err != nil {
		fail("seal vault name: %v", err)
	}
	return b64(out)
}

func fnOpenVaultName(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		fail("openVaultName(vaultKeyB64, vaultId, encB64)")
	}
	name, err := crypto.OpenVaultName(mustKey32(args[0].String()), args[1].String(), mustB64(args[2].String()))
	if err != nil {
		fail("open vault name: %v", err)
	}
	return name
}

func fnSealItem(_ js.Value, args []js.Value) any {
	if len(args) < 5 {
		fail("sealItem(alg, vaultKeyB64, vaultId, itemId, plaintext)")
	}
	out, err := crypto.SealItemWithVaultKey(uint8(args[0].Int()), mustKey32(args[1].String()), args[2].String(), args[3].String(), []byte(args[4].String()))
	if err != nil {
		fail("seal item: %v", err)
	}
	return b64(out)
}

func fnOpenItem(_ js.Value, args []js.Value) any {
	if len(args) < 4 {
		fail("openItem(vaultKeyB64, vaultId, itemId, blobB64)")
	}
	out, err := crypto.OpenItemWithVaultKey(mustKey32(args[0].String()), args[1].String(), args[2].String(), mustB64(args[3].String()))
	if err != nil {
		fail("open item: %v", err)
	}
	return string(out)
}

func fnRandomBytes(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		fail("randomBytes(n)")
	}
	n := args[0].Int()
	if n <= 0 || n > 1<<20 {
		fail("invalid byte count")
	}
	b, err := crypto.RandomBytes(n)
	if err != nil {
		fail("random bytes: %v", err)
	}
	return b64(b)
}

type genOpts struct {
	Length     int  `json:"length"`
	Lower      bool `json:"lower"`
	Upper      bool `json:"upper"`
	Digits     bool `json:"digits"`
	Symbols    bool `json:"symbols"`
	ExcludeAmb bool `json:"excludeAmbiguous"`
}

func fnGeneratePassword(_ js.Value, args []js.Value) any {
	opts := pwgen.DefaultOptions()
	if len(args) >= 1 && args[0].String() != "" {
		if err := json.Unmarshal([]byte(args[0].String()), &opts); err != nil {
			fail("invalid generator options: %v", err)
		}
	}
	pw, err := pwgen.Generate(pwgen.Options{
		Length: opts.Length, Lower: opts.Lower, Upper: opts.Upper,
		Digits: opts.Digits, Symbols: opts.Symbols, ExcludeAmb: opts.ExcludeAmb,
	})
	if err != nil {
		fail("generate password: %v", err)
	}
	return pw
}
