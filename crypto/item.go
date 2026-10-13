package crypto

// itemAADPrefix is the scope prefix for item ciphertexts.
const itemAADPrefix = "underflow/v1/item/"

// DeriveItemKey derives the per-item key from the vault key. Deriving a
// distinct key per item provides domain separation and limits nonce reuse
// exposure between items.
func DeriveItemKey(vk [32]byte, vaultID, itemID string) ([32]byte, error) {
	var k [32]byte
	out, err := hkdfSHA256(vk[:], nil, []byte(infoItem+vaultID+"/"+itemID), 32)
	if err != nil {
		return k, err
	}
	defer Zero(out)
	copy(k[:], out)
	return k, nil
}

func aadItem(vaultID, itemID string) []byte {
	return []byte(itemAADPrefix + vaultID + "/" + itemID)
}

// SealItem encrypts a plaintext item payload.
func SealItem(alg uint8, itemKey [32]byte, vaultID, itemID string, plaintext []byte) ([]byte, error) {
	return SealBlob(alg, itemKey[:], plaintext, aadItem(vaultID, itemID))
}

// OpenItem decrypts an item payload.
func OpenItem(itemKey [32]byte, vaultID, itemID string, envelope []byte) ([]byte, error) {
	return OpenBlob(itemKey[:], envelope, aadItem(vaultID, itemID))
}

// SealItemWithVaultKey is a convenience that derives the item key and seals in
// one call.
func SealItemWithVaultKey(alg uint8, vk [32]byte, vaultID, itemID string, plaintext []byte) ([]byte, error) {
	k, err := DeriveItemKey(vk, vaultID, itemID)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(&k)
	return SealItem(alg, k, vaultID, itemID, plaintext)
}

// OpenItemWithVaultKey derives the item key and opens in one call.
func OpenItemWithVaultKey(vk [32]byte, vaultID, itemID string, envelope []byte) ([]byte, error) {
	k, err := DeriveItemKey(vk, vaultID, itemID)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(&k)
	return OpenItem(k, vaultID, itemID, envelope)
}
