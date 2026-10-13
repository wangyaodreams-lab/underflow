package crypto

import "fmt"

// AAD scope prefixes.
const (
	prefixVaultKey  = "underflow/v1/vaultkey/"
	prefixVaultName = "underflow/v1/vaultname/"
)

func aadVaultKey(vaultID string) []byte {
	return []byte(prefixVaultKey + vaultID)
}

func aadVaultName(vaultID string) []byte {
	return []byte(prefixVaultName + vaultID)
}

// WrapVaultKey encrypts vk under the KEK and returns a KeyEnvelope that embeds
// the KDF parameters for provenance.
func WrapVaultKey(kek [32]byte, alg uint8, kdf KDFParams, vaultID string, vk [32]byte) ([]byte, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("%w: empty vault id", ErrInvalidEnvelope)
	}
	return SealKeyEnvelope(alg, kek, kdf, vk[:], aadVaultKey(vaultID))
}

// UnwrapVaultKey decrypts a KeyEnvelope and returns the 32-byte vault key.
func UnwrapVaultKey(kek [32]byte, vaultID string, envelope []byte) ([32]byte, error) {
	var vk [32]byte
	pt, _, err := OpenKeyEnvelope(kek, envelope, aadVaultKey(vaultID))
	if err != nil {
		return vk, err
	}
	defer Zero(pt)
	if len(pt) != 32 {
		return vk, ErrInvalidKeySize
	}
	copy(vk[:], pt)
	return vk, nil
}

// SealVaultName encrypts a vault name with the vault key.
func SealVaultName(alg uint8, vk [32]byte, vaultID, name string) ([]byte, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("%w: empty vault id", ErrInvalidEnvelope)
	}
	return SealBlob(alg, vk[:], []byte(name), aadVaultName(vaultID))
}

// OpenVaultName decrypts a vault name with the vault key.
func OpenVaultName(vk [32]byte, vaultID string, envelope []byte) (string, error) {
	pt, err := OpenBlob(vk[:], envelope, aadVaultName(vaultID))
	if err != nil {
		return "", err
	}
	defer Zero(pt)
	return string(pt), nil
}
