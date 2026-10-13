package crypto

import (
	"fmt"
)

// KDF identifiers.
const (
	// KDFArgon2id identifies Argon2id v1.3 (0x13).
	KDFArgon2id uint8 = 1
)

// KDF parameter bounds.
const (
	saltSize    = 16
	minMemory   = 8 * 1024        // 8 MiB
	maxMemory   = 4 * 1024 * 1024 // 4 GiB
	minTime     = 1
	maxTime     = 64
	minParallel = 1
	maxParallel = 64
)

// KDFParams describes the parameters used to derive a master key.
//
// M is memory in KiB, T is the iteration count, P is the degree of
// parallelism. Salt is the per-user random salt.
type KDFParams struct {
	ID   uint8
	M    uint32
	T    uint32
	P    uint8
	Salt [saltSize]byte
}

// Profile names a preset KDF parameter set.
type Profile string

// Supported KDF profiles.
const (
	ProfileInteractive Profile = "interactive"
	ProfileModerate    Profile = "moderate"
	ProfileParanoid    Profile = "paranoid"
)

// DefaultProfile is the profile used for new accounts.
const DefaultProfile = ProfileInteractive

// ParamsForProfile returns validated KDF parameters for a profile using salt.
func ParamsForProfile(p Profile, salt [saltSize]byte) (KDFParams, error) {
	k := KDFParams{ID: KDFArgon2id, Salt: salt}
	switch p {
	case ProfileInteractive:
		k.M, k.T, k.P = 65536, 3, 4
	case ProfileModerate:
		k.M, k.T, k.P = 262144, 4, 4
	case ProfileParanoid:
		k.M, k.T, k.P = 1048576, 6, 8
	default:
		return KDFParams{}, fmt.Errorf("%w: unknown profile %q", ErrInvalidParams, p)
	}
	return k, nil
}

// Validate checks that the parameters are within the accepted bounds.
func (k KDFParams) Validate() error {
	if k.ID != KDFArgon2id {
		return fmt.Errorf("%w: id %d", ErrUnsupportedKDF, k.ID)
	}
	if k.M < minMemory || k.M > maxMemory {
		return fmt.Errorf("%w: memory %d KiB out of range", ErrInvalidParams, k.M)
	}
	if k.T < minTime || k.T > maxTime {
		return fmt.Errorf("%w: time %d out of range", ErrInvalidParams, k.T)
	}
	if k.P < minParallel || k.P > maxParallel {
		return fmt.Errorf("%w: parallelism %d out of range", ErrInvalidParams, k.P)
	}
	return nil
}

// String renders the parameters without exposing the salt.
func (k KDFParams) String() string {
	return fmt.Sprintf("argon2id(m=%d,t=%d,p=%d)", k.M, k.T, k.P)
}
