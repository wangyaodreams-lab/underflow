// Package model defines the persisted entities of Underflow.
//
// All secret material stored in these structs is already encrypted by the
// client; the server never holds plaintext or the master password.
package model

import "time"

// User is an account. KDF* describe how the master key is derived from the
// master password; Verifier is HMAC-SHA256(serverPepper, AuthKey).
type User struct {
	ID        string
	Email     string
	KDFID     uint8
	KDFM      uint32
	KDFT      uint32
	KDFP      uint8
	KDFSalt   []byte
	Verifier  []byte
	CreatedAt time.Time
	Disabled  bool
}

// Vault is an encrypted container owned by a single user.
type Vault struct {
	ID                string
	OwnerID           string
	NameEnc           []byte
	ProtectedVaultKey []byte
	Alg               uint8
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Revision          int64
}

// Item is an encrypted entry. Blob is opaque ciphertext; Deleted marks a
// tombstone retained for sync.
type Item struct {
	ID        string
	VaultID   string
	Revision  int64
	Blob      []byte
	Deleted   bool
	UpdatedAt time.Time
}

// Session is an opaque authenticated session. TokenHash is SHA-256 of the
// bearer token; the token itself is never stored.
type Session struct {
	ID          string
	UserID      string
	TokenHash   []byte
	DeviceLabel string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastSeenAt  time.Time
}

// AuditEntry is a metadata-only audit record (never contains secrets).
type AuditEntry struct {
	ID     string
	UserID string
	Action string
	IP     string
	UA     string
	At     time.Time
}
