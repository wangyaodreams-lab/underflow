// Package store defines the persistence contract for Underflow and provides
// SQL-backed implementations over SQLite and PostgreSQL.
package store

import (
	"context"
	"errors"

	"github.com/wangyaodreams-lab/underflow/internal/model"
)

// Sentinel errors returned by Store implementations.
var (
	// ErrNotFound indicates the requested entity does not exist or is not
	// visible to the requesting subject.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict indicates an optimistic-concurrency revision mismatch.
	ErrConflict = errors.New("store: revision conflict")
	// ErrEmailTaken indicates the email is already registered.
	ErrEmailTaken = errors.New("store: email already registered")
)

// Store is the persistence interface. Every method that reads or mutates user
// data takes a subject identifier (userID / ownerID) so that implementations
// can enforce multi-tenant isolation.
type Store interface {
	// Users.
	CreateUser(ctx context.Context, u model.User) error
	UserByEmail(ctx context.Context, email string) (model.User, error)
	UserByID(ctx context.Context, id string) (model.User, error)
	UpdateUserKDF(ctx context.Context, userID string, kdfID uint8, m, t uint32, p uint8, salt, verifier []byte) error
	SetUserDisabled(ctx context.Context, userID string, disabled bool) error

	// Vaults.
	CreateVault(ctx context.Context, v model.Vault) error
	ListVaults(ctx context.Context, userID string) ([]model.Vault, error)
	GetVault(ctx context.Context, userID, vaultID string) (model.Vault, error)
	UpdateVaultKey(ctx context.Context, userID, vaultID string, alg uint8, protectedVaultKey []byte) error
	UpdateVaultName(ctx context.Context, userID, vaultID string, nameEnc []byte) error

	// Items.
	UpsertItem(ctx context.Context, userID string, it model.Item, baseRev int64) (model.Item, error)
	DeleteItem(ctx context.Context, userID, vaultID, itemID string, baseRev int64) (model.Item, error)
	GetItem(ctx context.Context, userID, vaultID, itemID string) (model.Item, error)
	Sync(ctx context.Context, userID string, since int64) ([]model.Item, int64, error)

	// Sessions.
	CreateSession(ctx context.Context, s model.Session) error
	SessionByTokenHash(ctx context.Context, hash []byte) (model.Session, error)
	TouchSession(ctx context.Context, id string, at int64) error
	DeleteSession(ctx context.Context, id string) error
	DeleteSessionsForUser(ctx context.Context, userID, exceptID string) (int64, error)
	DeleteExpiredSessions(ctx context.Context, beforeNanos int64) (int64, error)

	// Audit.
	AddAudit(ctx context.Context, e model.AuditEntry) error

	// Health.
	Ping(ctx context.Context) error
	Close() error
}
