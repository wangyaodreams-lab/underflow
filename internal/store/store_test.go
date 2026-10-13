package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wangyaodreams-lab/underflow/internal/model"
	"github.com/wangyaodreams-lab/underflow/internal/store"
	"github.com/wangyaodreams-lab/underflow/internal/store/postgres"
	"github.com/wangyaodreams-lab/underflow/internal/store/sqlite"
)

func newSQLiteStore(t *testing.T) store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "underflow-test.db")
	st, err := sqlite.Open(context.Background(), sqlite.Options{Path: path})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSQLiteContract(t *testing.T) {
	runContract(t, newSQLiteStore(t))
}

// TestPostgresContract runs the same suite against PostgreSQL when
// UF_TEST_PG_DSN is set, otherwise it is skipped.
func TestPostgresContract(t *testing.T) {
	dsn := os.Getenv("UF_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("UF_TEST_PG_DSN not set")
	}
	st, err := postgres.Open(context.Background(), postgres.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	runContract(t, st)
}

func runContract(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("users", func(t *testing.T) {
		u := model.User{
			ID: "u1", Email: "alice@example.com",
			KDFID: 1, KDFM: 65536, KDFT: 3, KDFP: 4,
			KDFSalt: []byte("0123456789abcdef"), Verifier: []byte("verifier"),
			CreatedAt: now,
		}
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		if err := st.CreateUser(ctx, u); !errors.Is(err, store.ErrEmailTaken) {
			t.Fatalf("duplicate email: got %v want ErrEmailTaken", err)
		}

		got, err := st.UserByEmail(ctx, "alice@example.com")
		if err != nil {
			t.Fatalf("by email: %v", err)
		}
		if got.ID != "u1" || got.KDFM != 65536 || string(got.KDFSalt) != "0123456789abcdef" {
			t.Fatalf("user mismatch: %+v", got)
		}
		if _, err := st.UserByID(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing user: got %v want ErrNotFound", err)
		}

		if err := st.UpdateUserKDF(ctx, "u1", 1, 262144, 4, 4, []byte("fedcba9876543210"), []byte("v2")); err != nil {
			t.Fatalf("update kdf: %v", err)
		}
		got, _ = st.UserByEmail(ctx, "alice@example.com")
		if got.KDFM != 262144 || string(got.Verifier) != "v2" {
			t.Fatalf("kdf update not applied: %+v", got)
		}
		if err := st.UpdateUserKDF(ctx, "ghost", 1, 1, 1, 1, nil, nil); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("update missing user: got %v want ErrNotFound", err)
		}
	})

	// Bob is used for cross-tenant isolation checks.
	bob := model.User{
		ID: "u2", Email: "bob@example.com",
		KDFID: 1, KDFM: 65536, KDFT: 3, KDFP: 4,
		KDFSalt: []byte("salt-salt-salt16"), Verifier: []byte("vb"),
		CreatedAt: now,
	}
	if err := st.CreateUser(ctx, bob); err != nil {
		t.Fatalf("create bob: %v", err)
	}

	t.Run("vaults", func(t *testing.T) {
		v := model.Vault{
			ID: "v1", OwnerID: "u1",
			NameEnc: []byte("name-ct"), ProtectedVaultKey: []byte("key-ct"),
			Alg: 1, CreatedAt: now, UpdatedAt: now,
		}
		if err := st.CreateVault(ctx, v); err != nil {
			t.Fatalf("create vault: %v", err)
		}
		list, err := st.ListVaults(ctx, "u1")
		if err != nil || len(list) != 1 {
			t.Fatalf("list vaults: %v len=%d", err, len(list))
		}
		if _, err := st.GetVault(ctx, "u2", "v1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-user vault read: got %v want ErrNotFound", err)
		}
		if err := st.UpdateVaultKey(ctx, "u2", "v1", 1, []byte("hijack")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-user vault write: got %v want ErrNotFound", err)
		}
		if err := st.UpdateVaultKey(ctx, "u1", "v1", 1, []byte("rewrapped")); err != nil {
			t.Fatalf("update vault key: %v", err)
		}
	})

	t.Run("items sync and conflict", func(t *testing.T) {
		first, err := st.UpsertItem(ctx, "u1", model.Item{ID: "i1", VaultID: "v1", Blob: []byte("blob1")}, 0)
		if err != nil {
			t.Fatalf("insert item: %v", err)
		}
		if first.Revision == 0 {
			t.Fatal("insert did not assign a revision")
		}
		// Stale base revision must conflict.
		if _, err := st.UpsertItem(ctx, "u1", model.Item{ID: "i1", VaultID: "v1", Blob: []byte("blob2")}, first.Revision+100); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("stale update: got %v want ErrConflict", err)
		}
		// Correct base revision succeeds and bumps revision.
		upd, err := st.UpsertItem(ctx, "u1", model.Item{ID: "i1", VaultID: "v1", Blob: []byte("blob2")}, first.Revision)
		if err != nil {
			t.Fatalf("update item: %v", err)
		}
		if upd.Revision <= first.Revision {
			t.Fatalf("revision did not advance: %d -> %d", first.Revision, upd.Revision)
		}
		// Update of a non-existent item with non-zero base revision.
		if _, err := st.UpsertItem(ctx, "u1", model.Item{ID: "ghost", VaultID: "v1"}, 5); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("ghost update: got %v want ErrNotFound", err)
		}
		// Cross-tenant write.
		if _, err := st.UpsertItem(ctx, "u2", model.Item{ID: "i2", VaultID: "v1", Blob: []byte("x")}, 0); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-user insert: got %v want ErrNotFound", err)
		}
		// Cross-vault item id reuse must not leak.
		if _, err := st.UpsertItem(ctx, "u1", model.Item{ID: "i1", VaultID: "v-missing", Blob: []byte("x")}, first.Revision); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("wrong vault: got %v want ErrNotFound", err)
		}

		items, cur, err := st.Sync(ctx, "u1", 0)
		if err != nil {
			t.Fatalf("sync: %v", err)
		}
		if len(items) != 1 || string(items[0].Blob) != "blob2" {
			t.Fatalf("sync payload mismatch: %+v", items)
		}
		if cur < upd.Revision {
			t.Fatalf("current revision %d < item revision %d", cur, upd.Revision)
		}
		// Cross-tenant sync must be empty.
		other, _, err := st.Sync(ctx, "u2", 0)
		if err != nil {
			t.Fatalf("sync u2: %v", err)
		}
		if len(other) != 0 {
			t.Fatalf("u2 saw %d foreign items", len(other))
		}

		got, err := st.GetItem(ctx, "u1", "v1", "i1")
		if err != nil || string(got.Blob) != "blob2" {
			t.Fatalf("get item: %v %+v", err, got)
		}
		if _, err := st.GetItem(ctx, "u2", "v1", "i1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-user get item: got %v want ErrNotFound", err)
		}
	})

	t.Run("delete tombstone", func(t *testing.T) {
		items, _, _ := st.Sync(ctx, "u1", 0)
		rev := items[0].Revision
		del, err := st.DeleteItem(ctx, "u1", "v1", "i1", rev)
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		if !del.Deleted {
			t.Fatal("delete did not mark tombstone")
		}
		changed, _, _ := st.Sync(ctx, "u1", rev)
		if len(changed) != 1 || !changed[0].Deleted {
			t.Fatalf("tombstone not propagated: %+v", changed)
		}
		if _, err := st.DeleteItem(ctx, "u2", "v1", "i1", del.Revision); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-user delete: got %v want ErrNotFound", err)
		}
	})

	t.Run("sessions", func(t *testing.T) {
		s := model.Session{
			ID: "s1", UserID: "u1", TokenHash: []byte("hash1"), DeviceLabel: "cli",
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now,
		}
		if err := st.CreateSession(ctx, s); err != nil {
			t.Fatalf("create session: %v", err)
		}
		got, err := st.SessionByTokenHash(ctx, []byte("hash1"))
		if err != nil || got.ID != "s1" || got.UserID != "u1" {
			t.Fatalf("session lookup: %v %+v", err, got)
		}
		if _, err := st.SessionByTokenHash(ctx, []byte("missing")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing session: got %v want ErrNotFound", err)
		}
		if err := st.TouchSession(ctx, "s1", now.Add(time.Minute).UnixNano()); err != nil {
			t.Fatalf("touch: %v", err)
		}
		// Expired session cleanup.
		expired := model.Session{
			ID: "s2", UserID: "u1", TokenHash: []byte("hash2"),
			CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), LastSeenAt: now.Add(-2 * time.Hour),
		}
		if err := st.CreateSession(ctx, expired); err != nil {
			t.Fatalf("create expired: %v", err)
		}
		n, err := st.DeleteExpiredSessions(ctx, now.UnixNano())
		if err != nil || n != 1 {
			t.Fatalf("delete expired: n=%d err=%v", n, err)
		}
		if err := st.DeleteSession(ctx, "s1"); err != nil {
			t.Fatalf("delete session: %v", err)
		}
		if _, err := st.SessionByTokenHash(ctx, []byte("hash1")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("deleted session still present: %v", err)
		}
	})

	t.Run("audit and ping", func(t *testing.T) {
		if err := st.AddAudit(ctx, model.AuditEntry{ID: "a1", UserID: "u1", Action: "login", IP: "127.0.0.1", UA: "test", At: now}); err != nil {
			t.Fatalf("audit: %v", err)
		}
		if err := st.Ping(ctx); err != nil {
			t.Fatalf("ping: %v", err)
		}
	})
}
