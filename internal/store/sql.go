package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/wangyaodreams-lab/underflow/internal/model"
	"github.com/wangyaodreams-lab/underflow/internal/store/migrations"
)

// dialect selects the SQL flavour and its embedded migrations.
type dialect string

const (
	dialectSQLite   dialect = "sqlite"
	dialectPostgres dialect = "postgres"
)

// rebind rewrites ? placeholders to $N for PostgreSQL.
func (d dialect) rebind(q string) string {
	if d != dialectPostgres {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(fmt.Sprint(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

func migrationsFS(d dialect) fs.FS {
	if d == dialectPostgres {
		return migrations.Postgres
	}
	return migrations.SQLite
}

type sqlStore struct {
	db *sql.DB
	d  dialect
}

// NewSQLite wraps an opened SQLite *sql.DB, applying migrations.
func NewSQLite(db *sql.DB) (Store, error) { return newSQL(db, dialectSQLite) }

// NewPostgres wraps an opened PostgreSQL *sql.DB, applying migrations.
func NewPostgres(db *sql.DB) (Store, error) { return newSQL(db, dialectPostgres) }

func newSQL(db *sql.DB, d dialect) (Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := migrate(ctx, db, d, migrationsFS(d)); err != nil {
		return nil, err
	}
	return &sqlStore{db: db, d: d}, nil
}

func nanos(t time.Time) int64     { return t.UTC().UnixNano() }
func fromNanos(n int64) time.Time { return time.Unix(0, n).UTC() }
func utcNow() time.Time           { return time.Now().UTC() }

func (s *sqlStore) q(query string) string { return s.d.rebind(query) }

func (s *sqlStore) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// --- Users ---

func (s *sqlStore) CreateUser(ctx context.Context, u model.User) error {
	if u.CreatedAt.IsZero() {
		u.CreatedAt = utcNow()
	}
	_, err := s.db.ExecContext(ctx, s.q(
		`INSERT INTO users(id,email,kdf_id,kdf_m,kdf_t,kdf_p,kdf_salt,verifier,created_at,disabled)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`),
		u.ID, u.Email, u.KDFID, u.KDFM, u.KDFT, u.KDFP, u.KDFSalt, u.Verifier, nanos(u.CreatedAt), u.Disabled)
	if isUniqueViolation(err) {
		return ErrEmailTaken
	}
	return err
}

func (s *sqlStore) UserByEmail(ctx context.Context, email string) (model.User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, s.q(
		`SELECT id,email,kdf_id,kdf_m,kdf_t,kdf_p,kdf_salt,verifier,created_at,disabled
		 FROM users WHERE email = ?`), email))
}

func (s *sqlStore) UserByID(ctx context.Context, id string) (model.User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, s.q(
		`SELECT id,email,kdf_id,kdf_m,kdf_t,kdf_p,kdf_salt,verifier,created_at,disabled
		 FROM users WHERE id = ?`), id))
}

func (s *sqlStore) scanUser(row *sql.Row) (model.User, error) {
	var u model.User
	var created int64
	var disabled bool
	err := row.Scan(&u.ID, &u.Email, &u.KDFID, &u.KDFM, &u.KDFT, &u.KDFP,
		&u.KDFSalt, &u.Verifier, &created, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	u.CreatedAt = fromNanos(created)
	u.Disabled = disabled
	return u, nil
}

func (s *sqlStore) UpdateUserKDF(ctx context.Context, userID string, kdfID uint8, m, t uint32, p uint8, salt, verifier []byte) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE users SET kdf_id=?, kdf_m=?, kdf_t=?, kdf_p=?, kdf_salt=?, verifier=? WHERE id=?`),
		kdfID, m, t, p, salt, verifier, userID)
	return mustAffect(res, err)
}

func (s *sqlStore) SetUserDisabled(ctx context.Context, userID string, disabled bool) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE users SET disabled=? WHERE id=?`), disabled, userID)
	return mustAffect(res, err)
}

// --- Vaults ---

func (s *sqlStore) CreateVault(ctx context.Context, v model.Vault) error {
	if v.CreatedAt.IsZero() {
		v.CreatedAt = utcNow()
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = v.CreatedAt
	}
	_, err := s.db.ExecContext(ctx, s.q(
		`INSERT INTO vaults(id,owner_id,name_enc,protected_vault_key,alg,created_at,updated_at,revision)
		 VALUES(?,?,?,?,?,?,?,?)`),
		v.ID, v.OwnerID, v.NameEnc, v.ProtectedVaultKey, v.Alg, nanos(v.CreatedAt), nanos(v.UpdatedAt), v.Revision)
	return err
}

func (s *sqlStore) ListVaults(ctx context.Context, userID string) ([]model.Vault, error) {
	rows, err := s.db.QueryContext(ctx, s.q(
		`SELECT id,owner_id,name_enc,protected_vault_key,alg,created_at,updated_at,revision
		 FROM vaults WHERE owner_id = ? ORDER BY created_at`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Vault
	for rows.Next() {
		v, err := scanVault(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *sqlStore) GetVault(ctx context.Context, userID, vaultID string) (model.Vault, error) {
	row := s.db.QueryRowContext(ctx, s.q(
		`SELECT id,owner_id,name_enc,protected_vault_key,alg,created_at,updated_at,revision
		 FROM vaults WHERE id = ? AND owner_id = ?`), vaultID, userID)
	v, err := scanVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}

type scanner interface{ Scan(dest ...any) error }

func scanVault(sc scanner) (model.Vault, error) {
	var v model.Vault
	var created, updated int64
	err := sc.Scan(&v.ID, &v.OwnerID, &v.NameEnc, &v.ProtectedVaultKey, &v.Alg, &created, &updated, &v.Revision)
	if err != nil {
		return v, err
	}
	v.CreatedAt = fromNanos(created)
	v.UpdatedAt = fromNanos(updated)
	return v, nil
}

func (s *sqlStore) UpdateVaultKey(ctx context.Context, userID, vaultID string, alg uint8, protectedVaultKey []byte) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE vaults SET alg=?, protected_vault_key=?, updated_at=? WHERE id=? AND owner_id=?`),
		alg, protectedVaultKey, nanos(utcNow()), vaultID, userID)
	return mustAffect(res, err)
}

func (s *sqlStore) UpdateVaultName(ctx context.Context, userID, vaultID string, nameEnc []byte) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`UPDATE vaults SET name_enc=?, updated_at=? WHERE id=? AND owner_id=?`),
		nameEnc, nanos(utcNow()), vaultID, userID)
	return mustAffect(res, err)
}

// --- Items ---

func (s *sqlStore) UpsertItem(ctx context.Context, userID string, it model.Item, baseRev int64) (model.Item, error) {
	var result model.Item
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		owned, err := vaultOwnedBy(ctx, tx, s.d, userID, it.VaultID)
		if err != nil {
			return err
		}
		if !owned {
			return ErrNotFound
		}

		var curRev int64
		var curVault string
		err = tx.QueryRowContext(ctx, s.q(`SELECT revision, vault_id FROM items WHERE id = ?`), it.ID).Scan(&curRev, &curVault)
		exists := true
		switch {
		case errors.Is(err, sql.ErrNoRows):
			exists = false
		case err != nil:
			return err
		default:
			if curVault != it.VaultID {
				return ErrNotFound
			}
			if curRev != baseRev {
				return ErrConflict
			}
		}
		if !exists && baseRev != 0 {
			return ErrNotFound
		}

		rev, err := s.nextRevision(ctx, tx)
		if err != nil {
			return err
		}
		now := utcNow()
		if !exists {
			if _, err := tx.ExecContext(ctx, s.q(
				`INSERT INTO items(id,vault_id,revision,blob,deleted,updated_at) VALUES(?,?,?,?,?,?)`),
				it.ID, it.VaultID, rev, it.Blob, false, nanos(now)); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx, s.q(
				`UPDATE items SET revision=?, blob=?, deleted=?, updated_at=? WHERE id=?`),
				rev, it.Blob, false, nanos(now), it.ID); err != nil {
				return err
			}
		}
		result = model.Item{ID: it.ID, VaultID: it.VaultID, Revision: rev, Blob: it.Blob, UpdatedAt: now}
		return nil
	})
	if err != nil {
		return model.Item{}, err
	}
	return result, nil
}

func (s *sqlStore) DeleteItem(ctx context.Context, userID, vaultID, itemID string, baseRev int64) (model.Item, error) {
	var result model.Item
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		owned, err := vaultOwnedBy(ctx, tx, s.d, userID, vaultID)
		if err != nil {
			return err
		}
		if !owned {
			return ErrNotFound
		}
		var curRev int64
		err = tx.QueryRowContext(ctx, s.q(`SELECT revision FROM items WHERE id=? AND vault_id=?`), itemID, vaultID).Scan(&curRev)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if curRev != baseRev {
			return ErrConflict
		}
		rev, err := s.nextRevision(ctx, tx)
		if err != nil {
			return err
		}
		now := utcNow()
		if _, err := tx.ExecContext(ctx, s.q(
			`UPDATE items SET revision=?, deleted=?, updated_at=? WHERE id=?`),
			rev, true, nanos(now), itemID); err != nil {
			return err
		}
		result = model.Item{ID: itemID, VaultID: vaultID, Revision: rev, Deleted: true, UpdatedAt: now}
		return nil
	})
	if err != nil {
		return model.Item{}, err
	}
	return result, nil
}

func (s *sqlStore) GetItem(ctx context.Context, userID, vaultID, itemID string) (model.Item, error) {
	row := s.db.QueryRowContext(ctx, s.q(
		`SELECT i.id, i.vault_id, i.revision, i.blob, i.deleted, i.updated_at
		 FROM items i JOIN vaults v ON v.id = i.vault_id
		 WHERE i.id=? AND i.vault_id=? AND v.owner_id=?`), itemID, vaultID, userID)
	var it model.Item
	var updated int64
	err := row.Scan(&it.ID, &it.VaultID, &it.Revision, &it.Blob, &it.Deleted, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return it, ErrNotFound
	}
	if err != nil {
		return it, err
	}
	it.UpdatedAt = fromNanos(updated)
	return it, nil
}

func (s *sqlStore) Sync(ctx context.Context, userID string, since int64) ([]model.Item, int64, error) {
	rows, err := s.db.QueryContext(ctx, s.q(
		`SELECT i.id, i.vault_id, i.revision, i.blob, i.deleted, i.updated_at
		 FROM items i JOIN vaults v ON v.id = i.vault_id
		 WHERE v.owner_id = ? AND i.revision > ?
		 ORDER BY i.revision ASC`), userID, since)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.Item
	for rows.Next() {
		var it model.Item
		var updated int64
		if err := rows.Scan(&it.ID, &it.VaultID, &it.Revision, &it.Blob, &it.Deleted, &updated); err != nil {
			return nil, 0, err
		}
		it.UpdatedAt = fromNanos(updated)
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var cur int64
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM sync_counter WHERE id = 1`).Scan(&cur); err != nil {
		return nil, 0, err
	}
	return out, cur, nil
}

func (s *sqlStore) nextRevision(ctx context.Context, tx *sql.Tx) (int64, error) {
	var rev int64
	if err := tx.QueryRowContext(ctx,
		`UPDATE sync_counter SET value = value + 1 WHERE id = 1 RETURNING value`).Scan(&rev); err != nil {
		return 0, err
	}
	return rev, nil
}

func vaultOwnedBy(ctx context.Context, tx *sql.Tx, d dialect, userID, vaultID string) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, d.rebind(`SELECT 1 FROM vaults WHERE id=? AND owner_id=?`), vaultID, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// --- Sessions ---

func (s *sqlStore) CreateSession(ctx context.Context, sess model.Session) error {
	_, err := s.db.ExecContext(ctx, s.q(
		`INSERT INTO sessions(id,user_id,token_hash,device_label,created_at,expires_at,last_seen_at)
		 VALUES(?,?,?,?,?,?,?)`),
		sess.ID, sess.UserID, sess.TokenHash, sess.DeviceLabel,
		nanos(sess.CreatedAt), nanos(sess.ExpiresAt), nanos(sess.LastSeenAt))
	return err
}

func (s *sqlStore) SessionByTokenHash(ctx context.Context, hash []byte) (model.Session, error) {
	row := s.db.QueryRowContext(ctx, s.q(
		`SELECT id,user_id,token_hash,device_label,created_at,expires_at,last_seen_at
		 FROM sessions WHERE token_hash = ?`), hash)
	var sess model.Session
	var created, expires, seen int64
	err := row.Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.DeviceLabel, &created, &expires, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, ErrNotFound
	}
	if err != nil {
		return sess, err
	}
	sess.CreatedAt = fromNanos(created)
	sess.ExpiresAt = fromNanos(expires)
	sess.LastSeenAt = fromNanos(seen)
	return sess, nil
}

func (s *sqlStore) TouchSession(ctx context.Context, id string, at int64) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE sessions SET last_seen_at=? WHERE id=?`), at, id)
	return mustAffect(res, err)
}

func (s *sqlStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE id=?`), id)
	return err
}

func (s *sqlStore) DeleteSessionsForUser(ctx context.Context, userID, exceptID string) (int64, error) {
	var res sql.Result
	var err error
	if exceptID == "" {
		res, err = s.db.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE user_id=?`), userID)
	} else {
		res, err = s.db.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE user_id=? AND id<>?`), userID, exceptID)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *sqlStore) DeleteExpiredSessions(ctx context.Context, beforeNanos int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE expires_at < ?`), beforeNanos)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Audit ---

func (s *sqlStore) AddAudit(ctx context.Context, e model.AuditEntry) error {
	_, err := s.db.ExecContext(ctx, s.q(
		`INSERT INTO audit_log(id,user_id,action,ip,ua,at) VALUES(?,?,?,?,?,?)`),
		e.ID, e.UserID, e.Action, e.IP, e.UA, nanos(e.At))
	return err
}

// --- Health ---

func (s *sqlStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *sqlStore) Close() error                   { return s.db.Close() }

// --- helpers ---

func mustAffect(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "unique constraint") ||
		strings.Contains(m, "duplicate key") ||
		strings.Contains(m, "unique violation") ||
		strings.Contains(m, "23505")
}
