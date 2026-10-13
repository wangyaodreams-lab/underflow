// Package sqlite opens a pure-Go (CGO-free) SQLite-backed Store.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/wangyaodreams-lab/underflow/internal/store"
)

// DriverName is the database/sql driver name registered by modernc.org/sqlite.
const DriverName = "sqlite"

// Options configures the SQLite connection.
type Options struct {
	// Path is the database file path. Use ":memory:" for an ephemeral database.
	Path string
	// BusyTimeout is how long to wait on a locked database (default 5s).
	BusyTimeout time.Duration
}

// DSN builds a modernc.org/sqlite URI with WAL, foreign keys and busy timeout.
func (o Options) DSN() string {
	busy := o.BusyTimeout
	if busy <= 0 {
		busy = 5 * time.Second
	}
	path := o.Path
	if path == "" {
		path = "underflow.db"
	}
	pragmas := []string{
		"_pragma=journal_mode(WAL)",
		"_pragma=foreign_keys(1)",
		fmt.Sprintf("_pragma=busy_timeout(%d)", busy.Milliseconds()),
		"_pragma=synchronous(NORMAL)",
	}
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return path + "?" + strings.Join(pragmas, "&")
	}
	return "file:" + url.PathEscape(path) + "?" + strings.Join(pragmas, "&")
}

// Open opens the database, applies migrations and returns a Store.
func Open(ctx context.Context, o Options) (store.Store, error) {
	db, err := sql.Open(DriverName, o.DSN())
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// SQLite serialises writes; a single connection avoids SQLITE_BUSY under
	// the database/sql pool and keeps behaviour predictable for local use.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	st, err := store.NewSQLite(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return st, nil
}
