// Package postgres opens a PostgreSQL-backed Store (recommended for cloud
// deployments).
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver

	"github.com/wangyaodreams-lab/underflow/internal/store"
)

// DriverName is the database/sql driver name registered by pgx's stdlib.
const DriverName = "pgx"

// Options configures the PostgreSQL connection pool.
type Options struct {
	// DSN is a libpq/pgx connection string, e.g.
	// "postgres://user:pass@host:5432/underflow?sslmode=require".
	DSN string
	// MaxOpenConns bounds the pool (default 10).
	MaxOpenConns int
}

// Open opens the database, applies migrations and returns a Store.
func Open(ctx context.Context, o Options) (store.Store, error) {
	db, err := sql.Open(DriverName, o.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	max := o.MaxOpenConns
	if max <= 0 {
		max = 10
	}
	db.SetMaxOpenConns(max)
	db.SetMaxIdleConns(max)
	db.SetConnMaxIdleTime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	st, err := store.NewPostgres(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return st, nil
}
