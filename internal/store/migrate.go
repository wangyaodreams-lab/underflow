package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

// migrate applies pending migrations from a filesystem rooted at the dialect
// directory (e.g. the "sqlite" sub-FS). Each file is named NNNN_name.sql and
// applied exactly once, tracked in schema_migrations.
func migrate(ctx context.Context, db *sql.DB, d dialect, fsys fs.FS) error {
	sub, err := fs.Sub(fsys, string(d))
	if err != nil {
		return fmt.Errorf("store: migration sub-fs: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		"CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at BIGINT NOT NULL)"); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(sub, ".")
	if err != nil {
		return fmt.Errorf("store: read migrations: %w", err)
	}
	files := map[int]string{}
	var versions []int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return fmt.Errorf("store: bad migration name %q", name)
		}
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return fmt.Errorf("store: bad migration version %q: %w", name, err)
		}
		files[v] = name
		versions = append(versions, v)
	}
	sort.Ints(versions)

	applied := map[int]bool{}
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("store: read applied migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close()
			return err
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	for _, v := range versions {
		if applied[v] {
			continue
		}
		data, err := fs.ReadFile(sub, files[v])
		if err != nil {
			return fmt.Errorf("store: read migration %d: %w", v, err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, stmt := range splitStatements(string(data)) {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("store: migration %d (%s): %w", v, files[v], err)
			}
		}
		if _, err := tx.ExecContext(ctx, d.rebind("INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)"),
			v, time.Now().UTC().UnixNano()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: record migration %d: %w", v, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %d: %w", v, err)
		}
	}
	return nil
}

// splitStatements naively splits a SQL script on semicolons. Underflow's
// migrations never contain semicolons inside string literals or comments.
func splitStatements(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ";") {
		stmt := strings.TrimSpace(part)
		if stmt == "" {
			continue
		}
		out = append(out, stmt)
	}
	return out
}
