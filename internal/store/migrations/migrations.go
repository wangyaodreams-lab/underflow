// Package migrations embeds the per-dialect SQL schema migrations.
package migrations

import "embed"

// SQLite migrations.
//
//go:embed sqlite/*.sql
var SQLite embed.FS

// Postgres migrations.
//
//go:embed postgres/*.sql
var Postgres embed.FS
