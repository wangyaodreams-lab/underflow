# Deploying Underflow

Underflow runs as a single Go binary with the frontend embedded. It supports
two storage backends:

| Backend | Use case | Driver |
|---|---|---|
| SQLite (default) | local machine, small self-hosted instance | `sqlite` (pure Go, no CGO) |
| PostgreSQL | cloud / multi-instance | `postgres` |

## Configuration

All configuration is via environment variables (flags override them for
`underflow serve`).

| Variable | Default | Notes |
|---|---|---|
| `UF_LISTEN_ADDR` | `127.0.0.1:8080` | bind address |
| `UF_DB_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `UF_DB_DSN` | `underflow.db` | file path or connection string |
| `UF_SERVER_PEPPER` | — | **required** for non-SQLite; >= 32 bytes (hex or raw). Generate with `openssl rand -hex 32` and back it up. |
| `UF_SERVER_PEPPER_FILE` | `<dsn>.pepper` | SQLite only: file used when `UF_SERVER_PEPPER` is unset |
| `UF_REGISTRATION` | `open` | `open`, `closed`, or `invite` |
| `UF_INVITE_CODE` | — | required when `UF_REGISTRATION=invite` |
| `UF_ARGON2_PROFILE` | `interactive` | `interactive`, `moderate`, `paranoid` |
| `UF_SESSION_TTL` | `12h` | session lifetime |
| `UF_TLS_CERT` / `UF_TLS_KEY` | — | serve HTTPS directly |
| `UF_TRUSTED_PROXIES` | — | comma-separated IPs allowed to set `X-Forwarded-For` |
| `UF_LOG_LEVEL` | `info` | `debug` or `info` |
| `UF_INSECURE` | `false` | allow running without a pepper (never in production) |

> The server pepper is **not stored in the database**. If you lose it, all
> accounts become unverifiable. Back it up separately from the database.

## Local single-binary deployment

```bash
make build
UF_SERVER_PEPPER=$(openssl rand -hex 32) \
  ./bin/underflow serve --listen 127.0.0.1:8080 --dsn /var/lib/underflow/underflow.db
```

For a machine-local instance you can omit `UF_SERVER_PEPPER`: Underflow creates
`<dsn>.pepper` with mode `0600`.

## systemd

```bash
sudo useradd --system --home /var/lib/underflow underflow
sudo install -d -o underflow -g underflow /var/lib/underflow
sudo install -m 0600 /dev/stdin /etc/underflow/underflow.env <<'EOF'
UF_SERVER_PEPPER=<openssl rand -hex 32>
UF_DB_DRIVER=sqlite
UF_DB_DSN=/var/lib/underflow/underflow.db
UF_REGISTRATION=closed
EOF
sudo install -m 0644 deployments/underflow.service /etc/systemd/system/underflow.service
sudo install -m 0755 bin/underflow /usr/local/bin/underflow
sudo systemctl daemon-reload
sudo systemctl enable --now underflow
```

## Docker Compose (cloud)

```bash
export UF_SERVER_PEPPER=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
export UF_DOMAIN=passwords.example.com
docker compose -f deployments/docker-compose.yml up -d --build
```

This starts PostgreSQL, the Underflow app and Caddy. Caddy obtains TLS
certificates automatically and proxies to the app on the internal network.

## Running behind a reverse proxy

Terminate TLS at the proxy and forward to `127.0.0.1:8080`. Set
`UF_TRUSTED_PROXIES` to the proxy's IP so client IPs are read from
`X-Forwarded-For` for rate limiting. Underflow sets HSTS automatically when it
terminates TLS itself; configure HSTS at the proxy otherwise.

## Backups

Back up three things together:

1. the database (SQLite file or a `pg_dump`),
2. the **server pepper**,
3. nothing else is required — vaults and items are already ciphertext.

Without the users' master passwords the ciphertext is not recoverable, by
design.

## Upgrades

Schema migrations run automatically on startup and are tracked in
`schema_migrations`. Roll forward by replacing the binary; there is currently
no automatic rollback of migrations, so take a database backup first.

## Health checks

- `GET /api/v1/healthz` — liveness, always 200 while the process runs.
- `GET /api/v1/readyz` — readiness, checks datastore connectivity.
