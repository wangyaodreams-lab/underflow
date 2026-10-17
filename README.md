# Underflow

A zero-knowledge password manager. The server stores only ciphertext; your
master password and plaintext never leave your device. One Go binary provides
both the web application and a command-line client, and the same cryptography
core runs natively (CLI) and in the browser (compiled to WebAssembly).

```
        ┌────────────┐        HTTPS (ciphertext only)        ┌────────────┐
        │  Browser   │ ───────────────────────────────────▶ │    Go      │
        │  (WASM)    │ ◀─────────────────────────────────── │  server    │
        └────────────┘                                      └─────┬──────┘
        ┌────────────┐                                            │
        │    CLI     │ ───────────────────────────────────────────┘
        └────────────┘            SQLite / PostgreSQL
```

## Features

- Zero-knowledge, client-side encryption (Argon2id + HKDF + XChaCha20-Poly1305).
- Web UI (framework-free TypeScript) and a CLI sharing one crypto core.
- Multi-user with strict per-tenant isolation.
- Encrypted item CRUD with incremental, revision-based sync and tombstones.
- Optional local single-binary deployment (SQLite) or cloud (PostgreSQL).
- Password generator, import (CSV/JSON) and export (CSV/JSON).
- Auto-lock, CSRF protection, security headers, login rate limiting.

## Quick start (local)

```bash
make build                 # builds the frontend, WASM core and the binary
./bin/underflow serve --local
# open http://127.0.0.1:8080 and create an account
```

`--local` binds to loopback and disables registration after you create your
account. A server pepper is generated next to the database on first run.

### Launcher (visual configuration)

Every server parameter can be set through a local web interface instead of
flags and environment variables:

```bash
./bin/underflow launcher
# opens http://127.0.0.1:8090
```

The launcher resolves the settings into the same `UF_*` environment contract
that `underflow serve` reads, validates them against the server's own rules,
shows the exact command it will run, then supervises the server and streams its
log output back into the page.

- **Parameters**: listener, SQLite/PostgreSQL, server pepper handling,
  registration mode and invite code, Argon2id profile, session lifetime, TLS
  certificate/key, trusted proxies, log level and insecure mode.
- **Pepper**: shown by path and fingerprint, never by value. Generate one with
  a click; the launcher writes it `0600` next to the database (or wherever you
  point it).
- **Control**: start, stop, restart and "open app", with live status and logs.
- **Persistence**: settings are saved to `launcher.json` in the config
  directory (`--state-dir`, default `~/.config/underflow`), so the next run
  starts from them.

The launcher binds to loopback only and rejects requests from any other origin.
It is a local development and single-machine operations convenience; for
production use the environment variables below directly.

| Flag | Default | Notes |
|---|---|---|
| `--addr` | `127.0.0.1:8090` | launcher UI address; moves to the next free port if busy |
| `--work-dir` | current directory | where the server runs and relative paths resolve |
| `--state-dir` | `~/.config/underflow` | where `launcher.json` is stored |
| `--binary` | this executable | the binary spawned for `serve` |
| `--open` | `true` | open the launcher in a browser |

### CLI

```bash
./bin/underflow register --server http://127.0.0.1:8080 --email you@example.com
./bin/underflow item add --name example.com --username you --url https://example.com --generate
./bin/underflow item list --show-passwords
./bin/underflow item get example.com --show
./bin/underflow export --format json > backup.json
./bin/underflow lock          # forget cached keys
./bin/underflow unlock        # re-derive keys from the master password
./bin/underflow password      # change master password (re-wraps vault keys)
```

> **No `--password` flag.** Master passwords are always entered interactively
> (hidden) or via standard input (`--password-stdin`) to avoid leaking into
> shell history.

## Cloud deployment

See [docs/DEPLOY.md](docs/DEPLOY.md). The short version:

```bash
export UF_SERVER_PEPPER=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
export UF_DOMAIN=passwords.example.com
docker compose -f deployments/docker-compose.yml up -d --build
```

## Documentation

- **User manual (使用手册): [docs/MANUAL.md](docs/MANUAL.md)** — Web and CLI usage, import/export, backup, FAQ.
- Crypto specification: [docs/CRYPTO.md](docs/CRYPTO.md)
- Security notes: [docs/SECURITY.md](docs/SECURITY.md)
- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Deployment: [docs/DEPLOY.md](docs/DEPLOY.md)
- HTTP API: [api/openapi.yaml](api/openapi.yaml)

## Security

- Specification: [docs/CRYPTO.md](docs/CRYPTO.md)
- Security notes: [docs/SECURITY.md](docs/SECURITY.md)
- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

In one line: the server holds only public KDF parameters, a password verifier
protected by a server-side pepper, wrapped vault keys and encrypted items.

## Configuration

### CLI config (local state)

The CLI persists two files under `~/.config/underflow/` (overridable via
`--config-dir` or `UNDERFLOW_CONFIG_DIR`):

| File | Content | Format |
|---|---|---|
| `config.toml` | `server`, `email`, `device_id` | simple `key = "value"` (TOML-like, no quotes) |
| `secrets.json` | session token, KDF params, cached vault keys | JSON (encrypted in memory, 0600 on disk) |

### Server environment variables

All server flags can be set via environment variables. The CLI `--help` for
`serve` lists the full set; the table below covers the most important ones:

| Variable | Default | Notes |
|---|---|---|
| `UF_LISTEN_ADDR` | `127.0.0.1:8080` | bind address |
| `UF_DB_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `UF_DB_DSN` | `underflow.db` | file path or PostgreSQL connection string |
| `UF_SERVER_PEPPER` | — | server-side secret for verifier protection; >= 32 bytes hex (or raw) |
| `UF_REGISTRATION` | `open` | `open`, `closed`, or `invite` (requires `UF_INVITE_CODE`) |
| `UF_ARGON2_PROFILE` | `interactive` | `interactive` (64 MiB) / `moderate` (256 MiB) / `paranoid` (1 GiB) |
| `UF_SESSION_TTL` | `12h` | session lifetime |
| `UF_LOG_LEVEL` | `info` | `debug` or `info` |

`serve` also accepts `--session-ttl` and `--log-level` alongside the flags
listed by `underflow serve --help`.

See [DEPLOY.md](docs/DEPLOY.md) for the full table (including TLS, rate-limit
proxy, and trusted-proxies settings).

## Development

```bash
make test          # unit + integration tests (SQLite)
make test-race     # race detector
make fuzz          # 30s crypto fuzzing
make wasm          # build the browser crypto core
make web           # bundle the TypeScript frontend
make build         # single binary with embedded assets
```

Requirements: Go 1.26+, Node 20+ (frontend only). The server has no CGO
dependency.

## Repository layout

| Path | Purpose |
|---|---|
| `crypto/` | Auditable crypto core (native + wasm) |
| `wasm/` | `syscall/js` bridge for the browser |
| `internal/server/` | HTTP API, middleware, handlers |
| `internal/store/` | SQLite and PostgreSQL storage |
| `internal/cli/` | Cobra command tree |
| `internal/client/` | CLI HTTP client |
| `web/` | TypeScript frontend and build |
| `deployments/` | Docker, Compose, systemd, Caddy |
| `docs/` | User manual, crypto spec, security, threat model, deployment |

## License

MIT — see [LICENSE](LICENSE).
