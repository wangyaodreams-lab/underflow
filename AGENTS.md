# AGENTS.md

Guidance for agents working in this repository. Read this before changing code;
it records the constraints that are easy to violate and expensive to discover.

## 1. What this is

**Underflow** is a zero-knowledge password manager. One Go binary is both the
web/API server and the CLI client, and the same crypto core runs natively and in
the browser via WebAssembly.

Stack: Go 1.26 (standard library first — chi, cobra, pgx, uuid, `x/crypto`,
`x/term`, `x/text`, `modernc.org/sqlite` are the only dependencies) plus a
framework-free TypeScript frontend built with esbuild and a hand-written DOM
`h()` helper in `web/src/main.ts`. No frontend framework, no runtime npm
dependencies.

Authoritative documents — read the relevant one before touching its area:

| File | Covers |
|---|---|
| `docs/CRYPTO.md` | **Normative.** Algorithms, envelope layouts, AAD strings, params |
| `docs/SECURITY.md` | What the server may see, operational guidance, residual risks |
| `docs/THREAT_MODEL.md` | Assets, adversaries, trust boundaries |
| `docs/DEPLOY.md` | Full `UF_*` table, systemd/Compose/Caddy, health checks |
| `docs/MANUAL.md` | End-user web and CLI usage |
| `api/openapi.yaml` | HTTP contract |
| `CHANGELOG.md` | User-visible history |

## 2. Architecture and dependency direction

```
cmd/underflow ─▶ internal/cli ─┬─▶ internal/{config,server,store,client,launcher,version}
                               └─▶ crypto
internal/server ─▶ internal/{server/handlers,server/middleware,config,store,auth,model} ─▶ crypto
internal/store  ─▶ internal/{model,store/migrations} ─▶ database/sql
internal/client ─▶ crypto                     (CLI's HTTP client)
internal/vault  ─▶ stdlib only                (plaintext item schema)
internal/pwgen  ─▶ stdlib only
crypto          ─▶ stdlib + x/crypto + x/text (NO internal/ imports)
wasm            ─▶ crypto + internal/pwgen    (compiled GOOS=js GOARCH=wasm)
web             ─▶ embedded build artifacts only
internal/launcher ─▶ stdlib only              (spawns `underflow serve`)
```

Rules that follow from this:

- **`crypto/` must stay portable and dependency-light.** It is compiled for both
  the native CLI and `js/wasm`. Never import `internal/`, `os/exec`, or anything
  platform-specific into it. It may only depend on the standard library,
  `golang.org/x/crypto`, and `golang.org/x/text`.
- **`wasm/` is the only place allowed to touch `syscall/js`**, behind
  `//go:build js && wasm` (see `wasm/stub.go` for the non-wasm counterpart).
- **Zero-knowledge is a layering rule, not just a promise:** plaintext item
  types (`internal/vault`) and the crypto core are client-side. The server may
  only ever handle `internal/model` types, which are ciphertext and metadata.
- `internal/launcher` deliberately depends on nothing but the standard library
  so it stays a small, auditable supervisor for the server process.

### Feature map

| Feature | Primary location |
|---|---|
| HTTP API + routing | `internal/server/router.go`, `internal/server/handlers/` |
| Auth, CSRF, security headers | `internal/server/middleware/middleware.go`, `internal/auth/` |
| Session tokens, rate limiting | `internal/auth/` |
| Persistence (SQLite/PostgreSQL) | `internal/store/` (`sql.go`, `sqlite/`, `postgres/`) |
| Schema migrations | `internal/store/migrations/{sqlite,postgres}/NNNN_name.sql` |
| Encryption core | `crypto/` |
| Browser crypto bridge | `wasm/main_js.go` (global `underflow`) |
| Web client | `web/src/` |
| Visual launcher for server params | `internal/launcher/`, `internal/cli/launcher.go`, `web/src/launcher/` |
| CLI command tree | `internal/cli/root.go` |

## 3. Build, test, verify

Requirements: Go 1.26+, Node 20+ (frontend only). The server has **no CGO
dependency** (`modernc.org/sqlite` is pure Go), so `CGO_ENABLED=0` always works.

```bash
make build        # web + wasm + binary  → bin/underflow
make build-go     # binary only, reusing existing web/dist assets (fast loop)
make web          # npm install + npm run build (frontend AND launcher UI)
make launcher     # rebuild only the launcher UI
make wasm         # compile crypto core to js/wasm + copy wasm_exec.js
make test         # go test ./...
make test-race    # needs cgo; not available on a CGO_ENABLED=0 box
make wasm-test    # run the js/wasm bridge tests under Node
make sec          # gofmt -l, go vet, staticcheck, gosec, govulncheck
make test-all     # race + wasm tests + npm ci + typecheck
```

Frontend:

```bash
cd web && npm run typecheck      # tsc for the app AND the launcher UI
cd web && npm run build          # app bundle + single-file launcher page
```

What CI enforces (`.github/workflows/ci.yml`) — match it before you claim done:

1. `gofmt -l .` is empty.
2. `go vet ./...` clean.
3. `go test -race ./...` passes.
4. Cross-compiles with `CGO_ENABLED=0` for linux/amd64, darwin/arm64,
   windows/amd64.
5. `GOOS=js GOARCH=wasm go build ./wasm` succeeds and the bridge tests pass
   under Node.
6. Short fuzzing of `FuzzEnvelopeDecode` and `FuzzBlobRoundTrip`.
7. `npm ci && npm run typecheck && npm run build`.
8. `govulncheck ./...` clean.
9. PostgreSQL contract tests with `UF_TEST_PG_DSN` set.

Useful invariants to preserve when testing:

- Datastore tests run against SQLite by default; the PostgreSQL suite only runs
  when `UF_TEST_PG_DSN` is set.
- Crypto tests assert that encrypting the same plaintext twice yields different
  ciphertext. Keep that property.
- `go test ./crypto/ -run '^$' -fuzz FuzzEnvelopeDecode -fuzztime 30s` for local
  fuzzing (`make fuzz`).

### Platform notes (Windows)

- `go test -race` fails with `-race requires cgo` when CGO is disabled; use
  `make test` locally and let CI run the race suite on Linux.
- Use `-o` for output paths, not PowerShell's `$null` — `go build -o $null`
  fails with "no Go files in <dir>" because it is treated as a directory.
- `Invoke-WebRequest` needs `-UseBasicParsing` in this environment and refuses
  to read a streaming (`text/event-stream`) response; use `curl.exe -s -N`.
- Chrome/Edge `--headless` prints mojibake to stderr even on success; capture
  stdout to a file rather than parsing the console.
- The repo's Go files are checked out with CRLF but stored as LF, so
  `gofmt -l` flags *every* pre-existing file on Windows. Normalize to LF before
  judging whether a file is really unformatted; new files written with LF pass
  as-is.

## 4. Configuration

Precedence is **CLI flag > environment variable > default**. Everything the
server reads is `UF_*`; see `internal/config/config.go` and `docs/DEPLOY.md`.

| Variable | Default |
|---|---|
| `UF_LISTEN_ADDR` | `127.0.0.1:8080` |
| `UF_DB_DRIVER` / `UF_DB_DSN` | `sqlite` / `underflow.db` |
| `UF_SERVER_PEPPER` / `UF_SERVER_PEPPER_FILE` | — / `<dsn>.pepper` |
| `UF_REGISTRATION` / `UF_INVITE_CODE` | `open` / — |
| `UF_ARGON2_PROFILE` | `interactive` |
| `UF_SESSION_TTL` / `UF_LOG_LEVEL` | `12h` / `info` |
| `UF_TLS_CERT` / `UF_TLS_KEY` | — |
| `UF_TRUSTED_PROXIES` / `UF_INSECURE` | — / `false` |

Pepper resolution order in `config.resolvePepper`: `UF_SERVER_PEPPER` → the
pepper file (`UF_SERVER_PEPPER_FILE`, else `<dsn>.pepper`) → create it `0600`
next to the database (SQLite only) → error unless `UF_INSECURE=1`.

Pitfalls that have already caused bugs:

- **`--local` must not override an explicit listen address.** It previously
  forced `127.0.0.1:8080` whenever the `--listen` *flag* was absent, silently
  discarding `UF_LISTEN_ADDR`. If you touch `internal/cli/serve.go`, keep the
  guard that checks both the flag and the environment variable.
- `register --profile` is **not** validated against the allowed profiles
  (`crypto.ParamsForProfile` does reject unknown values later in the flow).
  `serve --profile` *is* validated. Do not "fix" one to look like the other
  without deciding which behavior is intended.
- `UF_LOG_LEVEL` only distinguishes `debug` from anything else, which logs at
  info. The launcher UI therefore offers just `debug` and `info`.

## 5. Repository-specific gotchas

Frontend and embedded assets:

- Both UIs are `//go:embed`-ed and therefore **frozen into the binary**. After
  changing anything under `web/`, rerun `npm run build` before `go build`, or the
  binary keeps serving the old assets.
- A placeholder `web/dist/index.html` and `internal/launcher/dist/index.html`
  are committed so `go build` succeeds without Node. The launcher page is built
  as one **self-contained HTML file** (CSS and JS inlined) because the launcher
  serves only `/`; keep `web/esbuild.launcher.mjs` free of external asset
  references or the page will load unstyled and script-less.
- `web/dist` and `internal/launcher/dist` are gitignored except those
  placeholders. Do not commit build output.
- The SPA is served by the router's `NotFound` handler
  (`internal/server/router.go`), which falls back to `index.html` for unknown
  non-`/api/` paths. New server routes must be registered under `/api/v1/`.
- The strict CSP in `middleware.SecurityHeaders` forbids inline scripts and
  third-party origins. Frontend changes must not introduce either.

Crypto and wire formats:

- `docs/CRYPTO.md` is normative. Changing algorithms, parameters, the envelope
  layout, or an AAD string requires a new `formatVersion` and/or `kdfId` plus a
  migration path.
- Decoders must fail closed on wrong magic, unknown version/alg/kdfId,
  truncation, nonce length mismatch, and short ciphertext.
- Decryption failures must return one uniform error; do not add detail that
  distinguishes tag, padding, or AAD failures.
- KDF bounds: `8192 <= m <= 4194304` KiB, `1 <= t <= 64`, `1 <= p <= 64`
  (`crypto.ParamsForProfile` / `KDFParams.Validate`).

Storage:

- **Migrations are append-only and cannot be rolled back.** Add
  `NNNN_name.sql` to *both* dialect directories; `migrate` applies each version
  once, tracked in `schema_migrations`, sorted numerically.
- `internal/store/splitStatements` splits migration scripts on `;` naively.
  Never put a semicolon inside a string literal or comment in a migration.
- All SQL uses `?` placeholders; `dialect.rebind` rewrites them to `$N` for
  PostgreSQL. Write one query for both dialects and do not hand-roll `$N`.
- Every `Store` method that touches user data takes a subject id (`userID` /
  `ownerID`) and must enforce tenant isolation in the query itself.
- Item writes are guarded by an optimistic-concurrency `baseRev`; revision
  mismatches return `store.ErrConflict`, which `handlers.mapStoreErr` maps to
  HTTP 409 with code `revision_conflict`.
- Deletes are tombstones (`Deleted bool`) retained for sync — do not hard-delete
  items.
- Incremental sync is driven by a **global** monotonic revision, not per-row
  timestamps: `sync_counter` is a single-row table (`id = 1`) that every item
  write bumps, and `Store.Sync(ctx, userID, since)` returns rows with a higher
  revision plus the new high-water mark.
- Timestamps are persisted as Unix nanoseconds in `BIGINT` (PostgreSQL) /
  `INTEGER` (SQLite) rather than native timestamp types, for driver portability.
  Keep using `nanos` / `fromNanos` in `internal/store/sql.go`.

API conventions:

- JSON error body: `{"error":{"code":"...","message":"..."}}`. Use the existing
  helpers (`writeJSON`, `writeErr`, `badRequest`, `serverError`, `mapStoreErr`)
  rather than writing responses by hand.
- Request bodies are decoded with `DisallowUnknownFields` and an 8 MiB limit
  (`MaxRequestBytes`); decide deliberately before relaxing either.
- Successful state is reported with 200 + an explicit body; the launcher API in
  `internal/launcher/server.go` returns 200 with an `error` field for
  start/restart failures so the UI can render the reason instead of a bare 500.
- Cookie-authenticated clients must send the double-submit CSRF header
  (`X-UF-CSRF`). Bearer (CLI) requests are exempt — the exemption is keyed on
  how the request authenticated, so never infer it from the method alone.

Launcher specifics (`internal/launcher/`):

- It binds loopback only and rejects any request whose `Host` or `Origin` is not
  loopback on its own port. That check is the only thing preventing
  DNS-rebinding attacks from driving the control API; do not weaken it to make a
  test or a proxied deployment pass.
- `Spec` is the single source of truth: `Derive()` produces the `UF_*`
  environment map, the argv, the browser URL, the health-probe URL, and the
  validation issues. The UI, the command preview, and the spawned process all
  read from that one result — do not compute a second variant anywhere.
- Only `UF_*` variables may be set on the child; the launcher must never
  smuggle a setting through a second path (that is how the `--local` bug arose).
- A process that exits on its own is reported as `exited`/`failed` with a
  reason. Only an operator-initiated stop may report `stopped` with no error.

## 6. Safety rules

- **Never** put plaintext, a master password, a master key, a KEK, a vault key,
  an `AuthKey`, a session token, a CSRF token, or the server pepper into a log,
  an error message, an API response, a test fixture, a UI element, or a rendered
  command preview. The launcher redacts the invite code in its command preview;
  keep that behavior.
- **Never** add a flag that accepts a master password on the command line.
  Interactive or `--password-stdin` only (`internal/cli/item.go`), so it cannot
  leak into shell history.
- **Never** commit `*.db`, `*.pepper`, `*.pem`, `*.key`, `.env`, or anything
  under `.runtime/` (all gitignored — keep it that way).
- Secrets stay in `[32]byte` / `[]byte` and are zeroed with `crypto.Zero` after
  use. Do not copy them into `string`.
- Do not weaken the auth path: the verifier is
  `HMAC-SHA256(serverPepper, AuthKey)` compared with `hmac.Equal`, the session
  token is stored only as a SHA-256 hash, and expired sessions are deleted.
- New `gosec` findings must be fixed, not suppressed. The existing `#nosec`
  comments are scoped to a rule and carry a reason; match that style if a
  suppression is genuinely required.
- If a change affects the threat model, the crypto spec, or an operational
  guarantee, update `docs/SECURITY.md` / `docs/CRYPTO.md` / `docs/DEPLOY.md` in
  the same change.

## 7. Definition of done

1. `go test ./...` passes; add or update tests for behavior you changed.
2. `go vet ./...` and `gofmt -l` are clean (normalize line endings first on
   Windows).
3. `cd web && npm run typecheck` passes if you touched TypeScript.
4. If you touched `web/` or `internal/launcher/dist/`, rerun `npm run build` and
   confirm the generated `index.html` is the real page, not the placeholder.
5. Cross-compilation still works (`CGO_ENABLED=0`, including `js/wasm`).
6. Nothing secret is logged, returned, or committed.
7. Docs updated when behavior, configuration, or guarantees changed.
