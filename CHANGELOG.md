# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning (though as a pre-1.0 project,
breaking changes may appear between minor releases).

## [Unreleased]

### Added
- `cmd/underflow/main.go` — the missing CLI entry point that ties together
  `cli.NewRootCmd().Execute()`. This file was absent from the repository,
  which made `make build` and `docker build` impossible (the Makefile,
  Dockerfile, and CI pipeline all reference `./cmd/underflow`).
- `.gitignore` fix: the bare `underflow` pattern now correctly anchors to
  `/underflow` so that the `cmd/underflow/` directory is no longer silently
  ignored by git.
- `.gitignore`: added `/.runtime/` to exclude local test data and Go module
  cache from version control.
- `CHANGELOG.md` — this file.

### Fixed
- `.gitignore` bare `underflow` entry: was matching `cmd/underflow/` and any
  other directory at any depth named `underflow`. Changed to anchored
  `/underflow` to only match the root-level binary.

---

## [v1] — initial commit

### Added
- Zero-knowledge password manager: Argon2id + HKDF + XChaCha20-Poly1305
- Single Go binary serving both Web (WASM) and CLI
- Web frontend (framework-free TypeScript, esbuild bundle)
- SQLite and PostgreSQL storage backends
- Multi-user, per-tenant isolation
- Incremental, revision-based item sync with tombstones
- Password generator, CSV/JSON import and export
- Auto-lock, CSRF protection, security headers, login rate limiting

---

## [Unreleased] — planned

- [ ] OPAQUE (RFC 9807) authentication to eliminate the residual AuthKey
  leakage risk at login.
- [ ] Cross-user vault sharing via X25519 key wrapping.
- [ ] TOTP support in the Web UI.
- [ ] Docker Compose compose file: health check for the app container.
