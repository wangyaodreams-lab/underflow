# Security

## Reporting a vulnerability

Please open a private security advisory at
`https://github.com/wangyaodreams-lab/underflow/security/advisories` or email the
maintainers. Do not open public issues for security problems. We aim to
acknowledge reports within 72 hours.

## Design in one paragraph

Underflow is zero-knowledge. The master password is stretched with Argon2id to
a master key, from which an authentication key and a key-encryption key are
derived with HKDF-SHA256. Each vault has a random 256-bit vault key that is
wrapped under the key-encryption key; each item is encrypted with a per-item key
derived from the vault key using XChaCha20-Poly1305. The server stores only
public KDF parameters, a verifier, wrapped keys and ciphertext. See
[docs/CRYPTO.md](CRYPTO.md) for the normative specification.

## What the server sees

- Account email, Argon2 parameters and salt.
- `verifier = HMAC-SHA256(serverPepper, AuthKey)`.
- Wrapped vault keys and the ciphertext of vault names and items.
- Metadata: item ids, vault ids, revisions, timestamps, tombstones.
- Session records (hashed tokens), audit metadata, and client IPs.

The server **never** sees the master password, the master key, the
key-encryption key, vault keys, or any plaintext item field.

## Operational guidance

- Always serve over HTTPS. Use the built-in TLS options or a reverse proxy, and
  enable HSTS (Underflow does this automatically when it terminates TLS).
- Set `UF_SERVER_PEPPER` to at least 32 random bytes and store it separately
  from the database. Losing it locks out every account; leaking it together
  with the database enables offline guessing.
- Set `UF_REGISTRATION=closed` after creating accounts, or use `invite`.
- Disable swap and core dumps on the host. Go cannot guarantee that secret
  buffers are wiped before garbage collection, so limit how long keys live in
  memory (auto-lock) and avoid paging. On Linux, compile with
  `-tags=mlock` to pin secret buffers with `mlock(2)` (best effort, may fail
  under memory pressure).
- Restrict access to the database and backups.
- Publish the exact build (commit + checksum) so browser clients can verify the
  served frontend, since a compromised server can serve malicious JavaScript.
- The rate limiter is **in-memory** (fixed-window, ~10 attempts per 5 min).
  For multi-instance deployments this provides no protection across processes;
  use a reverse-proxy rate limiter or replace `internal/auth/limiter.go` with a
  shared store-backed implementation.

## Browser threat model caveat

A password manager delivered as a web page is only as trustworthy as the code
the server sends. A malicious or compromised server can serve JavaScript that
exfiltrates the master password. Underflow mitigates the common cases (strict
CSP without inline scripts, no third-party requests, no secrets in storage) but
cannot eliminate this. Users who require stronger guarantees can use the CLI,
which runs the same audited crypto core as native code.

## Cryptography choices

| Purpose | Primitive |
|---|---|
| Password stretching | Argon2id (RFC 9106), 64 MiB / t=3 / p=4 by default |
| Subkey derivation | HKDF-SHA256 (RFC 5869) with domain separation |
| Authenticated encryption | XChaCha20-Poly1305 (24-byte nonce), optional AES-256-GCM |
| Authentication verifier | HMAC-SHA256 over the derived authentication key |
| Randomness | `crypto/rand` / WebCrypto-grade source |

Every ciphertext is bound to its scope with additional authenticated data so it
cannot be replayed or swapped between items or vaults.

## Residual risks and roadmap

- `AuthKey` is presented to the server at login, so a malicious server can
  attempt an offline brute-force of weak master passwords. Planned mitigation:
  OPAQUE (RFC 9807).
- Go's garbage collector may copy secret bytes, so memory zeroing is
  best-effort. Deployments should disable swap and core dumps. Linux builds
  can use `go build -tags=mlock` to pin secret buffers with `mlock(2)`.
- In-memory rate limiting does not coordinate across multiple instances.
  Multi-instance deployments need an external rate limiter (reverse proxy) or
  a shared store-backed limiter replacing `internal/auth/limiter.go`.
