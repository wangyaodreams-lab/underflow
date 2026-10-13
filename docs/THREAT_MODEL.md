# Threat model

## Assets

1. **Master passwords** — the root of a user's security. Server compromise must
   not reveal them.
2. **Vault keys** — random per-vault keys that decrypt items.
3. **Item plaintext** — credentials, notes, card and identity data.
4. **Server pepper** — a server-side secret that protects stored verifiers.
5. **Session tokens** — bearer credentials for the API.

## Adversaries

| Adversary | Goal | Mitigation |
|---|---|---|
| Network attacker | Read/modify traffic | TLS; AEAD protects payload integrity even if TLS is terminated maliciously at the edge (they still only see ciphertext). |
| Database thief | Recover plaintext or crack passwords | Items are ciphertext; verifiers need the pepper; Argon2id makes guessing costly. |
| Malicious server operator | Recover master passwords or plaintext | Server never receives plaintext; sees only `AuthKey` at login (see residual risk). |
| Malicious client | Access another user's data | Every query is scoped by owner id; cross-tenant access returns 404 and is covered by tests. |
| XSS / malicious page | Steal session or keys | Strict CSP without `unsafe-inline`, no third-party resources, session cookie is `HttpOnly`+`SameSite=Strict`, keys are memory-only, CSRF double-submit. |
| Offline attacker with stolen backup | Crack passwords | Argon2id + pepper separation. |
| Replay / tampering at rest | Swap or corrupt ciphertext | AAD binds each ciphertext to vault/item ids; decoders fail closed. |

## Trust boundaries

- **Client (browser/CLI)** performs all key derivation and encryption.
- **TLS** protects transport; it is not the only line of defence.
- **Server** is untrusted with respect to plaintext.
- **Database** is untrusted with respect to plaintext.

## In scope

- Multi-tenant isolation of users, vaults and items.
- Integrity and confidentiality of stored items and wrapped keys.
- Resistance to offline password cracking in the event of database theft.
- Safe defaults for sessions, headers and registration.

## Out of scope (for now)

- Malicious JavaScript served by a compromised server (see SECURITY.md).
- Compromised client devices (keyloggers, memory scraping by root).
- Traffic analysis of ciphertext sizes and timestamps.
- Denial of service.
- Cross-user sharing (Phase 2, will use X25519 key wrapping).
- OPAQUE-based authentication (Phase 2).

## Verification

- Official test vectors for Argon2id, HKDF, ChaCha20-Poly1305, XChaCha20 and
  AES-256-GCM.
- Negative tests for tampering, wrong AAD, wrong keys and malformed input.
- Fuzzing of the envelope decoders and the item round trip.
- An end-to-end test that asserts the on-disk database and server logs never
  contain a canary secret, the master password or a vault key.
