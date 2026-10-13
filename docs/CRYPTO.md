# Underflow Cryptography Specification (v1)

This document is normative for the `crypto` package. Any change to the
algorithms, parameters, envelope layout, or derivation strings below requires a
new `formatVersion` and/or `kdfId` and a corresponding migration path.

## 1. Threat model summary

Underflow is **zero-knowledge**: the server stores only ciphertext and public
key-derivation parameters. The master password and all plaintext never leave
the client (WebAssembly in the browser, native code in the CLI).

The server provides: account records, the per-user KDF salt, the wrapped vault
key, opaque session tokens, and encrypted item blobs.

## 2. Password normalization

```
input = UTF-8( NFKD(masterPassword) )
```

- No trimming, no length limit, no truncation.
- NFKD (Unicode compatibility decomposition) is applied so that visually
  equivalent input entered on different platforms derives the same key.

## 3. Key derivation (KDF)

```
MasterKey(32 bytes) = Argon2id(
    password   = input,
    salt       = userKdfSalt (16 bytes, CSPRNG, stored server-side),
    time       = t,
    memory     = m KiB,
    parallelism= p,
    keyLen     = 32,
    version    = 0x13)
```

`kdfId = 1` identifies Argon2id v1.3.

Profiles (stored per user, upgradeable):

| Profile       | m (KiB) | t | p |
|---------------|---------|----|----|
| `interactive` | 65536   | 3  | 4  |
| `moderate`    | 262144  | 4  | 4  |
| `paranoid`    | 1048576 | 6  | 8  |

Validation bounds: `8192 <= m <= 4194304`, `1 <= t <= 64`, `1 <= p <= 64`.

## 4. Key hierarchy

```
AuthKey(32) = HKDF-SHA256(ikm=MasterKey, salt=userKdfSalt, info="underflow/v1/auth")
KEK(32)     = HKDF-SHA256(ikm=MasterKey, salt=userKdfSalt, info="underflow/v1/enc")

VaultKey(32) = CSPRNG

ProtectedVaultKey = AEAD(
    key   = KEK,
    nonce = CSPRNG,
    pt    = VaultKey,
    aad   = "underflow/v1/vaultkey/" || vaultID)

ItemKey(32) = HKDF-SHA256(
    ikm  = VaultKey,
    salt = (none),
    info = "underflow/v1/item/" || vaultID || "/" || itemID)
```

- `AuthKey` and `KEK` are domain-separated and must never be used
  interchangeably.
- Changing the master password only requires re-deriving `KEK` and re-wrapping
  `VaultKey` (O(1)).
- Changing KDF parameters (policy upgrade detected at login) re-derives the
  `MasterKey` and re-wraps `VaultKey`; the old parameters are discarded.

## 5. Authentication verifier

The client derives `AuthKey` locally and transmits it to the server over TLS.
The server derives and stores:

```
verifier = HMAC-SHA256(serverPepper, AuthKey)
```

- `serverPepper` is a server-side secret (>= 32 bytes) supplied via
  `UF_SERVER_PEPPER` and **never stored in the database**.
- Comparison uses `hmac.Equal` (constant time).
- Consequence: stealing the database alone does not permit offline guessing of
  the master password without also stealing the pepper. A malicious server can
  observe `AuthKey` at login and attempt an offline brute-force; upgrading to
  OPAQUE (RFC 9807) is a Phase 2 hardening step that removes this residual
  risk by never revealing a password-equivalent value.

## 6. AEAD and envelope format

Algorithms:

| id | Algorithm               | Key | Nonce | Tag |
|----|-------------------------|-----|-------|-----|
| 1  | XChaCha20-Poly1305 (default) | 32  | 24    | 16  |
| 2  | AES-256-GCM             | 32  | 12    | 16  |

XChaCha20-Poly1305 is the default because its 24-byte nonce makes random
nonces safe for the expected message volume. If AES-256-GCM is selected,
callers must ensure nonce uniqueness; Underflow uses random nonces and treats
this as a lower-assurance option.

### BlobEnvelope (item / vault-name ciphertext)

```
"UF"(2) | formatVersion(1)=1 | alg(1) | nonceLen(1) | nonce | ciphertext||tag
```

### KeyEnvelope (protected key / KDF parameters)

```
"UF"(2) | formatVersion(1)=1 | alg(1) | kdfId(1)
      | m(uvarint) | t(uvarint) | p(uvarint)
      | saltLen(1) | salt
      | nonceLen(1) | nonce | ciphertext||tag
```

Decoders fail closed on: wrong magic, unknown/unsupported `formatVersion`,
unknown `alg`, unknown `kdfId`, truncated buffers, nonce length mismatch for the
declared algorithm, or ciphertext shorter than the tag size.

Additional authenticated data (AAD):

```
vault key   : "underflow/v1/vaultkey/"  || vaultID
vault name  : "underflow/v1/vaultname/" || vaultID
item        : "underflow/v1/item/"      || vaultID || "/" || itemID
```

AAD binds every ciphertext to its scope, preventing cross-item or cross-vault
substitution/replay.

## 7. Randomness and memory hygiene

- All randomness comes from `crypto/rand`.
- Password generation uses `crypto/rand.Int` (no modulo bias).
- Keys are held in `[32]byte` / `[]byte`; secrets are never placed in `string`.
- Buffers are zeroed with `crypto.Zero` after use. On Linux/macOS keys may be
  pinned with `mlock` (build-tagged; best effort).
- **Residual risk:** Go's garbage collector may copy secret bytes, so zeroing
  is best-effort. Deployments should disable swap and core dumps.

## 8. Hard checks

- Nonce length, tag length, and minimum ciphertext length are validated.
- Decryption failure returns a single uniform error (no distinction between
  padding, tag, or AAD failures).
- Encrypting the same plaintext twice MUST produce different ciphertext
  (asserted by tests).

## 9. Standards references

- Argon2: RFC 9106
- HKDF: RFC 5869
- ChaCha20-Poly1305: RFC 8439
- XChaCha20: draft-irtf-cfrg-xchacha
- AES-GCM: NIST SP 800-38D
- OPAQUE (Phase 2): RFC 9807
