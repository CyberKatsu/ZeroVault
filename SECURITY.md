# SECURITY.md — ZeroVault Security Policy

## Responsible Disclosure

If you discover a security vulnerability in ZeroVault, please open a GitHub
Security Advisory rather than a public issue.  Do not include proof-of-concept
exploit code in public communications until a patch has been released.

---

## What the Server Stores

The following table documents **every** field stored in the ZeroVault
PostgreSQL database, what it represents, and whether a server operator
could use it to compromise user data.

### `users` table

| Column | Contents | Server can use to…  | Server CANNOT use to… |
|--------|----------|---------------------|-----------------------|
| `id` | Auto-increment integer | Identify user rows | — |
| `username` | Plaintext username | Identify the user | — |
| `auth_key_hash` | `bcrypt(auth_key, rounds=12)` | Verify login (offline crack attempt is very slow due to Argon2id + bcrypt chain) | Derive `enc_key`; decrypt vault |
| `argon2_salt` | 32-byte random salt, hex-encoded | Return to client at login so client can re-derive `auth_key` | Derive `enc_key` without the master password |
| `argon2_time_cost` | Integer (e.g. `3`) | Return to client | — |
| `argon2_memory_cost_kib` | Integer (e.g. `65536`) | Return to client | — |
| `argon2_parallelism` | Integer (e.g. `4`) | Return to client | — |
| `created_at` | UTC timestamp | Audit log | — |

### `vault_entries` table

| Column | Contents | Server can use to… | Server CANNOT use to… |
|--------|----------|--------------------|-----------------------|
| `id` | Auto-increment integer | Identify entries | — |
| `user_id` | Foreign key to `users.id` | Enforce ownership | — |
| `ciphertext_hex` | AES-256-GCM ciphertext including 128-bit auth tag, hex-encoded | Return to client | Decrypt; read site/username/password/notes |
| `nonce_hex` | 12-byte GCM nonce, hex-encoded | Return alongside ciphertext | Decrypt without `enc_key` |
| `created_at` | UTC timestamp | Sort entries; audit log | — |

---

## What the Server Can Compute

Given full read access to the database and unlimited compute:

1. **Attempt to crack `bcrypt(auth_key)`** — extremely slow.  The `auth_key`
   was itself derived by Argon2id (≥ 65 ms per guess on CPU, highly
   memory-intensive).  A bcrypt round-12 check takes an additional ≈ 250 ms.
   Combined, each password guess costs ≈ 315 ms on modern CPU hardware and
   significantly more on GPU due to Argon2's memory hardness.

2. **If `auth_key` is recovered** — the server operator can impersonate the
   user for API calls (list/delete vault entries, change settings).  They
   **still cannot** derive `enc_key` from `auth_key` alone.  `enc_key` and
   `auth_key` are derived independently from the same Argon2 output via HKDF
   with distinct `info` labels.  Knowing one provides no information about
   the other.

3. **Serve tampered ciphertext** — a malicious server could modify stored
   ciphertext before returning it to the client.  The client's AES-GCM
   decryption will detect any modification (the 128-bit authentication tag
   will not verify) and raise an exception rather than returning corrupt
   plaintext.

---

## What Remains Inaccessible to the Server Under All Circumstances

The following material is **never transmitted to or stored by the server**:

| Material | Why it never reaches the server |
|----------|--------------------------------|
| Master password | Entered by the user; used only for local KDF; discarded after key derivation |
| `enc_key` (AES-256 encryption key) | Derived locally; held in Reflex State memory during session; never included in any HTTP request |
| `auth_key` plaintext | Transmitted once per login for bcrypt verification; only the hash is stored; the plaintext is not retained |
| Vault plaintext (`site`, `username`, `password`, `notes`) | Encrypted locally before the HTTP request is made |

---

## Known Limitations and Accepted Risk

### 1. Reflex State Memory

ZeroVault uses the Reflex framework, which runs application state on a Python
server process.  The `enc_key` is held in `ZeroVaultState._enc_key_hex` for
the duration of an authenticated session.

**Risk:** A process-level memory dump during an active session could expose
`enc_key`.

**Accepted because:** This is equivalent to the trust model of any
server-rendered web application.  The alternative — running cryptographic
operations entirely in the browser via the WebCrypto API — would require
a JavaScript frontend.  For a Reflex portfolio project demonstrating
zero-knowledge *architecture*, the current design is documented and
acceptable.

**Mitigation:** The `_enc_key_hex` field is prefixed with `_` per Reflex
convention, which marks it as a backend-only var (not synced to the
frontend).  It is cleared on logout.  Sessions expire via JWT TTL (1 hour
by default).

### 2. User Enumeration via `/auth/kdf-params/{username}`

The KDF parameter endpoint returns a `404` for unknown usernames and `200`
for known ones.  An adversary can enumerate valid usernames by probing this
endpoint.

**Accepted because:** Username existence is often considered semi-public
information (e.g. "Username already taken" during registration already
reveals this).  For a hardened production system, this endpoint would return
synthetic KDF parameters for unknown usernames (derived from a server-side
HMAC secret keyed on the username) to make enumeration impossible.

### 3. No Rate Limiting

The current implementation does not include rate limiting on authentication
endpoints.  A production deployment should add:
- IP-based rate limiting on `/auth/login` (e.g. 10 requests/minute)
- Account-level lockout after N failed attempts
- CAPTCHA on registration

### 4. JWT `HS256` (Symmetric Signing)

The JWT is signed with a shared secret using HMAC-SHA256.  Any party with
the secret can both create and verify tokens.  For a multi-service
deployment, RS256 (asymmetric) is preferable.  For a single-backend system
this is acceptable.

### 5. No Vault Entry Update

Entries can be created and deleted but not updated.  Updating would require
re-encrypting the entry with the current `enc_key` and replacing the stored
ciphertext.  This is not yet implemented.

---

## Cryptographic Assumptions

ZeroVault's security relies on the following assumptions:

1. **AES-256-GCM is secure** — No known practical attacks against AES-256 or GCM with random nonces and 128-bit tags.
2. **Argon2id is memory-hard** — Adversaries cannot perform Argon2 cheaper than the specified parameters.
3. **HKDF-SHA256 provides domain separation** — Keys derived with distinct `info` labels are computationally independent.
4. **bcrypt is collision-resistant** — Finding a different input that produces the same bcrypt hash is computationally infeasible.
5. **`os.urandom` is a CSPRNG** — The OS kernel provides cryptographically random bytes for nonces and salts.
6. **HTTPS is used in production** — Without TLS, the `auth_key` transmitted at login could be intercepted in transit.

---

## Dependency Security

| Package | Version | Security notes |
|---------|---------|----------------|
| `cryptography` | 44.0.0 | PyCA reference library; regular CVE monitoring |
| `argon2-cffi` | 25.1.0 | No known CVEs; maintained |
| `bcrypt` | 4.2.1 | Direct C binding; no known CVEs |
| `PyJWT` | 2.10.1 | Used instead of `python-jose` (CVE-2024-33663, CVE-2024-33664) |
| `fastapi` | 0.115.x | No known CVEs at time of writing |
| `sqlalchemy` | 2.0.x | No known CVEs at time of writing |

Run `pip audit` regularly to detect newly disclosed vulnerabilities in
dependencies.
