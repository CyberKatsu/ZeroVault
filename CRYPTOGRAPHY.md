# CRYPTOGRAPHY.md — ZeroVault Cryptographic Architecture

## Overview

ZeroVault is a **zero-knowledge password manager**: the server stores encrypted vault entries and authentication credentials but possesses no material that would allow it to decrypt user data, even under a full database breach.

This document explains every cryptographic decision in the system, the threat model it addresses, and how the design compares to naïve alternatives.

---

## 1. The Two-Key Derivation Pattern

### The naïve approach and why it fails

A naïve password manager derives a single key from the user's master password and uses it for both purposes:

```
master_password ──→ KDF ──→ single_key
                              ├── used to encrypt vault entries
                              └── used as password for server login (bcrypt stored)
```

**The threat:** A database breach exposes `bcrypt(single_key)`. An adversary who cracks this hash — however slow bcrypt makes it — has the *same key* that encrypts the vault. Every password is now compromised.

### ZeroVault's two-key pattern

```
master_password + random_salt
        │
     Argon2id              ← memory-hard; ≈65 ms per guess on modern CPU
        │
  master_key_material (64 bytes of pseudorandom output)
        │
       HKDF (SHA-256)
       ├─── enc_key  (32 bytes, info="zerovault-v1-encryption-key")
       │       └── AES-256-GCM vault encryption.
       │            NEVER transmitted to the server. NEVER stored.
       └─── auth_key (32 bytes, info="zerovault-v1-authentication-key")
               └── Sent to server at registration/login.
                    Server stores bcrypt(auth_key).
```

**The result:** A database breach exposes only `bcrypt(auth_key)`. Cracking this gives the adversary the ability to *authenticate as the user* (until they change their password), but it gives them **zero information** about `enc_key`. The vault ciphertext remains computationally secure.

### Why HKDF instead of splitting the Argon2 output?

One could naively split the 64-byte Argon2 output: `enc_key = output[:32]`, `auth_key = output[32:]`.

This is *probably fine* in practice (Argon2 output is indistinguishable from random), but HKDF provides:

1. **Formal domain separation** — the `info` parameter acts as a domain label. Each derived key is bound to its specific purpose.
2. **Independence guarantee** — HKDF's extract-then-expand design ensures that even if the extraction phase (Argon2) has unexpected bias, the two output keys remain independently indistinguishable from random.
3. **Extensibility** — new keys (e.g. an HMAC signing key for entry metadata) can be derived by adding a new `info` label without changing the core KDF.

---

## 2. Argon2id Parameters

ZeroVault uses **Argon2id** — the variant recommended by RFC 9106 for password hashing.

| Parameter | Value | Justification |
|-----------|-------|---------------|
| `type` | `id` | Argon2id combines Argon2i's side-channel resistance with Argon2d's GPU resistance |
| `time_cost` | 3 | RFC 9106 "second recommended" profile; ≈65 ms on a 2024 mid-range CPU |
| `memory_cost` | 65536 KiB (64 MiB) | RFC 9106 "second recommended" profile; limits GPU parallelism to ≈128 instances per 8 GiB VRAM |
| `parallelism` | 4 | RFC 9106 default; matches typical server core count |
| `hash_len` | 64 bytes | Produces 512 bits for HKDF input; gives 32 bytes per derived key |

**Argon2 vs PBKDF2/bcrypt:** PBKDF2-SHA256 at 600,000 iterations (OWASP 2024 minimum) takes ≈100 ms on CPU but runs at billions of iterations per second on GPU. Argon2id at 64 MiB limits a GPU to a fraction of a percent of that throughput due to the memory bandwidth bottleneck.

---

## 3. AES-256-GCM Vault Encryption

### Why authenticated encryption?

Unauthenticated encryption (e.g. AES-CBC) provides confidentiality but not integrity. A malicious server could:
- Flip ciphertext bits and feed the result to the client (chosen-ciphertext attack)
- Substitute one user's ciphertext for another's
- Perform a padding-oracle attack if decryption errors are distinguishable

AES-256-GCM is an **AEAD (Authenticated Encryption with Associated Data)** scheme. It computes a 128-bit authentication tag over the ciphertext. Any single-bit modification to the ciphertext or tag causes decryption to fail with `InvalidTag` — no plaintext is returned.

### Nonce handling

GCM security requires that `(key, nonce)` pairs are **never reused**. Nonce reuse allows an adversary to recover the XOR of two plaintexts and completely breaks authentication.

ZeroVault generates nonces with `os.urandom(12)` — 96 cryptographically random bits per entry. Under the birthday paradox, the collision probability for any key approaches 1 at 2^48 entries; for a realistic vault (< 10,000 entries), this is negligible (< 10^-9).

### What is stored

| Field | Stored by server | Notes |
|-------|-----------------|-------|
| `ciphertext_hex` | ✓ | AES-GCM output; includes 16-byte tag appended by `AESGCM.encrypt` |
| `nonce_hex` | ✓ | 12-byte random nonce; required for decryption |
| Plaintext (`site`, `username`, `password`, `notes`) | ✗ | Never reaches server |
| `enc_key` | ✗ | Never transmitted |

---

## 4. Server-Side Authentication Key Storage

The `auth_key` is transmitted to the server as the user's effective password. The server stores `bcrypt(auth_key, work_factor=12)`.

**Why bcrypt on an already-derived key?**

`auth_key` is the output of Argon2id + HKDF — it already has 256 bits of entropy. One could argue that storing `auth_key` in plaintext would be acceptable because it cannot be reversed to `enc_key`. This is rejected for three reasons:

1. **Defence in depth** — if a memory dump, logging bug, or future vulnerability exposes the raw `auth_key`, the adversary can authenticate as the user. bcrypt hashing prevents this.
2. **Standard practice** — any field treated as a credential must be hashed before storage. Auditors and security reviewers expect this.
3. **Additional brute-force cost** — a combined Argon2id (client) + bcrypt (server) chain imposes sequential cost on any attacker attempting offline verification.

---

## 5. JWT Authentication

After login, the server issues a JWT signed with **HMAC-SHA256** (`HS256`).

ZeroVault uses **PyJWT** rather than `python-jose`. The `python-jose` library has known CVEs (CVE-2024-33663, CVE-2024-33664) related to algorithm confusion attacks. PyJWT with explicit algorithm specification in `jwt.decode(..., algorithms=["HS256"])` is the current recommended approach.

For a multi-service deployment, RS256 (asymmetric signing) would be preferable, as each service could verify tokens using the public key without needing the signing secret.

---

## 6. Threat Model

### What a fully compromised server operator can access

A malicious server operator with full read/write access to the database and process memory can see:

| What | Can they see it? |
|------|-----------------|
| `bcrypt(auth_key)` for each user | ✓ (stored in DB) |
| `argon2_salt`, KDF parameters | ✓ (stored in DB) |
| Vault ciphertext + nonces | ✓ (stored in DB) |
| `enc_key` | ✗ (never transmitted; held only in Reflex State memory during active session) |
| `auth_key` plaintext | ✗ (only bcrypt hash stored) |
| Master password | ✗ (never transmitted) |
| Vault plaintext | ✗ (requires `enc_key`) |

**What the server can do with what it has:**
- Attempt to crack `bcrypt(auth_key)` offline — slow due to Argon2id + bcrypt chain
- If auth_key is cracked: impersonate the user for API calls — but still cannot decrypt the vault
- Serve modified ciphertext to the client — detected by GCM tag verification

### What is NOT protected

1. **Active server impersonation (MITM):** If an adversary controls the server and injects malicious JavaScript/frontend code, they could capture the master password before derivation. This is outside the scope of a server-side zero-knowledge design. Mitigated by HTTPS + certificate pinning in production.

2. **Reflex State memory:** `enc_key` lives in the Reflex backend process memory for the duration of a session. A process-level memory dump during an active session could expose it. This is an architectural limitation of Reflex vs. a browser-native JS implementation using the WebCrypto API.

3. **Weak master passwords:** Argon2id significantly raises the cost of offline attacks, but a short or guessable master password remains vulnerable. ZeroVault enforces a minimum length of 12 characters and shows a password strength indicator.

---

## 7. Comparison: ZeroVault vs. Naïve Implementation

| Property | ZeroVault | Naïve |
|----------|-----------|-------|
| Server stores master password | ✗ | ✗ |
| Server stores encryption key | ✗ | Often ✓ |
| Server stores password hash | `bcrypt(auth_key)` | `bcrypt(password)` |
| Vault breach exposes plaintext | ✗ | ✓ (if same key used) |
| DB breach exposes vault | ✗ | ✓ (same key for auth + encryption) |
| KDF uses GPU-resistant algorithm | ✓ Argon2id | ✗ Often PBKDF2 |
| Encryption is authenticated | ✓ AES-GCM | ✗ Often AES-CBC |
| Nonces are random | ✓ `os.urandom(12)` | ✗ Often deterministic |
| Auth tag verified before plaintext return | ✓ | ✗ |
| Two-key derivation | ✓ | ✗ |

---

## 8. Cryptographic Library Choices

| Purpose | Library | Rationale |
|---------|---------|-----------|
| Argon2id | `argon2-cffi 25.1.0` | Only mature Python Argon2 binding; maintained by Hynek Schlawack |
| AES-256-GCM, HKDF | `cryptography 44.x` | PyCA reference library; FIPS-validated backend option; `AESGCM` hazmat primitive |
| bcrypt | `bcrypt 4.x` | Direct Python binding to bcrypt C library; no passlib dependency |
| JWT | `PyJWT 2.x` | Actively maintained; no known CVEs; explicit algorithm specification |
| CSPRNG | `os.urandom` | OS-provided CSPRNG; appropriate for nonce/salt generation |

The `random` module is **never used** for any security-sensitive purpose. All random material (salts, nonces) is generated via `os.urandom`.
