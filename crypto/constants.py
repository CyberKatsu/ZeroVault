"""
crypto/constants.py
~~~~~~~~~~~~~~~~~~~
Named constants for every cryptographic parameter in ZeroVault, each with a
comment explaining *why* that value was chosen and *what threat* it addresses.

Design principle: parameters should be easy to audit and easy to upgrade.
Centralising them here means a single diff tightens security across the
entire codebase.
"""

from argon2 import Type as Argon2Type

# ─────────────────────────────────────────────────────────────────────────────
# Argon2id parameters
# ─────────────────────────────────────────────────────────────────────────────
# Argon2id is the Password Hashing Competition winner and the OWASP-recommended
# algorithm for password-based key derivation. The "id" variant is resistant to
# both side-channel (timing) attacks AND GPU/ASIC brute-force because it
# combines data-dependent and data-independent memory access.
#
# Reference: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
#            https://www.rfc-editor.org/rfc/rfc9106 (Argon2 RFC)

ARGON2_TYPE: Argon2Type = Argon2Type.ID
# ^ Use Argon2id, not Argon2i or Argon2d.

ARGON2_TIME_COST: int = 3
# ^ Number of passes over memory (iterations).
#   OWASP minimum for interactive logins is 3.  Increasing this linearly
#   raises compute time; useful when hardware improves.  At 3 passes + 64 MiB
#   a typical server derives a key in ~0.3–0.5 s, which is acceptable for a
#   login but painful for an attacker running millions of guesses.

ARGON2_MEMORY_COST: int = 65_536
# ^ Memory required, in kibibytes (64 MiB).
#   OWASP minimum is 64 MiB.  Memory cost is the primary defence against GPU
#   attacks: a GPU with thousands of cores cannot run thousands of parallel
#   Argon2 instances if each requires 64 MiB of VRAM.  A single RTX 4090 has
#   24 GiB VRAM → at most ~375 parallel instances, vs. millions for bcrypt.
#   Increase to 131_072 (128 MiB) on systems with more RAM to spare.

ARGON2_PARALLELISM: int = 4
# ^ Degree of parallelism (threads).  Should match the number of CPU cores
#   available to the calling process.  4 is a pragmatic default for a
#   containerised service.  Setting this higher than available cores provides
#   no speed benefit but does increase memory pressure for the *attacker*
#   (they must allocate MEMORY_COST × PARALLELISM to match).

ARGON2_SALT_LENGTH: int = 16
# ^ Salt size in bytes (128 bits).  A random salt per user ensures that two
#   users with the same master password produce different keys, defeating
#   rainbow-table attacks.  128 bits is far above the collision threshold.

ARGON2_HASH_LENGTH: int = 64
# ^ Output length in bytes (512 bits).  We derive *two* 256-bit keys from
#   this output via HKDF, so we need at least 64 bytes to feed HKDF with
#   sufficient entropy without stretching.  Argon2 treats this as the raw
#   output size, not a truncated hash.

# ─────────────────────────────────────────────────────────────────────────────
# HKDF parameters
# ─────────────────────────────────────────────────────────────────────────────
# HKDF (RFC 5869) is a two-step Extract-and-Expand KDF built on HMAC.
# We use it to derive *two independent keys* from the single Argon2 output.
# Independence is guaranteed by the distinct `info` labels: even with the same
# IKM, different info strings produce cryptographically independent outputs.

HKDF_HASH: str = "sha256"
# ^ SHA-256 provides 256-bit security, matching our key lengths.

DERIVED_KEY_LENGTH: int = 32
# ^ 32 bytes = 256 bits per derived key.  This is the key length for AES-256.

HKDF_INFO_ENCRYPTION: bytes = b"zerovault-v1-encryption-key"
# ^ Domain-separation label for the encryption key.  Including "v1" allows
#   a future migration to v2 parameters without breaking existing vaults:
#   just change the label and re-encrypt.

HKDF_INFO_AUTH: bytes = b"zerovault-v1-authentication-key"
# ^ Domain-separation label for the authentication key.  The two labels MUST
#   differ so that encryption_key ≠ auth_key even when IKM is the same.
#   This is the core of the two-key separation pattern — see CRYPTOGRAPHY.md.

# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM parameters
# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM is an authenticated encryption with associated data (AEAD) scheme.
# "Authenticated" means the GCM authentication tag detects any tampering with
# the ciphertext BEFORE decryption begins — an attacker cannot flip bits
# silently (defeating chosen-ciphertext and bit-flipping attacks).

GCM_NONCE_LENGTH: int = 12
# ^ 12 bytes (96 bits) is the NIST-recommended nonce length for GCM (SP 800-38D).
#   A 96-bit random nonce has a birthday-bound collision at ~2^48 nonces per key.
#   Since we rotate the encryption key per *user* and nonces are random per
#   *entry*, collision probability is negligible for any realistic vault size.
#   Do NOT use a counter nonce here; random is simpler and safe at this scale.

GCM_TAG_LENGTH: int = 16
# ^ 128-bit (16-byte) authentication tag — the GCM default and maximum.
#   A shorter tag (e.g. 96 bits) reduces ciphertext overhead but also reduces
#   the forgery resistance.  Always use the full 128-bit tag.

# ─────────────────────────────────────────────────────────────────────────────
# bcrypt parameters (server-side, auth-key hashing)
# ─────────────────────────────────────────────────────────────────────────────
# The server bcrypt-hashes the auth_key before storage so that an attacker who
# exfiltrates the database cannot replay raw auth_keys to authenticate.
# bcrypt adds a second layer of key stretching on top of Argon2.

BCRYPT_ROUNDS: int = 12
# ^ Work factor (log2 of iterations).  12 ≈ 0.3–0.5 s per check.
#   Because auth_key is already a high-entropy 256-bit derived value (not a
#   human password), bcrypt here is not defending against brute-force on weak
#   inputs — it is defending against replay attacks using stolen DB rows.
#   bcrypt also adds a 128-bit random salt automatically.
