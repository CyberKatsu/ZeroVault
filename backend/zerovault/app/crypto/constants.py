"""
zerovault.crypto.constants
==========================
Named constants for all cryptographic parameters used in ZeroVault.

Every constant is annotated with the threat it addresses and the source of
the chosen value.  Changing these values WILL break existing vaults because
Argon2id is deterministic given (password, salt, params) — stored entries
can no longer be decrypted if the parameters differ from those used at
registration time.  The Argon2 parameters ARE stored in the database so that
a future parameter upgrade path (re-derive on next login) is possible.
"""

# ─── Argon2id parameters ────────────────────────────────────────────────────
#
# Reference: RFC 9106, §4 "Parameter Choice"
# https://www.rfc-editor.org/rfc/rfc9106#section-4
#
# RFC 9106 recommends two profiles:
#   FIRST  (memory-hard, high security): t=1, m=2 GiB, p=4
#   SECOND (time-constrained):           t=3, m=64 MiB, p=4
#
# We adopt the SECOND (64 MiB) profile as a reasonable default for a web
# application running on commodity hardware.  A dedicated attacker using a
# GPU cannot parallelise beyond `p` lanes; each lane requires 64/4 = 16 MiB
# of working memory.
#
# Threat addressed: offline dictionary / brute-force attacks after a database
# breach.  Even if an adversary exfiltrates the bcrypt hash of auth_key, they
# cannot regenerate auth_key without spending ~65 ms per guess on a modern CPU,
# which makes large-scale cracking economically infeasible.

ARGON2_TIME_COST: int = 3
# Number of passes over the memory buffer.
# Increasing t_cost raises wall-clock cost roughly linearly without changing
# memory requirements.  3 passes gives ≈ 65 ms on a 2024 mid-range laptop.

ARGON2_MEMORY_COST_KIB: int = 65536
# Memory cost in kibibytes (64 MiB).
# Memory hardness is the primary defence against GPU/ASIC attacks: a GPU with
# 8 GiB VRAM can run at most 8192/64 ≈ 128 concurrent instances, versus
# millions of iterations per second with a non-memory-hard function like PBKDF2.

ARGON2_PARALLELISM: int = 4
# Degree of internal parallelism (number of independent memory lanes).
# Matching the parallelism to a typical server core count ensures both server
# and adversary use the same number of threads.  Higher parallelism does NOT
# reduce the per-guess wall-clock time if the adversary matches it.

ARGON2_HASH_LENGTH: int = 64
# Output length in bytes.
# 64 bytes = 512 bits gives us 32 bytes for enc_key and 32 bytes for auth_key
# after HKDF expansion.  Using HKDF on this output (rather than naively
# splitting it) provides cryptographic domain separation between the two keys.

ARGON2_TYPE: str = "id"
# Argon2id combines the side-channel resistance of Argon2i (data-independent
# memory access) with the GPU-resistance of Argon2d (data-dependent access).
# It is the mandatory variant per RFC 9106 §7.4 for password hashing.


# ─── AES-GCM parameters ─────────────────────────────────────────────────────

AES_KEY_LENGTH: int = 32
# AES-256 key = 32 bytes.  AES-256 provides a 256-bit security level; even
# with Grover's algorithm a quantum adversary would need 2^128 operations.

NONCE_LENGTH: int = 12
# GCM nonce = 96 bits (12 bytes).
# NIST SP 800-38D §8.2.1 specifies 96-bit nonces as the recommended length
# for deterministic nonce generation.  We generate nonces with os.urandom
# (CSPRNG), so collision probability for any key is negligible until 2^32
# vault entries (~4 billion) are created under the same key.

GCM_TAG_LENGTH: int = 16
# Authentication tag = 128 bits (16 bytes).  This is the full GCM tag length.
# Shorter tags (e.g. 96 or 64 bits) are permissible under NIST SP 800-38D but
# reduce authentication security.  We always use 128 bits.


# ─── General key/salt parameters ─────────────────────────────────────────────

SALT_LENGTH: int = 32
# Argon2 salt = 256 bits.  RFC 9106 §3.1 requires ≥ 128-bit salts; we use
# 256 bits to ensure uniqueness even across billions of registrations.

JWT_ALGORITHM: str = "HS256"
# HMAC-SHA256 for JWT signing.  RS256 (asymmetric) would be preferable in a
# multi-service deployment; HS256 is acceptable for a single-backend system.


# ─── HKDF info labels (domain separation) ────────────────────────────────────
#
# Using distinct info strings ensures that even if the HKDF output were
# somehow related, an adversary cannot use auth_key to derive enc_key or
# vice versa.  The labels are arbitrary ASCII strings; they are never secret.

HKDF_INFO_ENC_KEY: bytes = b"zerovault-v1-encryption-key"
HKDF_INFO_AUTH_KEY: bytes = b"zerovault-v1-authentication-key"
